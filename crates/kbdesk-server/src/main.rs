//! KB-Desk relay / rendezvous server.
//!
//! Responsibilities:
//!   * A host connects and registers under a numeric id.
//!   * A viewer connects and asks for that id.
//!   * The server then becomes a transparent byte pump between the two.
//!
//! The server never sees plaintext input semantics after pairing: it only
//! forwards the framed stream. Authentication and streaming are end-to-end
//! between host and viewer.

use anyhow::{bail, Context, Result};
use clap::Parser;
use kbdesk_core::{generate_id, read_packet, write_packet, Control, Role, DEFAULT_PORT, KIND_CONTROL};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{info, warn, Level};
use tracing_subscriber::EnvFilter;

/// id -> the host's live TCP connection (parked until a viewer arrives).
type Registry = Arc<Mutex<HashMap<String, TcpStream>>>;

#[derive(Parser, Debug)]
#[command(
    name = "kbdesk-server",
    about = "KB-Desk relay and rendezvous server",
    version
)]
struct Args {
    /// Address to bind the listener to.
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

    /// TCP port to listen on.
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
}

async fn send_control<W: AsyncWrite + Unpin>(writer: &mut W, control: &Control) -> Result<()> {
    write_packet(writer, KIND_CONTROL, &control.encode()).await
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let addr = format!("{}:{}", args.bind, args.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    info!(%addr, "kbdesk-server listening; hosts register, viewers connect by id");

    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, registry, peer).await {
                if tracing::enabled!(Level::DEBUG) {
                    warn!(%peer, "connection ended: {e:#}");
                }
            }
        });
    }
}

async fn handle_conn(mut stream: TcpStream, registry: Registry, peer: SocketAddr) -> Result<()> {
    let packet = read_packet(&mut stream)
        .await
        .with_context(|| format!("reading first frame from {peer}"))?;
    if packet.kind != KIND_CONTROL {
        bail!("first frame from {peer} was not a control frame");
    }

    match Control::decode(&packet.payload)? {
        // A host wants to be reachable under an id.
        Control::Hello {
            role: Role::Host,
            id,
            ..
        } => {
            let id = if id.trim().is_empty() {
                generate_id()
            } else {
                id.trim().to_string()
            };
            info!(%peer, %id, "host registered");
            send_control(&mut stream, &Control::AssignedId(id.clone())).await?;
            registry.lock().await.insert(id, stream);
            // The stream now lives in the registry until a viewer claims it.
            Ok(())
        }
        // A viewer asks for a host id (either explicit Connect or viewer Hello).
        Control::Connect { target } => serve_viewer(stream, registry, target, peer).await,
        Control::Hello {
            role: Role::Viewer,
            id,
            ..
        } => serve_viewer(stream, registry, id, peer).await,
        other => {
            let mut stream = stream;
            let _ = send_control(
                &mut stream,
                &Control::Error(format!("unexpected first message: {other:?}")),
            )
            .await;
            Ok(())
        }
    }
}

async fn serve_viewer(
    mut viewer: TcpStream,
    registry: Registry,
    target: String,
    peer: SocketAddr,
) -> Result<()> {
    let target = target.trim().to_string();
    let host = registry.lock().await.remove(&target);

    match host {
        Some(mut host) => {
            info!(%peer, %target, "pairing viewer with host; relaying");
            // From here on we are a transparent pump. Host and viewer perform
            // their own handshake and authentication.
            let (from_host, from_viewer) = tokio::io::copy_bidirectional(&mut host, &mut viewer)
                .await
                .context("relay pump failed")?;
            info!(%target, from_host, from_viewer, "relay session closed");
            let _ = viewer.shutdown().await;
            Ok(())
        }
        None => {
            warn!(%peer, %target, "connection requested for unknown id");
            send_control(
                &mut viewer,
                &Control::Error("no host is registered with that id".into()),
            )
            .await?;
            let _ = viewer.shutdown().await;
            Ok(())
        }
    }
}
