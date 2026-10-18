//! KB-Desk web viewer.
//!
//! Serves a browser page that acts as a viewer: a WebSocket bridges the
//! browser to the same framed TCP protocol the native client uses. The browser
//! sends JSON commands and input events; the server streams JPEG frames back as
//! binary WebSocket messages using the standard KB-Desk video payload layout.
//!
//! No software has to be installed on the viewing machine — only a browser.

use anyhow::{bail, Context, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use clap::Parser;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use kbdesk_core::{
    read_packet, write_packet, Control, InputEvent, Packet, Role, KIND_CONTROL, KIND_VIDEO,
    PROTOCOL_VERSION,
};
use serde::Deserialize;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "kbdesk-web",
    about = "KB-Desk web viewer (browser-based control)",
    version
)]
struct Args {
    /// Address to serve the web UI on.
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,

    /// Relay server browsers should reach hosts through, e.g. relay.example:21118.
    /// When set, users only need an ID + password. When unset, they must give a
    /// direct host address, which is safer to leave unset on public deployments.
    #[arg(long)]
    relay: Option<String>,
}

#[derive(Clone)]
struct AppState {
    relay: Option<String>,
}

/// Messages the browser sends to us, tagged by `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum BrowserMsg {
    Connect {
        id: Option<String>,
        address: Option<String>,
        password: String,
        monitor: Option<u32>,
        quality: Option<u8>,
        fps: Option<u8>,
    },
    Input {
        event: InputEvent,
    },
    Disconnect,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let state = AppState {
        relay: args.relay.clone(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/config", get(config))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("binding web UI at {}", args.listen))?;

    info!(addr = %args.listen, relay = ?args.relay, "kbdesk-web listening");
    if args.relay.is_none() {
        warn!("no --relay set: browsers must supply a direct host address");
    }
    println!("KB-Desk web viewer:  http://{}", args.listen);
    if let Some(relay) = &args.relay {
        println!("  relay: {relay}");
    }

    axum::serve(listener, app).await.context("serving web UI")?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn config(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "relay": state.relay }))
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

fn status(message: &str) -> Message {
    Message::text(
        serde_json::json!({ "type": "status", "message": message }).to_string(),
    )
}

fn error_msg(message: &str) -> Message {
    Message::text(
        serde_json::json!({ "type": "error", "message": message }).to_string(),
    )
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();

    // Dedicated writer so the bridge never blocks on a slow browser.
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if ws_tx.send(message).await.is_err() {
                break;
            }
        }
    });

    if let Err(e) = drive(&mut ws_rx, &out_tx, &state).await {
        let _ = out_tx.send(error_msg(&format!("{e:#}")));
    }
    drop(out_tx);
    let _ = writer.await;
}

/// Wait for a connect request, run one session, then wait again.
async fn drive(
    ws_rx: &mut SplitStream<WebSocket>,
    out: &mpsc::UnboundedSender<Message>,
    state: &AppState,
) -> Result<()> {
    loop {
        // --- wait for a Connect command from the browser ---
        let (id, address, password, monitor, quality, fps) = loop {
            match ws_rx.next().await {
                Some(Ok(Message::Text(text))) => match serde_json::from_str::<BrowserMsg>(text.as_str()) {
                    Ok(BrowserMsg::Connect {
                        id,
                        address,
                        password,
                        monitor,
                        quality,
                        fps,
                    }) => {
                        break (
                            id,
                            address,
                            password,
                            monitor.unwrap_or(0),
                            quality.unwrap_or(70),
                            fps.unwrap_or(15),
                        )
                    }
                    Ok(BrowserMsg::Disconnect) => {
                        let _ = out.send(status("disconnected"));
                    }
                    Ok(BrowserMsg::Input { .. }) => {}
                    Err(e) => {
                        let _ = out.send(error_msg(&format!("bad message: {e}")));
                    }
                },
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Ok(_)) => {}
                Some(Err(_)) => return Ok(()),
            }
        };

        // --- resolve the target ---
        let (target, relay_id) = match (&state.relay, address.as_deref()) {
            (Some(relay), _) => (relay.clone(), id.clone()),
            (None, Some(addr)) if !addr.trim().is_empty() => (addr.trim().to_string(), None),
            _ => {
                let _ = out.send(error_msg(
                    "this viewer has no relay configured; enter a direct host address",
                ));
                continue;
            }
        };

        let _ = out.send(status(&format!("connecting to {target}…")));
        match start_session(&target, relay_id.as_deref(), &password, monitor, quality, fps).await {
            Ok((reader, writer)) => {
                let _ = out.send(status("connected; streaming"));
                if let Err(e) = session(ws_rx, out, reader, writer).await {
                    let _ = out.send(error_msg(&format!("{e:#}")));
                }
                let _ = out.send(status("session ended"));
            }
            Err(e) => {
                let _ = out.send(error_msg(&format!("{e:#}")));
            }
        }
    }
}

/// Perform the viewer handshake against a host (direct) or through a relay.
async fn start_session(
    server: &str,
    relay_id: Option<&str>,
    password: &str,
    monitor: u32,
    quality: u8,
    fps: u8,
) -> Result<(OwnedReadHalf, OwnedWriteHalf)> {
    let stream = TcpStream::connect(server)
        .await
        .with_context(|| format!("connecting to {server}"))?;
    let (mut reader, mut writer) = stream.into_split();

    if let Some(id) = relay_id {
        write_packet(
            &mut writer,
            KIND_CONTROL,
            &Control::Connect {
                target: id.to_string(),
            }
            .encode(),
        )
        .await?;
    }

    write_packet(
        &mut writer,
        KIND_CONTROL,
        &Control::Hello {
            version: PROTOCOL_VERSION,
            role: Role::Viewer,
            id: String::new(),
        }
        .encode(),
    )
    .await?;

    let packet = read_packet(&mut reader).await.context("waiting for host")?;
    match Control::decode(&packet.payload)? {
        Control::Hello {
            role: Role::Host, ..
        } => {}
        Control::Error(e) => bail!("peer refused: {e}"),
        other => bail!("unexpected reply: {other:?}"),
    }

    write_packet(
        &mut writer,
        KIND_CONTROL,
        &Control::Auth {
            password: password.to_string(),
        }
        .encode(),
    )
    .await?;
    let packet = read_packet(&mut reader).await.context("waiting for auth")?;
    match Control::decode(&packet.payload)? {
        Control::AuthResult { ok: true, .. } => {}
        Control::AuthResult { ok: false, reason } => bail!("authentication failed: {reason}"),
        other => bail!("unexpected reply: {other:?}"),
    }

    write_packet(
        &mut writer,
        KIND_CONTROL,
        &Control::StartStream {
            monitor,
            quality,
            fps,
        }
        .encode(),
    )
    .await?;

    Ok((reader, writer))
}

/// Pump frames to the browser and input events to the host until either side ends.
///
/// The host->browser reader runs in its own task and pushes whole packets onto a
/// channel. `read_packet` is not cancellation-safe, so it must never be raced
/// directly inside `select!` — doing so would drop partly-read bytes whenever the
/// browser sent input at the same moment a frame was arriving, corrupting the
/// stream (symptom: "incoming frame too large").
async fn session(
    ws_rx: &mut SplitStream<WebSocket>,
    out: &mpsc::UnboundedSender<Message>,
    reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
) -> Result<()> {
    let (packet_tx, mut packet_rx) = mpsc::unbounded_channel::<Result<Packet>>();
    tokio::spawn(async move {
        let mut reader = reader;
        loop {
            match read_packet(&mut reader).await {
                Ok(packet) => {
                    if packet_tx.send(Ok(packet)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = packet_tx.send(Err(e));
                    break;
                }
            }
        }
    });

    loop {
        tokio::select! {
            incoming = packet_rx.recv() => {
                let packet = match incoming {
                    Some(Ok(packet)) => packet,
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()),
                };
                match packet.kind {
                    KIND_VIDEO => {
                        // Forward the payload verbatim; the browser decodes the header.
                        let _ = out.send(Message::binary(packet.payload));
                    }
                    KIND_CONTROL => {
                        if let Ok(Control::Error(e)) = Control::decode(&packet.payload) {
                            bail!("host error: {e}");
                        }
                    }
                    _ => {}
                }
            }
            message = ws_rx.next() => {
                match message {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<BrowserMsg>(text.as_str()) {
                            Ok(BrowserMsg::Input { event }) => {
                                write_packet(&mut writer, KIND_CONTROL, &Control::Input(event).encode()).await?;
                            }
                            Ok(BrowserMsg::Disconnect) => return Ok(()),
                            Ok(BrowserMsg::Connect { .. }) => {}
                            Err(e) => warn!("bad browser message: {e}"),
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(_)) => return Ok(()),
                }
            }
        }
    }
}
