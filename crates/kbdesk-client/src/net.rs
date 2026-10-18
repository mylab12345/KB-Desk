//! Networking for the viewer.
//!
//! A Tokio runtime runs on a background thread. The GUI talks to it by sending
//! [`ClientCmd`] values and by reading live state out of [`Shared`].
//!
//! Connections are TLS-encrypted, and the viewer<->host session is
//! additionally end-to-end encrypted (protocol v2): the password never
//! leaves this process — it is verified through the key exchange in
//! `kbdesk_core::crypto`. TLS behaviour is configured via environment
//! (same names as everywhere else): `KB_DESK_TLS_CA`,
//! `KB_DESK_TLS_SERVER_NAME`, plus the development-only escapes
//! `KB_DESK_TLS_INSECURE=1` / `KB_DESK_ALLOW_PLAINTEXT=1`.

use anyhow::{Context, Result};
use kbdesk_core::crypto;
use kbdesk_core::tls::{self, TlsClientOptions};
use kbdesk_core::{
    decode_video, read_secure_packet, write_packet, write_secure_packet, Control, InputEvent,
    Packet, KIND_CONTROL, KIND_VIDEO,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes"))
}

fn tls_options_from_env() -> TlsClientOptions {
    let opts = TlsClientOptions {
        ca_file: std::env::var_os("KB_DESK_TLS_CA").map(PathBuf::from),
        server_name: std::env::var("KB_DESK_TLS_SERVER_NAME").ok().filter(|s| !s.is_empty()),
        insecure: env_flag("KB_DESK_TLS_INSECURE"),
        allow_plaintext: env_flag("KB_DESK_ALLOW_PLAINTEXT"),
    };
    if opts.allow_plaintext {
        tracing::warn!("KB_DESK_ALLOW_PLAINTEXT=1: transport TLS disabled (session still E2E-encrypted). Local development only.");
    }
    if opts.insecure {
        tracing::warn!("KB_DESK_TLS_INSECURE=1: server certificates will not be verified. Local development only.");
    }
    opts
}

/// A frame ready to be decoded by the GUI.
#[derive(Clone)]
pub struct FrameData {
    pub width: u16,
    pub height: u16,
    pub jpeg: Vec<u8>,
}

/// State shared between the network thread and the GUI thread.
#[derive(Default)]
pub struct Shared {
    pub status: String,
    pub connected: bool,
    pub frame: Option<FrameData>,
    /// Set by the network thread when a new frame has arrived.
    pub dirty: bool,
}

/// Commands the GUI sends to the network thread.
pub enum ClientCmd {
    Connect {
        addr: String,
        relay_id: Option<String>,
        password: String,
        monitor: u32,
        quality: u8,
        fps: u8,
    },
    Input(InputEvent),
    Disconnect,
}

/// Start the network thread and return a sender the GUI can drive it with.
pub fn spawn_network(shared: Arc<Mutex<Shared>>) -> UnboundedSender<ClientCmd> {
    let (tx, rx) = unbounded_channel::<ClientCmd>();
    std::thread::Builder::new()
        .name("kbdesk-net".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    tracing::error!("could not start network runtime: {e}");
                    return;
                }
            };
            runtime.block_on(run(rx, shared));
        })
        .expect("spawning network thread");
    tx
}

async fn run(mut rx: UnboundedReceiver<ClientCmd>, shared: Arc<Mutex<Shared>>) {
    while let Some(cmd) = rx.recv().await {
        if let ClientCmd::Connect {
            addr,
            relay_id,
            password,
            monitor,
            quality,
            fps,
        } = cmd
        {
            if let Err(e) = session(&mut rx, &shared, &addr, relay_id, password, monitor, quality, fps)
                .await
            {
                set_status(&shared, &format!("error: {e:#}"), false);
            }
        }
    }
}

fn set_status(shared: &Arc<Mutex<Shared>>, status: &str, connected: bool) {
    let mut s = shared.lock().unwrap();
    s.status = status.to_string();
    s.connected = connected;
}

#[allow(clippy::too_many_arguments)]
async fn session(
    rx: &mut UnboundedReceiver<ClientCmd>,
    shared: &Arc<Mutex<Shared>>,
    addr: &str,
    relay_id: Option<String>,
    password: String,
    monitor: u32,
    quality: u8,
    fps: u8,
) -> Result<()> {
    set_status(shared, &format!("connecting to {addr}…"), false);
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to {addr}"))?;
    let (mut reader, mut writer) = stream.into_split();

    // Relay: ask to be paired with a host id before the end-to-end handshake.
    if let Some(id) = &relay_id {
        write_packet(
            &mut writer,
            KIND_CONTROL,
            &Control::Connect { target: id.clone() }.encode(),
        )
        .await?;
    }

    // End-to-end handshake.
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
            role: Role::Host,
            id,
            ..
        } => set_status(shared, &format!("connected to host {id}; authenticating…"), false),
        Control::Error(e) => bail!("peer refused: {e}"),
        other => bail!("unexpected reply: {other:?}"),
    }

    write_packet(
        &mut writer,
        KIND_CONTROL,
        &Control::Auth { password }.encode(),
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
    set_status(shared, &format!("connected to {addr}"), true);

    // Read frames in a dedicated task: `read_packet` is not cancellation-safe,
    // so it must not be raced against outgoing input inside `select!`.
    let (packet_tx, mut packet_rx) = unbounded_channel::<Result<Packet>>();
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
                        let frame = decode_video(&packet.payload)?;
                        let mut s = shared.lock().unwrap();
                        s.frame = Some(FrameData { width: frame.width, height: frame.height, jpeg: frame.jpeg });
                        s.dirty = true;
                    }
                    KIND_CONTROL => {
                        if let Ok(Control::Error(e)) = Control::decode(&packet.payload) {
                            set_status(shared, &format!("host error: {e}"), false);
                        }
                    }
                    _ => {}
                }
            }
            command = rx.recv() => {
                match command {
                    Some(ClientCmd::Input(event)) => {
                        write_secure_packet(&mut writer, &mut tx_cipher, KIND_CONTROL, &Control::Input(event).encode()).await?;
                    }
                    Some(ClientCmd::Disconnect) | None => {
                        let _ = writer.shutdown().await;
                        set_status(shared, "disconnected", false);
                        return Ok(());
                    }
                    Some(ClientCmd::Connect { .. }) => { /* already in a session */ }
                }
            }
        }
    }
}
