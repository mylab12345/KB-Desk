//! KB-Desk web viewer.
//!
//! Serves a browser page that acts as a viewer: a WebSocket bridges the
//! browser to the same framed TCP protocol the native client uses. The browser
//! sends JSON commands and input events; the server streams JPEG frames back as
//! binary WebSocket messages using the standard KB-Desk video payload layout.
//!
//! No software has to be installed on the viewing machine — only a browser.
//! Browsers cannot open raw TCP connections, so this bridge is the piece that
//! lets a browser reach the (TCP) relay: run it next to the relay
//! (`kbdesk-web --relay 127.0.0.1:21118`, or `kbdesk serve`) and every visitor
//! only needs the host's ID + password.
//!
//! Robustness rules for "control it from the browser without issues":
//!   * every handshake step has a timeout (a dead host fails fast, visibly);
//!   * video frames are latest-frame-wins end to end (a slow browser/network
//!     drops frames instead of accumulating ever-growing latency);
//!   * ending a session releases all held keys/buttons on the host.

use anyhow::{bail, Context, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::header,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use clap::Parser;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use kbdesk_core::{
    normalize_id, read_packet, write_packet, Control, InputEvent, Packet, Role, KIND_CONTROL,
    KIND_VIDEO, PROTOCOL_VERSION,
};
use serde::Deserialize;
use std::time::Duration;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// TCP connect + each handshake read gets this long before we give up.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Browser-bound queue depth (video is dropped past this, never queued up).
const OUT_QUEUE: usize = 8;

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
    /// Several input events in one message (e.g. a key combination).
    Inputs {
        events: Vec<InputEvent>,
    },
    /// Change stream parameters mid-session.
    Stream {
        monitor: Option<u32>,
        quality: Option<u8>,
        fps: Option<u8>,
    },
    /// Latency probe; forwarded to the host, whose Pong comes back as
    /// `{"type":"pong","t":…}` so the browser measures the full path.
    Ping {
        t: u64,
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
        .route("/healthz", get(|| async { "ok" }))
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

async fn index() -> impl IntoResponse {
    // Never let a browser keep a stale viewer page after an upgrade.
    (
        [(header::CACHE_CONTROL, "no-cache")],
        Html(include_str!("../web/index.html")),
    )
}

async fn config(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Only tell the browser *whether* a relay is configured, not where it is.
    Json(serde_json::json!({
        "relay": state.relay.is_some(),
        "mode": if state.relay.is_some() { "relay" } else { "direct" },
    }))
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

fn status_msg(message: &str) -> Message {
    Message::text(serde_json::json!({ "type": "status", "message": message }).to_string())
}

fn error_msg(message: &str) -> Message {
    Message::text(serde_json::json!({ "type": "error", "message": message }).to_string())
}

fn ended_msg() -> Message {
    Message::text(serde_json::json!({ "type": "ended", "message": "session ended" }).to_string())
}

async fn send_status(out: &mpsc::Sender<Message>, message: &str) {
    let _ = out.send(status_msg(message)).await;
}

async fn send_error(out: &mpsc::Sender<Message>, message: &str) {
    let _ = out.send(error_msg(message)).await;
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    // Bounded: a browser that cannot keep up drops video frames (try_send in
    // the session loop) instead of building an ever-growing backlog.
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(OUT_QUEUE);

    // Dedicated writer so the bridge never blocks on a slow browser.
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if ws_tx.send(message).await.is_err() {
                break;
            }
        }
    });

    if let Err(e) = drive(&mut ws_rx, &out_tx, &state).await {
        send_error(&out_tx, &format!("{e:#}")).await;
    }
    drop(out_tx);
    let _ = writer.await;
}

/// Wait for a connect request, run one session, then wait again — so a failed
/// attempt (wrong password, host offline) can be retried on the same socket.
async fn drive(
    ws_rx: &mut SplitStream<WebSocket>,
    out: &mpsc::Sender<Message>,
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
                            quality.unwrap_or(70).clamp(1, 100),
                            fps.unwrap_or(15).clamp(1, 60),
                        )
                    }
                    Ok(BrowserMsg::Disconnect) => {
                        send_status(out, "disconnected").await;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        send_error(out, &format!("bad message: {e}")).await;
                    }
                },
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Ok(_)) => {}
                Some(Err(_)) => return Ok(()),
            }
        };

        // --- resolve the target ---
        // IDs are normalised so "544 228 382" (as shown to users) connects.
        let relay_id = id
            .as_deref()
            .map(normalize_id)
            .filter(|s| !s.is_empty());
        let direct = address
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let (target, relay_id) = match (&state.relay, relay_id, direct) {
            // Relay configured server-side: browsers only ever supply an ID.
            (Some(relay), Some(id), _) => (relay.clone(), Some(id)),
            (Some(_), None, _) => {
                send_error(out, "enter the ID shown on the machine you want to control").await;
                continue;
            }
            // No configured relay: the address field is either a host
            // (direct) or, when an ID is also given, a relay to go through.
            (None, id, Some(addr)) => (addr, id),
            (None, _, None) => {
                send_error(
                    out,
                    "this viewer has no relay configured; enter a direct host address",
                )
                .await;
                continue;
            }
        };

        match &relay_id {
            Some(id) => send_status(out, &format!("connecting to host {id} via relay…")).await,
            None => send_status(out, &format!("connecting to {target}…")).await,
        }
        match start_session(&target, relay_id.as_deref(), &password, monitor, quality, fps).await {
            Ok((reader, writer)) => {
                send_status(out, "connected; streaming").await;
                if let Err(e) = session(ws_rx, out, reader, writer, monitor).await {
                    send_error(out, &format!("{e:#}")).await;
                }
                let _ = out.send(ended_msg()).await;
            }
            Err(e) => {
                send_error(out, &format!("{e:#}")).await;
            }
        }
    }
}

/// Read one handshake packet, bounded by [`HANDSHAKE_TIMEOUT`].
async fn read_timed(reader: &mut OwnedReadHalf, what: &str) -> Result<kbdesk_core::Packet> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, read_packet(reader))
        .await
        .with_context(|| format!("timed out {what}"))?
        .with_context(|| format!("failed {what}"))
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
    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(server))
        .await
        .with_context(|| format!("timed out connecting to {server}"))?
        .with_context(|| format!("connecting to {server} (is the relay/host running?)"))?;
    let _ = stream.set_nodelay(true);
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

    let packet = read_timed(&mut reader, "waiting for the host").await?;
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
    let packet = read_timed(&mut reader, "waiting for authentication").await?;
    match Control::decode(&packet.payload)? {
        Control::AuthResult { ok: true, .. } => {}
        Control::AuthResult { ok: false, reason } => bail!("authentication failed: {reason}"),
        Control::Error(e) => bail!("peer refused: {e}"),
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

/// Pump frames to the browser and input events to the host until either side
/// ends, then close the host side cleanly.
///
/// The host->browser reader runs in its own task and pushes whole packets onto
/// a channel. `read_packet` is not cancellation-safe, so it must never be
/// raced directly inside `select!` — doing so would drop partly-read bytes
/// whenever the browser sent input at the same moment a frame was arriving,
/// corrupting the stream (symptom: "incoming frame too large").
async fn session(
    ws_rx: &mut SplitStream<WebSocket>,
    out: &mpsc::Sender<Message>,
    reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    monitor: u32,
) -> Result<()> {
    let (packet_tx, mut packet_rx) = mpsc::unbounded_channel::<Result<Packet>>();
    let reader_task = tokio::spawn(async move {
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

    let result = session_loop(ws_rx, out, &mut packet_rx, &mut writer, monitor).await;

    // Best-effort clean close: release held input, stop the stream. The host
    // also releases input when the connection drops, so this is belt-and-braces.
    let _ = write_packet(
        &mut writer,
        KIND_CONTROL,
        &Control::Input(InputEvent::ReleaseAll).encode(),
    )
    .await;
    let _ = write_packet(&mut writer, KIND_CONTROL, &Control::StopStream.encode()).await;
    reader_task.abort();
    result
}

async fn session_loop(
    ws_rx: &mut SplitStream<WebSocket>,
    out: &mpsc::Sender<Message>,
    packet_rx: &mut mpsc::UnboundedReceiver<Result<Packet>>,
    writer: &mut OwnedWriteHalf,
    mut monitor: u32,
) -> Result<()> {
    loop {
        tokio::select! {
            incoming = packet_rx.recv() => {
                let packet = match incoming {
                    Some(Ok(packet)) => packet,
                    Some(Err(e)) => bail!("connection to the host was lost: {e:#}"),
                    None => return Ok(()),
                };
                match packet.kind {
                    KIND_VIDEO => {
                        // Forward verbatim; the browser decodes the header.
                        // Latest-frame-wins: drop, never queue, when behind.
                        match out.try_send(Message::binary(packet.payload)) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                        }
                    }
                    KIND_CONTROL => {
                        match Control::decode(&packet.payload) {
                            Ok(Control::Pong(t)) => {
                                let msg = Message::text(
                                    serde_json::json!({ "type": "pong", "t": t }).to_string(),
                                );
                                let _ = out.try_send(msg);
                            }
                            Ok(Control::Error(e)) => bail!("host error: {e}"),
                            _ => {}
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
                                write_packet(writer, KIND_CONTROL, &Control::Input(event).encode()).await?;
                            }
                            Ok(BrowserMsg::Inputs { events }) => {
                                for event in events {
                                    write_packet(writer, KIND_CONTROL, &Control::Input(event).encode()).await?;
                                }
                            }
                            Ok(BrowserMsg::Stream { monitor: m, quality, fps }) => {
                                if let Some(m) = m {
                                    monitor = m;
                                }
                                write_packet(
                                    writer,
                                    KIND_CONTROL,
                                    &Control::StartStream {
                                        monitor,
                                        quality: quality.unwrap_or(70).clamp(1, 100),
                                        fps: fps.unwrap_or(15).clamp(1, 60),
                                    }
                                    .encode(),
                                )
                                .await?;
                            }
                            Ok(BrowserMsg::Ping { t }) => {
                                write_packet(writer, KIND_CONTROL, &Control::Ping(t).encode()).await?;
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
