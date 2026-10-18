//! KB-Desk web viewer (blind bridge).
//!
//! Serves a browser page that is a full KB-Desk viewer in its own right.
//! Browsers cannot open raw TCP/TLS connections, so this process bridges the
//! page's WebSocket to the framed TCP/TLS protocol — but it is a *blind* byte
//! pipe: the page itself performs the protocol-v2 key exchange
//! (`web/crypto.js`) and encrypts/decrypts every control and video frame, so
//! this bridge — like the relay — never sees screen contents, input events,
//! or the password (the page never even sends it here).
//!
//! Run it next to the relay (`kbdesk-web --relay relay.example:21118`, or
//! `kbdesk serve`) and every visitor only needs the host's ID + password.
//!
//! Transport encryption is mandatory on both sides of the bridge:
//!   * browser <-> bridge: HTTPS/WSS (`--tls-cert/--tls-key`); this also
//!     protects the delivered page itself, whose code handles the password;
//!   * bridge <-> relay/host: KB-Desk TLS (`--tls-ca` for private CAs).
//! `--allow-plaintext` disables both, for local development only.
//!
//! Trust note: whoever controls this web server controls the page's code,
//! and the page handles the password. Serve it from infrastructure you
//! trust, over HTTPS. (The native client needs no web server at all.)

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
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use kbdesk_core::tls::{self, MaybeTlsStream, TlsClientOptions, TlsServerOptions};
use kbdesk_core::{normalize_id, write_packet, Control, KIND_CONTROL};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// TCP+TLS connect to relay/host gets this long before we give up.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Browser-bound queue depth. Unlike the old translating bridge we can never
/// drop bytes (the page's AEAD counters are strict), so a slow browser
/// back-pressures the host, which drops frames *before* encryption instead.
const OUT_QUEUE: usize = 32;
/// Raw chunk size shovelled between the TCP side and the WebSocket.
const CHUNK: usize = 64 * 1024;

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

    /// PEM certificate chain for HTTPS. Env: KB_DESK_TLS_CERT.
    #[arg(long, env = "KB_DESK_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// PEM private key for --tls-cert. Env: KB_DESK_TLS_KEY.
    #[arg(long, env = "KB_DESK_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// PEM CA certificate(s) to trust for the relay/host TLS leg.
    /// Env: KB_DESK_TLS_CA.
    #[arg(long, env = "KB_DESK_TLS_CA")]
    tls_ca: Option<PathBuf>,

    /// Expected name in the relay/host certificate (default: its host).
    /// Env: KB_DESK_TLS_SERVER_NAME.
    #[arg(long, env = "KB_DESK_TLS_SERVER_NAME")]
    tls_server_name: Option<String>,

    /// Accept any relay/host certificate. Local development ONLY.
    #[arg(long)]
    tls_insecure: bool,

    /// Serve plain HTTP and dial without TLS. Local development ONLY —
    /// session content stays end-to-end encrypted between the page and host.
    #[arg(long)]
    allow_plaintext: bool,
}

#[derive(Clone)]
struct AppState {
    relay: Option<String>,
    tls_client: TlsClientOptions,
}

/// The only command the bridge itself understands: open a byte pipe.
/// Deliberately has no password field — authentication happens end-to-end
/// between the page and the host, inside the pipe.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum BrowserMsg {
    Dial {
        id: Option<String>,
        address: Option<String>,
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

    if args.allow_plaintext {
        warn!("--allow-plaintext: serving HTTP and dialling without TLS (page<->host content is still E2E-encrypted; page delivery is NOT protected). Local development only.");
    }
    if args.tls_insecure {
        warn!("--tls-insecure: relay/host certificates will not be verified. Local development only.");
    }

    let state = AppState {
        relay: args.relay.clone(),
        tls_client: TlsClientOptions {
            ca_file: args.tls_ca.clone(),
            server_name: args.tls_server_name.clone(),
            insecure: args.tls_insecure,
            allow_plaintext: args.allow_plaintext,
        },
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/crypto.js", get(crypto_js))
        .route("/config", get(config))
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let server_config = tls::server_config(&TlsServerOptions {
        cert_file: args.tls_cert.clone(),
        key_file: args.tls_key.clone(),
        allow_plaintext: args.allow_plaintext,
    })?;

    info!(addr = %args.listen, relay = ?args.relay, https = server_config.is_some(), "kbdesk-web listening");
    if args.relay.is_none() {
        warn!("no --relay set: browsers must supply a direct host address");
    }
    println!(
        "KB-Desk web viewer:  {}://{}",
        if server_config.is_some() { "https" } else { "http" },
        args.listen
    );
    if let Some(relay) = &args.relay {
        println!("  relay: {relay}");
    }

    match server_config {
        Some(config) => {
            let addr: SocketAddr = args
                .listen
                .parse()
                .with_context(|| format!("parsing --listen address {}", args.listen))?;
            let rustls_config = RustlsConfig::from_config(Arc::new(config));
            axum_server::bind_rustls(addr, rustls_config)
                .serve(app.into_make_service())
                .await
                .context("serving web UI")?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(&args.listen)
                .await
                .with_context(|| format!("binding web UI at {}", args.listen))?;
            axum::serve(listener, app).await.context("serving web UI")?;
        }
    }
    Ok(())
}

async fn index() -> impl IntoResponse {
    // Never let a browser keep a stale viewer page after an upgrade.
    (
        [(header::CACHE_CONTROL, "no-cache")],
        Html(include_str!("../web/index.html")),
    )
}

async fn crypto_js() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-cache"),
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
        ],
        include_str!("../web/crypto.js"),
    )
}

async fn config(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Only tell the browser *whether* a relay is configured, not where it is.
    Json(serde_json::json!({
        "relay": state.relay.is_some(),
        "mode": if state.relay.is_some() { "relay" } else { "direct" },
        "e2e": true,
        "protocol": kbdesk_core::PROTOCOL_VERSION,
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

fn ready_msg() -> Message {
    Message::text(serde_json::json!({ "type": "ready" }).to_string())
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
    // Bounded: back-pressure propagates to the host (see OUT_QUEUE docs).
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

/// Wait for a dial request, open one byte pipe, then wait again — so a failed
/// attempt (host offline) can be retried on the same socket. Each dial uses a
/// fresh TCP/TLS connection because an AEAD session cannot be resumed.
async fn drive(
    ws_rx: &mut SplitStream<WebSocket>,
    out: &mpsc::Sender<Message>,
    state: &AppState,
) -> Result<()> {
    loop {
        // --- wait for a dial command from the browser ---
        let (id, address) = loop {
            match ws_rx.next().await {
                Some(Ok(Message::Text(text))) => match serde_json::from_str::<BrowserMsg>(text.as_str()) {
                    Ok(BrowserMsg::Dial { id, address }) => break (id, address),
                    Ok(BrowserMsg::Disconnect) => {
                        send_status(out, "disconnected").await;
                    }
                    Err(e) => {
                        send_error(out, &format!("bad message: {e}")).await;
                    }
                },
                Some(Ok(Message::Binary(_))) => {
                    send_error(out, "send a dial command before session data").await;
                }
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
        match start_pipe(&target, relay_id.as_deref(), &state.tls_client).await {
            Ok((reader, writer)) => {
                // The pipe is open and (in relay mode) paired. Everything
                // from here is the page<->host conversation: we just carry
                // bytes, which are ciphertext after the key exchange.
                let _ = out.send(ready_msg()).await;
                send_status(out, "pipe open; page is establishing the encrypted session…").await;
                if let Err(e) = pipe(ws_rx, out, reader, writer).await {
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

/// Open the TCP/TLS leg and, in relay mode, send the single routing frame.
/// Returns once paired — never speaks the session protocol itself.
async fn start_pipe(
    server: &str,
    relay_id: Option<&str>,
    tls_client: &TlsClientOptions,
) -> Result<(ReadHalf<MaybeTlsStream>, WriteHalf<MaybeTlsStream>)> {
    let stream = tls::connect_timeout(server, tls_client, DIAL_TIMEOUT)
        .await
        .with_context(|| format!("connecting to {server} (is the relay/host running?)"))?;
    let _ = stream.set_nodelay(true);
    let (reader, mut writer) = tokio::io::split(stream);

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
    Ok((reader, writer))
}

/// Shovel raw chunks between the WebSocket and the host leg until either
/// side ends. No parsing, no decryption, no dropping: chunk boundaries are
/// meaningless to the framed, AEAD-protected protocol inside.
async fn pipe(
    ws_rx: &mut SplitStream<WebSocket>,
    out: &mpsc::Sender<Message>,
    reader: ReadHalf<MaybeTlsStream>,
    mut writer: WriteHalf<MaybeTlsStream>,
) -> Result<()> {
    // The reader runs in its own task and pushes chunks onto a *bounded*
    // channel — awaiting send is what turns a slow browser into TCP
    // back-pressure instead of dropped ciphertext.
    let (chunk_tx, mut chunk_rx) = mpsc::channel::<Result<Vec<u8>>>(OUT_QUEUE);
    let reader_task = tokio::spawn(async move {
        let mut reader = reader;
        let mut buf = vec![0u8; CHUNK];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break, // EOF: channel close ends the session
                Ok(n) => {
                    if chunk_tx.send(Ok(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = chunk_tx.send(Err(e.into())).await;
                    break;
                }
            }
        }
    });

    let result = pipe_loop(ws_rx, out, &mut chunk_rx, &mut writer).await;

    // Note: unlike the old translating bridge we cannot send a final
    // ReleaseAll/StopStream — those frames must be AEAD-encrypted by the
    // page (which sends them before disconnecting). The host also releases
    // all input when this connection drops, so this remains safe.
    let _ = writer.shutdown().await;
    reader_task.abort();
    result
}

async fn pipe_loop(
    ws_rx: &mut SplitStream<WebSocket>,
    out: &mpsc::Sender<Message>,
    chunk_rx: &mut mpsc::Receiver<Result<Vec<u8>>>,
    writer: &mut WriteHalf<MaybeTlsStream>,
) -> Result<()> {
    loop {
        tokio::select! {
            chunk = chunk_rx.recv() => {
                match chunk {
                    Some(Ok(bytes)) => {
                        if out.send(Message::binary(bytes)).await.is_err() {
                            return Ok(()); // browser gone
                        }
                    }
                    Some(Err(e)) => bail!("connection to the host was lost: {e:#}"),
                    None => return Ok(()), // host closed the connection
                }
            }
            message = ws_rx.next() => {
                match message {
                    Some(Ok(Message::Binary(data))) => {
                        writer.write_all(&data).await?;
                        writer.flush().await?;
                    }
                    Some(Ok(Message::Text(text))) => {
                        // The only text understood mid-session is "disconnect".
                        match serde_json::from_str::<BrowserMsg>(text.as_str()) {
                            Ok(BrowserMsg::Disconnect) => return Ok(()),
                            _ => warn!("ignoring unexpected browser text message mid-session"),
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
