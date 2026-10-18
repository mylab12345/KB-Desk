//! KB-Desk host agent.
//!
//! Runs on the machine to be controlled. It can either:
//!   * listen for viewers directly (`--listen`), or
//!   * register with a relay under a numeric id (`--server`).
//!
//! It captures the screen, streams it as JPEG frames, and injects the input
//! events it receives from the viewer.

mod capture;
mod input;

use anyhow::{bail, Context, Result};
use clap::Parser;
use kbdesk_core::{
    encode_video, read_packet, write_packet, Control, Role, VideoFrame, DEFAULT_PORT, KIND_CONTROL,
    KIND_VIDEO, PROTOCOL_VERSION,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "kbdesk-host",
    about = "KB-Desk host agent (shares this screen)",
    version
)]
struct Args {
    /// Fixed numeric id to display. If omitted with --server, the relay assigns one.
    #[arg(long)]
    id: Option<String>,

    /// Session password. Falls back to $KB_DESK_PASSWORD.
    #[arg(long)]
    password: Option<String>,

    /// Relay server address, e.g. 203.0.113.5:21118.
    #[arg(long)]
    server: Option<String>,

    /// Accept direct viewer connections on --bind:--port.
    #[arg(long)]
    listen: bool,

    /// Bind address for --listen.
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

    /// Port for --listen.
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Target frames per second.
    #[arg(long, default_value_t = 15)]
    fps: u8,

    /// JPEG quality (1-100).
    #[arg(long, default_value_t = 70)]
    quality: u8,

    /// Monitor index to capture (0 = primary).
    #[arg(long, default_value_t = 0)]
    monitor: u8,
}

#[derive(Clone)]
struct SessionCfg {
    id: String,
    password: String,
    fps: u8,
    quality: u8,
    monitor: u8,
}

/// Session-wide state shared with the capture thread.
struct StreamState {
    streaming: AtomicBool,
    /// Set when the session is shutting down, so the capture thread stops even
    /// if the frame channel is still (transiently) open.
    stop: AtomicBool,
    /// (quality, fps, monitor)
    params: Mutex<(u8, u8, u8)>,
}

enum OutPacket {
    Control(Control),
    Video(VideoFrame),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let password = args
        .password
        .clone()
        .or_else(|| std::env::var("KB_DESK_PASSWORD").ok())
        .filter(|p| !p.is_empty())
        .context("no password set: pass --password or set KB_DESK_PASSWORD")?;

    if !args.listen && args.server.is_none() {
        bail!("nothing to do: pass --listen and/or --server <relay-address>");
    }

    let cfg = SessionCfg {
        id: args.id.clone().unwrap_or_default(),
        password,
        fps: args.fps,
        quality: args.quality,
        monitor: args.monitor,
    };

    println!("KB-Desk host ready");
    println!("  id       : {}", if cfg.id.is_empty() { "(assigned by relay)" } else { &cfg.id });

    let mut tasks = Vec::new();

    if args.listen {
        let addr = format!("{}:{}", args.bind, args.port);
        let cfg = cfg.clone();
        tasks.push(tokio::spawn(async move { run_listener(addr, cfg).await }));
    }

    if let Some(server) = args.server.clone() {
        let cfg = cfg.clone();
        tasks.push(tokio::spawn(
            async move { register_with_relay(&server, cfg).await },
        ));
    }

    for task in tasks {
        let _ = task.await;
    }
    Ok(())
}

async fn run_listener(addr: String, cfg: SessionCfg) -> Result<()> {
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding listener at {addr}"))?;
    info!("listening for direct connections on {addr}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };
        info!(%peer, "viewer connected");
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = run_session(stream, cfg).await {
                warn!(%peer, "session ended: {e:#}");
            }
        });
    }
}

/// Register with the relay and serve viewers, re-registering after each one so
/// the host stays reachable for as long as the process runs.
async fn register_with_relay(server: &str, cfg: SessionCfg) -> Result<()> {
    let mut cfg = cfg;
    let mut announced: Option<String> = None;
    loop {
        match connect_and_register(server, &cfg).await {
            Ok((id, stream)) => {
                // Keep the same id across re-registrations so viewers can rely on it.
                if cfg.id.is_empty() {
                    cfg.id = id.clone();
                }
                if announced.as_deref() != Some(id.as_str()) {
                    info!("registered with relay; waiting for a viewer");
                    println!("KB-Desk ID: {id}");
                    announced = Some(id.clone());
                }
                if let Err(e) = run_session(stream, cfg.clone()).await {
                    warn!("session ended: {e:#}");
                } else {
                    info!("session ended; ready for another viewer");
                }
            }
            Err(e) => {
                warn!("could not reach relay: {e:#}");
            }
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }
}

/// One registration attempt: connect, announce ourselves, learn our id.
async fn connect_and_register(server: &str, cfg: &SessionCfg) -> Result<(String, TcpStream)> {
    let stream = TcpStream::connect(server)
        .await
        .with_context(|| format!("connecting to relay {server}"))?;
    let (mut reader, mut writer) = stream.into_split();

    write_packet(
        &mut writer,
        KIND_CONTROL,
        &Control::Hello {
            version: PROTOCOL_VERSION,
            role: Role::Host,
            id: cfg.id.clone(),
        }
        .encode(),
    )
    .await?;

    let packet = read_packet(&mut reader).await?;
    let id = match Control::decode(&packet.payload)? {
        Control::AssignedId(id) => id,
        other => bail!("relay refused registration: {other:?}"),
    };

    let stream = reader.reunite(writer).context("reassembling relay stream")?;
    Ok((id, stream))
}

/// Serve one authenticated viewer on an established connection.
async fn run_session(stream: TcpStream, cfg: SessionCfg) -> Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<OutPacket>();

    // Dedicated writer: serialises frames so the read loop never blocks on I/O.
    let writer_task = tokio::spawn(async move {
        while let Some(packet) = out_rx.recv().await {
            let result = match packet {
                OutPacket::Control(control) => {
                    write_packet(&mut writer, KIND_CONTROL, &control.encode()).await
                }
                OutPacket::Video(frame) => {
                    write_packet(&mut writer, KIND_VIDEO, &encode_video(&frame)).await
                }
            };
            if result.is_err() {
                break;
            }
        }
    });

    // Handshake: viewer speaks first with a Hello.
    let first = read_packet(&mut reader)
        .await
        .context("waiting for viewer hello")?;
    if first.kind != KIND_CONTROL {
        bail!("viewer's first frame was not a control frame");
    }
    match Control::decode(&first.payload)? {
        Control::Hello {
            role: Role::Viewer, ..
        } => {}
        other => bail!("unexpected first message from viewer: {other:?}"),
    }

    // Introduce ourselves.
    let _ = out_tx.send(OutPacket::Control(Control::Hello {
        version: PROTOCOL_VERSION,
        role: Role::Host,
        id: cfg.id.clone(),
    }));

    // Authenticate.
    let auth = read_packet(&mut reader).await.context("waiting for auth")?;
    let ok = match Control::decode(&auth.payload)? {
        Control::Auth { password } => password == cfg.password,
        other => {
            let _ = out_tx.send(OutPacket::Control(Control::Error(format!(
                "expected auth, got {other:?}"
            ))));
            false
        }
    };
    let _ = out_tx.send(OutPacket::Control(Control::AuthResult {
        ok,
        reason: if ok { "ok".into() } else { "incorrect password".into() },
    }));
    if !ok {
        info!("rejected viewer: incorrect password");
        return Ok(());
    }
    info!("viewer authenticated");

    let state = Arc::new(StreamState {
        streaming: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        params: Mutex::new((cfg.quality, cfg.fps, cfg.monitor)),
    });
    let input = input::spawn();

    // Capture thread (own OS thread; owns the platform capture handle).
    let capture_state = state.clone();
    let capture_tx = out_tx.clone();
    let capture_thread = std::thread::Builder::new()
        .name("kbdesk-capture".into())
        .spawn(move || {
            if capture_tx.is_closed() {
                return;
            }
            let capture = match capture::Capture::new() {
                Ok(capture) => capture,
                Err(e) => {
                    warn!("screen capture unavailable: {e:#}");
                    return;
                }
            };
            let (w, h) = capture.dimensions();
            info!("capture ready: {w}x{h}");

            loop {
                if capture_state.stop.load(Ordering::Relaxed) || capture_tx.is_closed() {
                    break;
                }
                if !capture_state.streaming.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(40));
                    continue;
                }
                let (quality, fps, monitor) = {
                    let params = capture_state.params.lock().unwrap();
                    *params
                };
                let started = Instant::now();
                match capture.capture_jpeg(quality) {
                    Ok((w, h, jpeg)) => {
                        let frame = VideoFrame {
                            width: w,
                            height: h,
                            monitor,
                            jpeg,
                        };
                        if capture_tx.send(OutPacket::Video(frame)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("capture error: {e:#}");
                        std::thread::sleep(Duration::from_millis(200));
                        continue;
                    }
                }
                let target = Duration::from_millis(1000 / (fps.max(1) as u64));
                if let Some(remaining) = target.checked_sub(started.elapsed()) {
                    std::thread::sleep(remaining);
                }
            }
        })?;

    // Control loop.
    loop {
        let packet = match read_packet(&mut reader).await {
            Ok(packet) => packet,
            Err(_) => break,
        };
        if packet.kind != KIND_CONTROL {
            continue;
        }
        match Control::decode(&packet.payload) {
            Ok(Control::StartStream {
                monitor,
                quality,
                fps,
            }) => {
                {
                    let mut params = state.params.lock().unwrap();
                    *params = (quality, fps, monitor as u8);
                }
                state.streaming.store(true, Ordering::Relaxed);
                info!(monitor, quality, fps, "streaming started");
            }
            Ok(Control::StopStream) => {
                state.streaming.store(false, Ordering::Relaxed);
                info!("stream stopped");
            }
            Ok(Control::Input(event)) => {
                tracing::debug!(?event, "injecting remote input");
                input.send(event);
            }
            Ok(Control::Ping(t)) => {
                let _ = out_tx.send(OutPacket::Control(Control::Pong(t)));
            }
            Ok(Control::Error(message)) => warn!("viewer reported: {message}"),
            Ok(Control::Hello { .. }) => {}
            Ok(other) => info!("unhandled control message: {other:?}"),
            Err(e) => warn!("malformed control frame: {e}"),
        }
    }

    state.streaming.store(false, Ordering::Relaxed);
    state.stop.store(true, Ordering::Relaxed);
    drop(out_tx);
    let _ = capture_thread.join();
    let _ = writer_task.await;
    info!("session closed");
    Ok(())
}
