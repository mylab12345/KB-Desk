//! KB-Desk one-command launcher.
//!
//! Starts the right combination of the other KB-Desk binaries for a given job,
//! on Windows, macOS and Linux alike, so the same command works everywhere:
//!
//!   kbdesk up       relay + host + web viewer on this machine
//!   kbdesk web      host + web viewer (no relay)
//!   kbdesk serve    relay + web viewer only (run on a server; hosts anywhere
//!                   register with it, browsers anywhere control them by id)
//!   kbdesk host     host sharing this screen directly
//!   kbdesk relay    relay/rendezvous server only
//!   kbdesk viewer   native desktop viewer
//!
//! It finds the sibling binaries next to itself (all are produced together by
//! `cargo build --release`), spawns them, prints the browser URL / host id, and
//! shuts everything down when you press Ctrl-C.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(
    name = "kbdesk",
    about = "KB-Desk launcher — start a remote-desktop session in one command",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Session password. Falls back to $KB_DESK_PASSWORD, else a random one.
    #[arg(long, global = true)]
    password: Option<String>,

    /// Fixed host id (relay mode). Omit to let the relay assign one.
    #[arg(long, global = true)]
    id: Option<String>,

    /// Interface the web viewer listens on (0.0.0.0 = reachable on the LAN).
    #[arg(long, global = true, default_value = "0.0.0.0")]
    bind: String,

    /// Port for the web viewer.
    #[arg(long, global = true, default_value_t = 8080)]
    web_port: u16,

    /// Port for the relay.
    #[arg(long, global = true, default_value_t = 21118)]
    relay_port: u16,

    /// Port the host listens on in `web` (direct) mode.
    #[arg(long, global = true, default_value_t = 21119)]
    host_port: u16,

    /// Target frames per second.
    #[arg(long, global = true, default_value_t = 15)]
    fps: u8,

    /// JPEG quality (1-100).
    #[arg(long, global = true, default_value_t = 70)]
    quality: u8,
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum Cmd {
    /// Relay + host + web viewer on this machine (viewers need only an id).
    Up,
    /// Host + web viewer, no relay (viewers enter this machine's address).
    Web,
    /// Relay + web viewer only — the browser front door for hosts anywhere.
    /// Run this on a LAN/VPS server: controlled machines run
    /// `kbdesk-host --server <this-host>:<relay-port>`, and anyone can then
    /// control them from a browser at http://<this-host>:<web-port>/.
    Serve,
    /// Share this screen, accepting direct connections.
    Host,
    /// Run the relay/rendezvous server only.
    Relay,
    /// Run the native desktop viewer.
    Viewer,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("kbdesk: {e:#}");
        std::process::exit(1);
    }
}

struct Service {
    name: String,
    child: Child,
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let cmd = cli.cmd.unwrap_or(Cmd::Up);
    let password = resolve_password(cli.password.clone());

    let mut services: Vec<Service> = Vec::new();
    let id_slot = Arc::new(Mutex::new(None::<String>));

    match cmd {
        Cmd::Up => {
            // Relay is only needed by the local host and web app, so keep it
            // off the network.
            services.push(start(
                "kbdesk-server",
                &[
                    "--bind".into(),
                    "127.0.0.1".into(),
                    "--port".into(),
                    cli.relay_port.to_string(),
                ],
                None,
            )?);

            let mut host_args = vec![
                "--server".into(),
                format!("127.0.0.1:{}", cli.relay_port),
                "--password".into(),
                password.clone(),
                "--fps".into(),
                cli.fps.to_string(),
                "--quality".into(),
                cli.quality.to_string(),
            ];
            if let Some(id) = cli.id.clone() {
                host_args.push("--id".into());
                host_args.push(id);
            }
            services.push(start("kbdesk-host", &host_args, Some(id_slot.clone()))?);

            services.push(start(
                "kbdesk-web",
                &[
                    "--listen".into(),
                    format!("{}:{}", cli.bind, cli.web_port),
                    "--relay".into(),
                    format!("127.0.0.1:{}", cli.relay_port),
                ],
                None,
            )?);

            // Give the host a moment to register so the id can be shown.
            let id = wait_for_id(&id_slot, Duration::from_secs(6));
            banner("relay", &cli, Some(&password), id.as_deref(), None);
        }
        Cmd::Web => {
            // Host stays on loopback: the web app is the only front door.
            services.push(start(
                "kbdesk-host",
                &[
                    "--listen".into(),
                    "--bind".into(),
                    "127.0.0.1".into(),
                    "--port".into(),
                    cli.host_port.to_string(),
                    "--password".into(),
                    password.clone(),
                    "--fps".into(),
                    cli.fps.to_string(),
                    "--quality".into(),
                    cli.quality.to_string(),
                ],
                Some(id_slot.clone()),
            )?);

            services.push(start(
                "kbdesk-web",
                &[
                    "--listen".into(),
                    format!("{}:{}", cli.bind, cli.web_port),
                ],
                None,
            )?);

            let host_addr = format!("127.0.0.1:{}", cli.host_port);
            banner("direct", &cli, Some(&password), None, Some(&host_addr));
        }
        Cmd::Serve => {
            // Relay faces the network (hosts anywhere register with it); the
            // web bridge also faces the network (browsers anywhere), and it
            // talks to the relay over loopback.
            services.push(start(
                "kbdesk-server",
                &[
                    "--bind".into(),
                    cli.bind.clone(),
                    "--port".into(),
                    cli.relay_port.to_string(),
                ],
                None,
            )?);

            services.push(start(
                "kbdesk-web",
                &[
                    "--listen".into(),
                    format!("{}:{}", cli.bind, cli.web_port),
                    "--relay".into(),
                    format!("127.0.0.1:{}", cli.relay_port),
                ],
                None,
            )?);

            let ip = local_ip().unwrap_or_else(|| "localhost".to_string());
            let line = "─".repeat(60);
            println!("{line}");
            println!("  KB-Desk relay + browser viewer are running");
            println!("{line}");
            println!("  1. On each machine to control, run:");
            println!(
                "       kbdesk-host --server {ip}:{} --password <pw>",
                cli.relay_port
            );
            println!("     (it prints a 9-digit ID; use a different password per machine)");
            println!("  2. To control it, open in any browser:");
            println!("       http://{ip}:{}", cli.web_port);
            println!("     and enter that ID + its password. Nothing to install.");
            println!("{line}");
        }
        Cmd::Relay => {
            services.push(start(
                "kbdesk-server",
                &[
                    "--bind".into(),
                    cli.bind.clone(),
                    "--port".into(),
                    cli.relay_port.to_string(),
                ],
                None,
            )?);
            println!("KB-Desk relay listening on {}:{}", cli.bind, cli.relay_port);
        }
        Cmd::Host => {
            services.push(start(
                "kbdesk-host",
                &[
                    "--listen".into(),
                    "--bind".into(),
                    cli.bind.clone(),
                    "--port".into(),
                    cli.host_port.to_string(),
                    "--password".into(),
                    password.clone(),
                ],
                Some(id_slot.clone()),
            )?);
            println!(
                "KB-Desk host sharing this screen on {}:{}",
                cli.bind, cli.host_port
            );
            println!("Password: {password}");
        }
        Cmd::Viewer => {
            services.push(start("kbdesk-client", &[], None)?);
        }
    }

    println!();
    println!("Press Ctrl-C to stop.");

    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let interrupted = interrupted.clone();
        let _ = ctrlc::set_handler(move || {
            interrupted.store(true, Ordering::SeqCst);
        });
    }
    supervise(&mut services, &interrupted)
}

/// Build and launch a service, optionally watching its stdout for the host id.
fn start(
    name: &str,
    args: &[String],
    watch_id: Option<Arc<Mutex<Option<String>>>>,
) -> Result<Service> {
    let path = sibling_binary(name)?;
    let mut command = Command::new(&path);
    command.args(args);
    if watch_id.is_some() {
        command.stdout(Stdio::piped());
        command.stderr(Stdio::inherit());
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("starting {}", path.display()))?;

    if let (Some(slot), Some(stdout)) = (watch_id, child.stdout.take()) {
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                println!("[host] {line}");
                if let Some(rest) = line.strip_prefix("KB-Desk ID:") {
                    let id = rest.trim().to_string();
                    if !id.is_empty() {
                        *slot.lock().unwrap() = Some(id);
                    }
                }
            }
        });
    }

    Ok(Service {
        name: name.to_string(),
        child,
    })
}

/// Locate a KB-Desk binary that sits next to this launcher executable.
fn sibling_binary(name: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locating the launcher executable")?;
    let dir = exe
        .parent()
        .context("launcher executable has no parent directory")?;
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let path = dir.join(&file);
    if !path.exists() {
        bail!(
            "{} not found (looked in {}).\n       Build everything first:  cargo build --release",
            file,
            dir.display()
        );
    }
    Ok(path)
}

/// Wait up to `limit` for the host to report its id.
fn wait_for_id(slot: &Arc<Mutex<Option<String>>>, limit: Duration) -> Option<String> {
    let deadline = std::time::Instant::now() + limit;
    while std::time::Instant::now() < deadline {
        if let Some(id) = slot.lock().unwrap().clone() {
            return Some(id);
        }
        thread::sleep(Duration::from_millis(150));
    }
    slot.lock().unwrap().clone()
}

fn banner(mode: &str, cli: &Cli, password: Option<&str>, id: Option<&str>, host_addr: Option<&str>) {
    let ip = local_ip().unwrap_or_else(|| "localhost".to_string());
    let line = "─".repeat(60);
    println!("{line}");
    println!("  KB-Desk is running  ({mode} mode)");
    println!("{line}");
    println!("  Open in a browser :  http://{ip}:{}", cli.web_port);
    if let Some(id) = id {
        println!("  Host ID           :  {id}");
    }
    if let Some(addr) = host_addr {
        println!("  Address to enter  :  {addr}");
    }
    if let Some(password) = password {
        println!("  Password          :  {password}");
    }
    println!("{line}");
}

/// Best-effort LAN IP without any platform-specific code: opening a UDP socket
/// and "connecting" it (which sends nothing) reveals the outbound interface.
fn local_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn resolve_password(explicit: Option<String>) -> String {
    if let Some(p) = explicit.filter(|p| !p.is_empty()) {
        return p;
    }
    if let Ok(p) = std::env::var("KB_DESK_PASSWORD") {
        if !p.is_empty() {
            return p;
        }
    }
    generate_password()
}

/// A readable, high-entropy session password (ambiguous characters removed).
fn generate_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        // Extremely unlikely; fall back to clock entropy so we still start.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (nanos.rotate_left(i as u32 * 7) & 0xff) as u8;
        }
    }
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

/// Wait for any service to exit (or for Ctrl-C), then bring the rest down.
fn supervise(services: &mut Vec<Service>, interrupted: &AtomicBool) -> Result<()> {
    loop {
        if interrupted.load(Ordering::SeqCst) {
            println!("\nkbdesk: stopping…");
            shutdown(services);
            std::process::exit(0);
        }
        for service in services.iter_mut() {
            if let Ok(Some(status)) = service.child.try_wait() {
                eprintln!(
                    "\nkbdesk: '{}' exited ({status}); stopping the others",
                    service.name
                );
                shutdown(services);
                std::process::exit(if status.success() { 0 } else { 1 });
            }
        }
        thread::sleep(Duration::from_millis(300));
    }
}

fn shutdown(services: &mut [Service]) {
    for service in services.iter_mut() {
        let _ = service.child.kill();
        let _ = service.child.wait();
    }
}
