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
//!
//! Encryption: every KB-Desk leg is TLS and every viewer<->host session is
//! additionally end-to-end encrypted. So that one-command modes stay
//! one-command, the launcher manages a small local CA in `./kbdesk-tls/`
//! (generated once with rcgen, then reused): server components get a leaf
//! certificate, client components get `ca.pem` to verify against. Operators
//! with real certificates (Let's Encrypt, corporate PKI) override with
//! `--tls-cert/--tls-key/--tls-ca`. `--allow-plaintext` exists for local
//! development only. See docs/encryption-and-certificates.md.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
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

    /// Use this PEM certificate chain for TLS listeners instead of the
    /// launcher-generated one (needs --tls-key). Env: KB_DESK_TLS_CERT.
    #[arg(long, global = true, env = "KB_DESK_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// PEM private key for --tls-cert. Env: KB_DESK_TLS_KEY.
    #[arg(long, global = true, env = "KB_DESK_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// PEM CA certificate(s) client components should trust (defaults to the
    /// launcher-generated CA, or just the public WebPKI roots when you supply
    /// your own publicly-trusted --tls-cert). Env: KB_DESK_TLS_CA.
    #[arg(long, global = true, env = "KB_DESK_TLS_CA")]
    tls_ca: Option<PathBuf>,

    /// Extra DNS name/IP to include in the generated certificate (repeatable),
    /// e.g. --tls-host kb.example.com when clients use that name to reach this
    /// machine. Delete ./kbdesk-tls to regenerate after changing this.
    #[arg(long, global = true)]
    tls_host: Vec<String>,

    /// Directory for the generated CA + certificates.
    #[arg(long, global = true, default_value = "kbdesk-tls")]
    tls_dir: PathBuf,

    /// Disable TLS entirely. Local development ONLY — viewer<->host session
    /// content remains end-to-end encrypted, but relay signalling and the web
    /// page are then served in the clear.
    #[arg(long, global = true)]
    allow_plaintext: bool,
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
enum Cmd {
    /// Relay + host + web viewer on this machine (viewers need only an id).
    Up,
    /// Host + web viewer, no relay (viewers enter this machine's address).
    Web,
    /// Relay + web viewer only — the browser front door for hosts anywhere.
    /// Run this on a LAN/VPS server: controlled machines run
    /// `kbdesk-host --server <this-host>:<relay-port>`, and anyone can then
    /// control them from a browser at https://<this-host>:<web-port>/.
    Serve,
    /// Share this screen, accepting direct connections.
    Host,
    /// Run the relay/rendezvous server only.
    Relay,
    /// Run the native desktop viewer.
    Viewer,
}

/// Certificate material handed to child processes (None = plaintext mode).
#[derive(Clone)]
struct TlsMaterial {
    /// PEM chain for listeners (leaf, then issuing CA).
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    /// CA PEM for clients to verify against (None = WebPKI roots only).
    ca: Option<PathBuf>,
    plaintext: bool,
}

impl TlsMaterial {
    /// Listener flags (--tls-cert/--tls-key or --allow-plaintext).
    fn server_args(&self) -> Vec<String> {
        if self.plaintext {
            return vec!["--allow-plaintext".into()];
        }
        let mut args = Vec::new();
        if let (Some(cert), Some(key)) = (&self.cert, &self.key) {
            args.push("--tls-cert".into());
            args.push(cert.display().to_string());
            args.push("--tls-key".into());
            args.push(key.display().to_string());
        }
        args
    }

    /// Client flags (--tls-ca or --allow-plaintext).
    fn client_args(&self) -> Vec<String> {
        if self.plaintext {
            return vec!["--allow-plaintext".into()];
        }
        let mut args = Vec::new();
        if let Some(ca) = &self.ca {
            args.push("--tls-ca".into());
            args.push(ca.display().to_string());
        }
        args
    }

    /// Environment for the native viewer, which is configured via env only.
    fn client_env(&self) -> Vec<(String, String)> {
        if self.plaintext {
            return vec![("KB_DESK_ALLOW_PLAINTEXT".into(), "1".into())];
        }
        match &self.ca {
            Some(ca) => vec![("KB_DESK_TLS_CA".into(), ca.display().to_string())],
            None => Vec::new(),
        }
    }

    fn scheme(&self) -> &'static str {
        if self.plaintext { "http" } else { "https" }
    }
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

    if cli.allow_plaintext {
        eprintln!("kbdesk: WARNING --allow-plaintext: TLS disabled (session content still E2E-encrypted). Local development only.");
    }
    // The viewer subcommand needs no server certificate; everything else does.
    let tls = prepare_tls(&cli, cmd != Cmd::Viewer)?;

    let mut services: Vec<Service> = Vec::new();
    let id_slot = Arc::new(Mutex::new(None::<String>));

    match cmd {
        Cmd::Up => {
            // Relay is only needed by the local host and web app, so keep it
            // off the network.
            let mut server_args = vec![
                "--bind".into(),
                "127.0.0.1".into(),
                "--port".into(),
                cli.relay_port.to_string(),
            ];
            server_args.extend(tls.server_args());
            services.push(start("kbdesk-server", &server_args, &[], None)?);

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
            host_args.extend(tls.client_args());
            if let Some(id) = cli.id.clone() {
                host_args.push("--id".into());
                host_args.push(id);
            }
            services.push(start("kbdesk-host", &host_args, &[], Some(id_slot.clone()))?);

            let mut web_args = vec![
                "--listen".into(),
                format!("{}:{}", cli.bind, cli.web_port),
                "--relay".into(),
                format!("127.0.0.1:{}", cli.relay_port),
            ];
            web_args.extend(tls.server_args());
            web_args.extend(tls.client_args());
            services.push(start("kbdesk-web", &web_args, &[], None)?);

            // Give the host a moment to register so the id can be shown.
            let id = wait_for_id(&id_slot, Duration::from_secs(6));
            banner("relay", &cli, &tls, Some(&password), id.as_deref(), None);
        }
        Cmd::Web => {
            // Host stays on loopback: the web app is the only front door.
            let mut host_args = vec![
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
            ];
            host_args.extend(tls.server_args());
            services.push(start("kbdesk-host", &host_args, &[], Some(id_slot.clone()))?);

            let mut web_args = vec![
                "--listen".into(),
                format!("{}:{}", cli.bind, cli.web_port),
            ];
            web_args.extend(tls.server_args());
            web_args.extend(tls.client_args());
            services.push(start("kbdesk-web", &web_args, &[], None)?);

            let host_addr = format!("127.0.0.1:{}", cli.host_port);
            banner("direct", &cli, &tls, Some(&password), None, Some(&host_addr));
        }
        Cmd::Serve => {
            // Relay faces the network (hosts anywhere register with it); the
            // web bridge also faces the network (browsers anywhere), and it
            // talks to the relay over loopback.
            let mut server_args = vec![
                "--bind".into(),
                cli.bind.clone(),
                "--port".into(),
                cli.relay_port.to_string(),
            ];
            server_args.extend(tls.server_args());
            services.push(start("kbdesk-server", &server_args, &[], None)?);

            let mut web_args = vec![
                "--listen".into(),
                format!("{}:{}", cli.bind, cli.web_port),
                "--relay".into(),
                format!("127.0.0.1:{}", cli.relay_port),
            ];
            web_args.extend(tls.server_args());
            web_args.extend(tls.client_args());
            services.push(start("kbdesk-web", &web_args, &[], None)?);

            let ip = local_ip().unwrap_or_else(|| "localhost".to_string());
            let line = "─".repeat(60);
            println!("{line}");
            println!("  KB-Desk relay + browser viewer are running (TLS + E2E encrypted)");
            println!("{line}");
            println!("  1. On each machine to control, run:");
            match &tls.ca {
                Some(ca) => {
                    println!("       copy {} to it, then:", ca.display());
                    println!(
                        "       kbdesk-host --server {ip}:{} --password <pw> --tls-ca ca.pem",
                        cli.relay_port
                    );
                }
                None if tls.plaintext => {
                    println!(
                        "       kbdesk-host --server {ip}:{} --password <pw> --allow-plaintext",
                        cli.relay_port
                    );
                }
                None => {
                    println!(
                        "       kbdesk-host --server {ip}:{} --password <pw>",
                        cli.relay_port
                    );
                }
            }
            println!("     (it prints a 9-digit ID; use a different password per machine)");
            println!("  2. To control it, open in any browser:");
            println!("       {}://{ip}:{}", tls.scheme(), cli.web_port);
            println!("     and enter that ID + its password. Nothing to install.");
            if tls.ca.is_some() && !tls.plaintext {
                println!("  Note: the generated local CA is not in any browser's trust");
                println!("  store. For a warning-free public deployment use real");
                println!("  certificates (--tls-cert/--tls-key) or import ca.pem.");
            }
            println!("{line}");
        }
        Cmd::Relay => {
            let mut server_args = vec![
                "--bind".into(),
                cli.bind.clone(),
                "--port".into(),
                cli.relay_port.to_string(),
            ];
            server_args.extend(tls.server_args());
            services.push(start("kbdesk-server", &server_args, &[], None)?);
            println!("KB-Desk relay listening on {}:{}", cli.bind, cli.relay_port);
            if let Some(ca) = &tls.ca {
                println!("Hosts/viewers must trust the CA at {} (pass --tls-ca ca.pem).", ca.display());
            }
        }
        Cmd::Host => {
            let mut host_args = vec![
                "--listen".into(),
                "--bind".into(),
                cli.bind.clone(),
                "--port".into(),
                cli.host_port.to_string(),
                "--password".into(),
                password.clone(),
            ];
            host_args.extend(tls.server_args());
            services.push(start("kbdesk-host", &host_args, &[], Some(id_slot.clone()))?);
            println!(
                "KB-Desk host sharing this screen on {}:{}",
                cli.bind, cli.host_port
            );
            println!("Password: {password}");
            if let Some(ca) = &tls.ca {
                println!("Native viewers must trust the CA at {} (KB_DESK_TLS_CA).", ca.display());
            }
        }
        Cmd::Viewer => {
            services.push(start("kbdesk-client", &[], &tls.client_env(), None)?);
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

/// Resolve certificate material once, generating a local CA when needed.
fn prepare_tls(cli: &Cli, need_server_cert: bool) -> Result<TlsMaterial> {
    if cli.allow_plaintext {
        return Ok(TlsMaterial { cert: None, key: None, ca: None, plaintext: true });
    }
    match (&cli.tls_cert, &cli.tls_key) {
        (Some(cert), Some(key)) => {
            return Ok(TlsMaterial {
                cert: Some(cert.clone()),
                key: Some(key.clone()),
                ca: cli.tls_ca.clone(),
                plaintext: false,
            });
        }
        (None, None) => {}
        _ => bail!("--tls-cert and --tls-key must be given together"),
    }

    if !need_server_cert {
        // Viewer: trust an explicit --tls-ca, else an existing generated CA,
        // else just the public roots. Never generate for a pure viewer.
        let generated_ca = cli.tls_dir.join("ca.pem");
        let ca = cli.tls_ca.clone().or_else(|| {
            if generated_ca.exists() { Some(generated_ca) } else { None }
        });
        return Ok(TlsMaterial { cert: None, key: None, ca, plaintext: false });
    }

    let dir = cli.tls_dir.clone();
    let ca_pem = dir.join("ca.pem");
    let ca_key_pem = dir.join("ca-key.pem");
    let cert_pem = dir.join("cert.pem");
    let key_pem = dir.join("key.pem");
    if ca_pem.exists() && cert_pem.exists() && key_pem.exists() {
        println!("kbdesk: using TLS material in {}", dir.display());
        return Ok(TlsMaterial {
            cert: Some(cert_pem),
            key: Some(key_pem),
            ca: Some(cli.tls_ca.clone().unwrap_or(ca_pem)),
            plaintext: false,
        });
    }

    println!("kbdesk: generating a local CA + TLS certificate in {} …", dir.display());
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    // --- local CA ---
    let mut ca_params = CertificateParams::new(Vec::new()).context("CA params")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "KB-Desk local CA");
    ca_params.distinguished_name.push(DnType::OrganizationName, "KB-Desk (auto-generated)");
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params.not_before = date_time_ymd(2024, 1, 1);
    ca_params.not_after = date_time_ymd(2044, 1, 1);
    let ca_key = KeyPair::generate().context("generating CA key")?;
    let ca_cert = ca_params.self_signed(&ca_key).context("self-signing CA")?;
    let ca_key_serialized = ca_key.serialize_pem();
    let issuer = Issuer::new(ca_params, ca_key);

    // --- leaf certificate for this machine's services ---
    let mut sans: Vec<String> = ["localhost", "127.0.0.1", "::1"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if let Some(ip) = local_ip() {
        sans.push(ip);
    }
    let bind_san = cli.bind.trim().to_string();
    if !bind_san.is_empty() && bind_san != "0.0.0.0" && bind_san != "::" {
        sans.push(bind_san);
    }
    sans.extend(cli.tls_host.iter().cloned());
    sans.sort();
    sans.dedup();

    let mut leaf_params = CertificateParams::new(sans.clone()).context("leaf params")?;
    leaf_params.distinguished_name.push(DnType::CommonName, "KB-Desk services");
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    leaf_params.not_before = date_time_ymd(2024, 1, 1);
    leaf_params.not_after = date_time_ymd(2034, 1, 1);
    let leaf_key = KeyPair::generate().context("generating leaf key")?;
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .context("signing leaf certificate")?;

    write_file(&ca_pem, &ca_cert.pem(), false)?;
    write_file(&ca_key_pem, &ca_key_serialized, true)?;
    // Listeners present leaf + CA chain; rustls takes the first key it finds.
    write_file(&cert_pem, &format!("{}\n{}", leaf_cert.pem(), ca_cert.pem()), false)?;
    write_file(&key_pem, &leaf_key.serialize_pem(), true)?;

    println!("kbdesk: generated CA covers: {}", sans.join(", "));
    println!("kbdesk: give {} to any KB-Desk client that must trust this machine.", ca_pem.display());

    Ok(TlsMaterial {
        cert: Some(cert_pem),
        key: Some(key_pem),
        ca: Some(cli.tls_ca.clone().unwrap_or(ca_pem)),
        plaintext: false,
    })
}

fn write_file(path: &Path, contents: &str, private: bool) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    let _ = private;
    Ok(())
}

/// Build and launch a service, optionally watching its stdout for the host id.
fn start(
    name: &str,
    args: &[String],
    envs: &[(String, String)],
    watch_id: Option<Arc<Mutex<Option<String>>>>,
) -> Result<Service> {
    let path = sibling_binary(name)?;
    let mut command = Command::new(&path);
    command.args(args);
    for (k, v) in envs {
        command.env(k, v);
    }
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

fn banner(mode: &str, cli: &Cli, tls: &TlsMaterial, password: Option<&str>, id: Option<&str>, host_addr: Option<&str>) {
    let ip = local_ip().unwrap_or_else(|| "localhost".to_string());
    let line = "─".repeat(60);
    println!("{line}");
    println!("  KB-Desk is running  ({mode} mode · TLS + end-to-end encrypted)");
    println!("{line}");
    println!("  Open in a browser :  {}://{ip}:{}", tls.scheme(), cli.web_port);
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
