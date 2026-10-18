//! TLS transport for every KB-Desk network leg (rustls, `ring` provider).
//!
//! Encryption is mandatory: listeners and outbound connections refuse to
//! run without TLS unless the operator explicitly passes
//! `--allow-plaintext` (local development only — every such start logs a
//! loud warning at the call site). Even with plaintext *transport*, the
//! application-level session encryption in [`crate::crypto`] still applies
//! between viewer and host; TLS additionally authenticates servers,
//! protects the relay signalling (host IDs, pairing), and covers the
//! browser page itself (HTTPS/WSS in `kbdesk-web`).
//!
//! Client verification modes, best to last-resort:
//!   * default: WebPKI roots (public CAs, e.g. Let's Encrypt) **plus** any
//!     `--tls-ca FILE` PEM (private CA, e.g. the launcher-generated one);
//!   * `--tls-insecure`: accept any certificate (development only — this
//!     defeats server authentication; the E2E password-bound handshake then
//!     becomes the only MITM barrier on that leg).

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Once};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub use tokio_rustls::TlsAcceptor;

/// Guidance shown when a component is started without the certificates TLS
/// requires and did not explicitly opt into plaintext.
pub const MISSING_TLS_HINT: &str =
    "TLS is mandatory: pass --tls-cert FILE --tls-key FILE (PEM), \
     or run via the `kbdesk` launcher which generates a local CA automatically, \
     or pass --allow-plaintext for local development ONLY";

/// Outbound (client-side) TLS settings, shared by host/client/web binaries.
#[derive(Debug, Clone, Default)]
pub struct TlsClientOptions {
    /// Extra PEM CA certificate(s) to trust (e.g. a private/launcher CA).
    pub ca_file: Option<PathBuf>,
    /// Expected DNS name/IP in the server certificate (default: from the address).
    pub server_name: Option<String>,
    /// Accept any certificate. Development only.
    pub insecure: bool,
    /// Do not use TLS at all. Development only.
    pub allow_plaintext: bool,
}

/// Inbound (server-side) TLS settings, shared by relay/host/web binaries.
#[derive(Debug, Clone, Default)]
pub struct TlsServerOptions {
    /// PEM certificate chain to present.
    pub cert_file: Option<PathBuf>,
    /// PEM private key for the certificate.
    pub key_file: Option<PathBuf>,
    /// Serve plaintext instead of TLS. Development only.
    pub allow_plaintext: bool,
}

/// Install the `ring` crypto provider as rustls' process default (idempotent).
/// Every binary must call this before building rustls configurations.
pub fn ensure_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("reading certificate file {}", path.display()))?;
    let mut reader = io::Cursor::new(data);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<io::Result<Vec<_>>>()
        .with_context(|| format!("parsing PEM certificates in {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).with_context(|| format!("reading key file {}", path.display()))?;
    let mut reader = io::Cursor::new(data);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing PEM private key in {}", path.display()))?
        .with_context(|| format!("no private key found in {}", path.display()))
}

/// Build a rustls `ServerConfig`, or `None` if plaintext was opted into.
/// Errors when TLS is required (default) but cert/key are missing.
pub fn server_config(opts: &TlsServerOptions) -> Result<Option<ServerConfig>> {
    ensure_crypto_provider();
    if opts.allow_plaintext {
        return Ok(None);
    }
    let (cert_file, key_file) = match (&opts.cert_file, &opts.key_file) {
        (Some(cert), Some(key)) => (cert, key),
        _ => bail!("{MISSING_TLS_HINT}"),
    };
    let certs = load_certs(cert_file)?;
    let key = load_key(key_file)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS server configuration (does the key match the certificate?)")?;
    Ok(Some(config))
}

/// Build a `TlsAcceptor` from server options (see [`server_config`]).
pub fn tls_acceptor(opts: &TlsServerOptions) -> Result<Option<TlsAcceptor>> {
    Ok(server_config(opts)?.map(|cfg| TlsAcceptor::from(Arc::new(cfg))))
}

/// Accept-any-certificate verifier for `--tls-insecure` (development only).
#[derive(Debug)]
struct NoServerVerify;

impl ServerCertVerifier for NoServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a rustls `ClientConfig`, or `None` if plaintext was opted into.
pub fn client_config(opts: &TlsClientOptions) -> Result<Option<Arc<ClientConfig>>> {
    ensure_crypto_provider();
    if opts.allow_plaintext {
        return Ok(None);
    }
    if opts.insecure {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoServerVerify))
            .with_no_client_auth();
        return Ok(Some(Arc::new(config)));
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(ca_file) = &opts.ca_file {
        for cert in load_certs(ca_file)? {
            roots
                .add(cert)
                .with_context(|| format!("adding CA certificate(s) from {}", ca_file.display()))?;
        }
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Some(Arc::new(config)))
}

/// The server name to verify/connect with for `addr` (host:port form).
fn server_name_for(addr: &str, opts: &TlsClientOptions) -> Result<ServerName<'static>> {
    let name = match &opts.server_name {
        Some(name) => name.clone(),
        None => {
            let host = addr
                .rsplit_once(':')
                .map(|(host, _port)| host)
                .unwrap_or(addr)
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            host
        }
    };
    ServerName::try_from(name.clone())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name {name:?} (set --tls-server-name)"))
}

/// A TCP stream that may be wrapped in TLS (client or server side).
/// One concrete type for every leg keeps session code transport-agnostic.
pub enum MaybeTlsStream {
    Plain(TcpStream),
    TlsClient(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    TlsServer(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl MaybeTlsStream {
    pub fn is_tls(&self) -> bool {
        !matches!(self, MaybeTlsStream::Plain(_))
    }

    fn tcp(&self) -> &TcpStream {
        match self {
            MaybeTlsStream::Plain(stream) => stream,
            MaybeTlsStream::TlsClient(stream) => stream.get_ref().0,
            MaybeTlsStream::TlsServer(stream) => stream.get_ref().0,
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.tcp().set_nodelay(nodelay)
    }

    /// Peek at the underlying TCP socket without consuming anything from the
    /// (possibly TLS) stream. Used by the relay's dead-host reaper:
    /// `Ok(0)`/error = peer gone, timeout or `Ok(n)` = alive.
    pub async fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp().peek(buf).await
    }
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            MaybeTlsStream::TlsClient(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
            MaybeTlsStream::TlsServer(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_write(cx, data),
            MaybeTlsStream::TlsClient(stream) => Pin::new(stream.as_mut()).poll_write(cx, data),
            MaybeTlsStream::TlsServer(stream) => Pin::new(stream.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            MaybeTlsStream::TlsClient(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
            MaybeTlsStream::TlsServer(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            MaybeTlsStream::TlsClient(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
            MaybeTlsStream::TlsServer(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Connect to `addr` ("host:port"), upgrading to TLS unless plaintext was
/// explicitly opted into.
pub async fn connect(addr: &str, opts: &TlsClientOptions) -> Result<MaybeTlsStream> {
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to {addr}"))?;
    let _ = tcp.set_nodelay(true);
    match client_config(opts)? {
        None => Ok(MaybeTlsStream::Plain(tcp)),
        Some(config) => {
            let connector = TlsConnector::from(config);
            let name = server_name_for(addr, opts)?;
            let tls = connector
                .connect(name, tcp)
                .await
                .with_context(|| format!("TLS handshake with {addr}"))?;
            Ok(MaybeTlsStream::TlsClient(Box::new(tls)))
        }
    }
}

/// [`connect`] with an overall timeout (TCP + TLS handshake).
pub async fn connect_timeout(
    addr: &str,
    opts: &TlsClientOptions,
    timeout: Duration,
) -> Result<MaybeTlsStream> {
    tokio::time::timeout(timeout, connect(addr, opts))
        .await
        .with_context(|| format!("timed out connecting to {addr}"))?
}

/// Wrap an accepted TCP connection per the acceptor (or pass it through
/// unchanged in plaintext mode).
pub async fn accept(stream: TcpStream, acceptor: Option<&TlsAcceptor>) -> Result<MaybeTlsStream> {
    let _ = stream.set_nodelay(true);
    match acceptor {
        None => Ok(MaybeTlsStream::Plain(stream)),
        Some(acceptor) => {
            let tls = acceptor
                .accept(stream)
                .await
                .context("TLS handshake with connecting peer")?;
            Ok(MaybeTlsStream::TlsServer(Box::new(tls)))
        }
    }
}
