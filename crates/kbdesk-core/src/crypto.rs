//! End-to-end session encryption between viewer and host (protocol v2).
//!
//! This layer sits *inside* whatever transport carries the frames (direct
//! TCP/TLS, the relay's byte pump, or the web bridge's WebSocket), so the
//! relay and the web bridge only ever forward ciphertext. The host password
//! is never transmitted: it is mixed into the key derivation and proven via
//! key-confirmation values.
//!
//! Construction (implemented identically in Rust, the browser page
//! `crates/kbdesk-web/web/crypto.js`, and the Python reference
//! `tests/e2e/kb_crypto.py`; all three are pinned to one test vector):
//!
//! ```text
//! T   = SHA256("KBDesk-v2-transcript" || client_pub || host_pub
//!              || client_nonce || host_nonce || host_id_utf8)
//! P   = SHA256(password_utf8)
//! S   = X25519(my_secret, peer_pub)                 (all-zero rejected)
//! PRK = HKDF-Extract(salt = T, IKM = S || P)        (HKDF-SHA256, RFC 5869)
//! labels via HKDF-Expand: "* confirm" (32B), per-direction *" key" (32B)
//!         and *" nonce" (4B prefix)
//! frame AEAD (ChaCha20-Poly1305, RFC 8439):
//!   nonce = prefix(4) || counter_u64_be             (per direction, from 0)
//!   aad   = "KBDesk-v2-frame" || kind_byte || counter_u64_be
//!   wire payload = counter_u64_be || ciphertext||tag
//! ```
//!
//! Security properties: ephemeral X25519 gives forward secrecy per session;
//! because the password is part of the extracted key material, a passive
//! observer cannot dictionary-attack it (they cannot compute S), and an
//! active man-in-the-middle gets exactly one password guess per connection
//! attempt, which the key-confirmation step exposes. Counters are strict
//! and sequential, so replays/reordering are detected.

use crate::frame::{read_packet, write_packet, Packet, KIND_CONTROL};
use crate::protocol::{Control, Role, PROTOCOL_VERSION};
use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use x25519_dalek::{PublicKey, StaticSecret};

const TRANSCRIPT_LABEL: &[u8] = b"KBDesk-v2-transcript";
const FRAME_AAD_LABEL: &[u8] = b"KBDesk-v2-frame";
/// Timeout for handshake steps once both peers are known to be present.
const HANDSHAKE_STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Fill a byte array from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| anyhow!("OS randomness unavailable: {e}"))?;
    Ok(buf)
}

/// Lowercase hex encoding (used for keys/nonces/confirmations in `Control`).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decode lowercase/uppercase hex produced by [`hex_encode`].
pub fn hex_decode(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        bail!("hex string has odd length");
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = char::from(pair[0]).to_digit(16).context("invalid hex")?;
        let lo = char::from(pair[1]).to_digit(16).context("invalid hex")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn hex32(text: &str, what: &str) -> Result<[u8; 32]> {
    let v = hex_decode(text)?;
    v.try_into()
        .map_err(|_| anyhow!("{what} must be 32 bytes (64 hex chars)"))
}

fn hex16(text: &str, what: &str) -> Result<[u8; 16]> {
    let v = hex_decode(text)?;
    v.try_into()
        .map_err(|_| anyhow!("{what} must be 16 bytes (32 hex chars)"))
}

/// Constant-time equality for confirmation values.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// An ephemeral X25519 keypair for one session.
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        Ok(Self::from_secret_bytes(random_bytes::<32>()?))
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        KeyPair { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}

/// One direction of the encrypted frame stream (its own key + counter pair).
pub struct SessionCipher {
    cipher: ChaCha20Poly1305,
    nonce_prefix: [u8; 4],
    tx_counter: u64,
    rx_expected: u64,
}

impl SessionCipher {
    fn new(key: [u8; 32], nonce_prefix: [u8; 4]) -> Self {
        SessionCipher {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            nonce_prefix,
            tx_counter: 0,
            rx_expected: 0,
        }
    }

    fn nonce_and_aad(&self, kind: u8, counter: u64) -> (Nonce, Vec<u8>) {
        let counter_bytes = counter.to_be_bytes();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&counter_bytes);
        let mut aad = Vec::with_capacity(FRAME_AAD_LABEL.len() + 1 + 8);
        aad.extend_from_slice(FRAME_AAD_LABEL);
        aad.push(kind);
        aad.extend_from_slice(&counter_bytes);
        (*Nonce::from_slice(&nonce), aad)
    }

    /// Encrypt one frame payload; the result goes in the frame verbatim.
    pub fn encrypt(&mut self, kind: u8, payload: &[u8]) -> Vec<u8> {
        let counter = self.tx_counter;
        self.tx_counter += 1;
        let (nonce, aad) = self.nonce_and_aad(kind, counter);
        let ct = self
            .cipher
            .encrypt(&nonce, Payload { msg: payload, aad: &aad })
            .expect("ChaCha20-Poly1305 encryption cannot fail for in-range sizes");
        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypt one frame payload produced by the peer's [`SessionCipher::encrypt`].
    pub fn decrypt(&mut self, kind: u8, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 8 + 16 {
            bail!("encrypted payload too short: {} bytes", wire.len());
        }
        let counter = u64::from_be_bytes(wire[..8].try_into().expect("8 bytes"));
        if counter != self.rx_expected {
            bail!(
                "frame counter out of order: got {counter}, want {} (replay or loss?)",
                self.rx_expected
            );
        }
        self.rx_expected += 1;
        let (nonce, aad) = self.nonce_and_aad(kind, counter);
        self.cipher
            .decrypt(&nonce, Payload { msg: &wire[8..], aad: &aad })
            .map_err(|_| anyhow!("frame decryption/authentication failed (wrong key or tampered data)"))
    }
}

/// All key material for one side of an established session.
pub struct SessionKeys {
    pub send: SessionCipher,
    pub recv: SessionCipher,
    pub my_confirm: [u8; 32],
    pub peer_confirm: [u8; 32],
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Derive the session keys shared by viewer and host. Deterministic given
/// the handshake transcript and password; see the module docs.
#[allow(clippy::too_many_arguments)]
pub fn derive_session(
    my_secret: &StaticSecret,
    peer_public: &PublicKey,
    client_public: [u8; 32],
    host_public: [u8; 32],
    client_nonce: [u8; 16],
    host_nonce: [u8; 16],
    host_id: &str,
    password: &str,
    i_am_viewer: bool,
) -> Result<SessionKeys> {
    let mut transcript_input = Vec::with_capacity(TRANSCRIPT_LABEL.len() + 96 + host_id.len());
    transcript_input.extend_from_slice(TRANSCRIPT_LABEL);
    transcript_input.extend_from_slice(&client_public);
    transcript_input.extend_from_slice(&host_public);
    transcript_input.extend_from_slice(&client_nonce);
    transcript_input.extend_from_slice(&host_nonce);
    transcript_input.extend_from_slice(host_id.as_bytes());
    let transcript = sha256(&transcript_input);

    let shared = my_secret.diffie_hellman(peer_public);
    if shared.as_bytes() == &[0u8; 32] {
        bail!("all-zero X25519 shared secret (small-order peer key)");
    }
    let password_key = sha256(password.as_bytes());
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(shared.as_bytes());
    ikm.extend_from_slice(&password_key);

    let hk = Hkdf::<Sha256>::new(Some(&transcript), &ikm);
    let expand = |label: &[u8], out: &mut [u8]| {
        hk.expand(label, out)
            .expect("HKDF-Expand length is always in range here");
    };
    let (mut confirm_host, mut confirm_viewer) = ([0u8; 32], [0u8; 32]);
    expand(b"kbdesk v2 host confirm", &mut confirm_host);
    expand(b"kbdesk v2 viewer confirm", &mut confirm_viewer);
    let direction = |key_label: &[u8], nonce_label: &[u8]| {
        let (mut key, mut prefix) = ([0u8; 32], [0u8; 4]);
        expand(key_label, &mut key);
        expand(nonce_label, &mut prefix);
        SessionCipher::new(key, prefix)
    };
    let v2h = direction(
        b"kbdesk v2 viewer-to-host key",
        b"kbdesk v2 viewer-to-host nonce",
    );
    let h2v = direction(
        b"kbdesk v2 host-to-viewer key",
        b"kbdesk v2 host-to-viewer nonce",
    );
    Ok(if i_am_viewer {
        SessionKeys { send: v2h, recv: h2v, my_confirm: confirm_viewer, peer_confirm: confirm_host }
    } else {
        SessionKeys { send: h2v, recv: v2h, my_confirm: confirm_host, peer_confirm: confirm_viewer }
    })
}

// ---- handshake (shared by Rust host/client; mirrored in crypto.js) ----

async fn write_control<W: AsyncWrite + Unpin>(writer: &mut W, control: &Control) -> Result<()> {
    write_packet(writer, KIND_CONTROL, &control.encode()).await
}

async fn read_control<R: AsyncRead + Unpin>(reader: &mut R, timeout: Option<Duration>) -> Result<Control> {
    let packet = match timeout {
        Some(limit) => tokio::time::timeout(limit, read_packet(reader))
            .await
            .context("timed out during handshake")??,
        None => read_packet(reader).await?,
    };
    if packet.kind != KIND_CONTROL {
        bail!("expected a control frame during handshake, got kind {}", packet.kind);
    }
    Control::decode(&packet.payload)
}

fn check_version(version: u16) -> Result<()> {
    if version != PROTOCOL_VERSION {
        bail!(
            "peer speaks protocol v{version}, we require v{PROTOCOL_VERSION} \
             (mandatory encryption) — upgrade the other side"
        );
    }
    Ok(())
}

/// Viewer side of the v2 handshake. On success returns the host's id and the
/// session keys; every subsequent frame must use the secure packet helpers.
/// The password is never sent — it only feeds the key derivation here.
pub async fn viewer_handshake<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    password: &str,
) -> Result<(String, SessionKeys)> {
    write_control(writer, &Control::Hello {
        version: PROTOCOL_VERSION,
        role: Role::Viewer,
        id: String::new(),
    }).await?;

    let host_id = match read_control(reader, Some(HANDSHAKE_STEP_TIMEOUT)).await? {
        Control::Hello { version, role: Role::Host, id } => {
            check_version(version)?;
            id
        }
        Control::Error(e) => bail!("peer refused: {e}"),
        other => bail!("unexpected reply to Hello: {other:?}"),
    };

    let keypair = KeyPair::generate()?;
    let client_nonce = random_bytes::<16>()?;
    write_control(writer, &Control::KeyExchangeInit {
        pubkey: hex_encode(&keypair.public_bytes()),
        nonce: hex_encode(&client_nonce),
    }).await?;

    let (host_public, host_nonce, confirm_from_host) =
        match read_control(reader, Some(HANDSHAKE_STEP_TIMEOUT)).await? {
            Control::KeyExchangeReply { pubkey, nonce, confirm } => (
                hex32(&pubkey, "host pubkey")?,
                hex16(&nonce, "host nonce")?,
                hex32(&confirm, "host confirm")?,
            ),
            Control::Error(e) => bail!("peer refused key exchange: {e}"),
            other => bail!("unexpected reply to key exchange: {other:?}"),
        };

    let mut session = derive_session(
        &keypair.secret,
        &PublicKey::from(host_public),
        keypair.public_bytes(),
        host_public,
        client_nonce,
        host_nonce,
        &host_id,
        password,
        true,
    )?;
    if !ct_eq(&confirm_from_host, &session.peer_confirm) {
        bail!("host authentication failed: wrong password, or a man-in-the-middle is impersonating the host");
    }

    write_control(writer, &Control::KeyExchangeFinish {
        confirm: hex_encode(&session.my_confirm),
    }).await?;

    // First encrypted frame: the host's AuthResult.
    let packet = tokio::time::timeout(HANDSHAKE_STEP_TIMEOUT, read_packet(reader))
        .await
        .context("timed out waiting for auth result")??;
    let auth_payload = match session.recv.decrypt(packet.kind, &packet.payload) {
        Ok(payload) => payload,
        Err(e) => {
            // A host that rejected our confirmation sends a plaintext Error.
            if let Ok(Control::Error(message)) = Control::decode(&packet.payload) {
                bail!("host rejected the session: {message}");
            }
            return Err(e);
        }
    };
    match Control::decode(&auth_payload)? {
        Control::AuthResult { ok: true, .. } => Ok((host_id, session)),
        Control::AuthResult { ok: false, reason } => bail!("authentication failed: {reason}"),
        other => bail!("unexpected auth reply: {other:?}"),
    }
}

/// Host side of the v2 handshake. The first read has **no timeout**: in
/// relay mode it is what parks the host until a viewer is paired with it.
pub async fn host_handshake<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    host_id: &str,
    password: &str,
) -> Result<SessionKeys> {
    match read_control(reader, None).await? {
        Control::Hello { version, role: Role::Viewer, .. } => check_version(version)?,
        other => bail!("unexpected first message from viewer: {other:?}"),
    }
    write_control(writer, &Control::Hello {
        version: PROTOCOL_VERSION,
        role: Role::Host,
        id: host_id.to_string(),
    }).await?;

    let (client_public, client_nonce) =
        match read_control(reader, Some(HANDSHAKE_STEP_TIMEOUT)).await? {
            Control::KeyExchangeInit { pubkey, nonce } => (
                hex32(&pubkey, "viewer pubkey")?,
                hex16(&nonce, "viewer nonce")?,
            ),
            other => bail!("expected key exchange, got {other:?} (plaintext/v1 clients are not accepted)"),
        };

    let keypair = KeyPair::generate()?;
    let host_nonce = random_bytes::<16>()?;
    let mut session = derive_session(
        &keypair.secret,
        &PublicKey::from(client_public),
        client_public,
        keypair.public_bytes(),
        client_nonce,
        host_nonce,
        host_id,
        password,
        false,
    )?;
    write_control(writer, &Control::KeyExchangeReply {
        pubkey: hex_encode(&keypair.public_bytes()),
        nonce: hex_encode(&host_nonce),
        confirm: hex_encode(&session.my_confirm),
    }).await?;

    let confirm_from_viewer = match read_control(reader, Some(HANDSHAKE_STEP_TIMEOUT)).await? {
        Control::KeyExchangeFinish { confirm } => hex32(&confirm, "viewer confirm")?,
        other => bail!("expected key-exchange finish, got {other:?}"),
    };
    if !ct_eq(&confirm_from_viewer, &session.peer_confirm) {
        let _ = write_control(writer, &Control::Error("authentication failed".into())).await;
        bail!("viewer authentication failed (wrong password or tampered handshake)");
    }

    // First encrypted frame: AuthResult(ok).
    let auth = Control::AuthResult { ok: true, reason: "ok".into() };
    let wire = session.send.encrypt(KIND_CONTROL, &auth.encode());
    write_packet(writer, KIND_CONTROL, &wire).await?;
    Ok(session)
}

/// Convenience so callers decrypting raw relay-tap bytes in tests can prove
/// a captured frame is not plaintext JSON.
pub fn looks_like_plaintext_control(packet: &Packet) -> bool {
    Control::decode(&packet.payload).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{read_secure_packet, write_secure_packet, KIND_VIDEO};

    fn unhex(s: &str) -> Vec<u8> {
        hex_decode(s).unwrap()
    }

    /// The reference vector generated by tests/e2e/kb_crypto.py and asserted
    /// identically by tests/js/crypto.test.cjs.
    #[test]
    fn session_vector_matches_reference() {
        let viewer_secret: [u8; 32] =
            unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").try_into().unwrap();
        let host_secret: [u8; 32] =
            unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d").try_into().unwrap();
        let viewer_kp = KeyPair::from_secret_bytes(viewer_secret);
        let host_kp = KeyPair::from_secret_bytes(host_secret);
        assert_eq!(hex_encode(&viewer_kp.public_bytes()),
                   "1c9fd88f45606d932a80c71824ae151d15d73e77de38e8e000852e614fae7019");
        assert_eq!(hex_encode(&host_kp.public_bytes()),
                   "ff63fe57bfbf43fa3f563628b149af704d3db625369c49983650347a6a71e00e");

        let client_nonce: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let host_nonce: [u8; 16] = unhex("101112131415161718191a1b1c1d1e1f").try_into().unwrap();
        let mut viewer = derive_session(
            &viewer_kp.secret, &host_kp.public, viewer_kp.public_bytes(), host_kp.public_bytes(),
            client_nonce, host_nonce, "544228382", "correct horse battery staple", true,
        ).unwrap();
        let mut host = derive_session(
            &host_kp.secret, &viewer_kp.public, viewer_kp.public_bytes(), host_kp.public_bytes(),
            client_nonce, host_nonce, "544228382", "correct horse battery staple", false,
        ).unwrap();
        assert_eq!(hex_encode(&viewer.my_confirm),
                   "ad8940072fe15eba71f387830fdc88107dc2ac732a0447ef040b2792f7b8b46b");
        assert_eq!(hex_encode(&viewer.peer_confirm),
                   "c986bae686b94483414ecb3953e1b34a127b40e4c4573140aba8e681697e33f0");

        let pt1 = br#"{"StartStream":{"monitor":0,"quality":70,"fps":15}}"#;
        let wire1 = viewer.send.encrypt(KIND_CONTROL, pt1);
        assert_eq!(hex_encode(&wire1),
            "0000000000000000e314b7b98a172751bf83ec6ddc6e90b703e5629dddbc17fe8c994c496821a5dd1c56bebef2d86646d3e2d4543eab15c01303f8486fd655ee6158eabdac9f2c68c33ab1");
        assert_eq!(host.recv.decrypt(KIND_CONTROL, &wire1).unwrap(), pt1);

        let pt2 = unhex("0780043800ffd866616b656a706567ffd9");
        let wire2 = host.send.encrypt(KIND_VIDEO, &pt2);
        assert_eq!(hex_encode(&wire2),
            "00000000000000004f468e3b56610c7b004e0fd618300159b634956b80c7b070493a7e2a0969c7eb69");
        assert_eq!(viewer.recv.decrypt(KIND_VIDEO, &wire2).unwrap(), pt2);

        // Tampering and replay are rejected.
        let mut tampered = wire1.clone();
        tampered[10] ^= 1;
        // (fresh session needed: host's counter already advanced past #0)
        let mut host2 = derive_session(
            &host_kp.secret, &viewer_kp.public, viewer_kp.public_bytes(), host_kp.public_bytes(),
            client_nonce, host_nonce, "544228382", "correct horse battery staple", false,
        ).unwrap();
        assert!(host2.recv.decrypt(KIND_CONTROL, &tampered).is_err());
        let mut host3 = derive_session(
            &host_kp.secret, &viewer_kp.public, viewer_kp.public_bytes(), host_kp.public_bytes(),
            client_nonce, host_nonce, "544228382", "correct horse battery staple", false,
        ).unwrap();
        assert!(host3.recv.decrypt(KIND_CONTROL, &wire1).is_ok());
        assert!(host3.recv.decrypt(KIND_CONTROL, &wire1).is_err(), "replay must fail");

        // Wrong password -> different confirmations.
        let wrong = derive_session(
            &viewer_kp.secret, &host_kp.public, viewer_kp.public_bytes(), host_kp.public_bytes(),
            client_nonce, host_nonce, "544228382", "wrong", true,
        ).unwrap();
        assert!(!ct_eq(&wrong.peer_confirm, &host.my_confirm));
    }

    #[tokio::test]
    async fn handshake_over_duplex_then_secure_frames() {
        let (viewer_stream, host_stream) = tokio::io::duplex(64 * 1024);
        let host = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(host_stream);
            let mut session = host_handshake(&mut reader, &mut writer, "544228382", "s3cret").await?;
            // Receive one encrypted input frame, send one encrypted video frame.
            let packet = read_secure_packet(&mut reader, &mut session.recv).await?;
            assert_eq!(packet.kind, KIND_CONTROL);
            match Control::decode(&packet.payload)? {
                Control::StartStream { quality, .. } => assert_eq!(quality, 70),
                other => bail!("unexpected: {other:?}"),
            }
            write_secure_packet(&mut writer, &mut session.send, KIND_VIDEO, b"\x00\x01\x00\x01\x00jpeg").await?;
            Ok::<(), anyhow::Error>(())
        });

        let (mut reader, mut writer) = tokio::io::split(viewer_stream);
        let (host_id, mut session) =
            viewer_handshake(&mut reader, &mut writer, "s3cret").await.unwrap();
        assert_eq!(host_id, "544228382");
        let start = Control::StartStream { monitor: 0, quality: 70, fps: 15 };
        write_secure_packet(&mut writer, &mut session.send, KIND_CONTROL, &start.encode()).await.unwrap();
        let video = read_secure_packet(&mut reader, &mut session.recv).await.unwrap();
        assert_eq!(video.kind, KIND_VIDEO);
        assert_eq!(video.payload, b"\x00\x01\x00\x01\x00jpeg");
        host.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_password() {
        let (viewer_stream, host_stream) = tokio::io::duplex(64 * 1024);
        let host = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(host_stream);
            host_handshake(&mut reader, &mut writer, "544228382", "right").await
        });
        let (mut reader, mut writer) = tokio::io::split(viewer_stream);
        let err = viewer_handshake(&mut reader, &mut writer, "wrong")
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(format!("{err:#}").contains("wrong password"), "got: {err:#}");
        // Host side must not have established a session either.
        assert!(host.await.unwrap().is_err());
    }
}
