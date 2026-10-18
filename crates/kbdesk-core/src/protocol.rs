//! Control messages and video-frame encoding.
//!
//! Control messages travel as JSON so the protocol is easy to inspect and
//! extend. Video frames travel as a small binary header (width, height,
//! monitor index) followed by a JPEG payload produced by the host.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Wire-protocol version. Bump on breaking changes.
/// v2 = mandatory end-to-end session encryption (see `crate::crypto`):
/// peers must complete the X25519 key exchange and encrypt every session
/// frame. v1 peers are rejected outright — upgrade all components together.
pub const PROTOCOL_VERSION: u16 = 2;

/// Which side of a session a peer claims to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// The machine being controlled (shares its screen, accepts input).
    Host,
    /// The machine controlling (views the screen, sends input).
    Viewer,
}

/// Every control message exchanged between peers (and, for setup, the relay).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Control {
    /// First message a peer sends after connecting.
    Hello {
        version: u16,
        role: Role,
        /// Host identity. Empty when a host wants the relay to assign one.
        id: String,
    },
    /// Relay → host: the identity the relay assigned.
    AssignedId(String),
    /// Viewer → relay: ask to be connected to a given host identity.
    Connect { target: String },
    /// Viewer → host: start the v2 key exchange (hex-encoded fields).
    /// Sent after `Hello`; establishes the encrypted session (see
    /// `crate::crypto`). Carries only public material.
    KeyExchangeInit { pubkey: String, nonce: String },
    /// Host → viewer: key-exchange reply with the host's key-confirmation
    /// value, proving knowledge of the session password + shared secret.
    KeyExchangeReply { pubkey: String, nonce: String, confirm: String },
    /// Viewer → host: the viewer's key-confirmation value. After this point
    /// every frame in both directions is AEAD-encrypted.
    KeyExchangeFinish { confirm: String },
    /// Viewer → host: authentication attempt. **Protocol v1 only** — v2
    /// authenticates inside the key exchange and never sends a password.
    /// Kept so old payloads still decode to a clear version error.
    Auth { password: String },
    /// Host → viewer: authentication result. In v2 this is the first
    /// *encrypted* frame of the session.
    AuthResult { ok: bool, reason: String },
    /// Viewer → host: begin sending screen frames.
    StartStream {
        monitor: u32,
        quality: u8,
        fps: u8,
    },
    /// Viewer → host: stop sending screen frames.
    StopStream,
    /// Convenience wrapper for a single input event.
    Input(InputEvent),
    /// Liveness probe.
    Ping(u64),
    /// Reply to [`Control::Ping`], echoing the value.
    Pong(u64),
    /// A fatal or informational error.
    Error(String),
}

impl Control {
    /// Serialize to JSON bytes (payload of a [`crate::KIND_CONTROL`] frame).
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Control is always serializable")
    }

    /// Parse JSON bytes produced by [`Control::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// A single remote input event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputEvent {
    /// Absolute pointer position in host screen coordinates.
    MouseMove { x: i32, y: i32 },
    /// Mouse button press/release.
    MouseButton { button: MouseButton, down: bool },
    /// Scroll wheel delta.
    MouseScroll { dx: i32, dy: i32 },
    /// Keyboard press/release.
    Key { key: KeySpec, down: bool },
    /// Type a whole string into the host (clipboard-paste style input).
    /// Injected as text by the host, so layout and casing are preserved.
    Text(String),
    /// Release every key and mouse button the host is currently holding.
    /// Viewers send this on focus loss / disconnect so the controlled machine
    /// never ends up with stuck modifiers or a stuck mouse button.
    ReleaseAll,
}

/// Mouse buttons we model. Kept small and portable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    Back,
    Forward,
}

/// A keyboard key, either a printable character or a named non-printing key
/// (for example `"Enter"`, `"Shift"`, `"F5"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeySpec {
    /// A character produced by the layout (e.g. `'a'`, `'é'`).
    Char(char),
    /// A named key; the host maps the name to its platform key code.
    Named(String),
}

/// A decoded screen frame.
#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub width: u16,
    pub height: u16,
    /// Zero-based monitor index the frame came from.
    pub monitor: u8,
    pub jpeg: Vec<u8>,
}

/// Encode a [`VideoFrame`] into the payload of a [`crate::KIND_VIDEO`] frame.
pub fn encode_video(frame: &VideoFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + frame.jpeg.len());
    out.extend_from_slice(&frame.width.to_be_bytes());
    out.extend_from_slice(&frame.height.to_be_bytes());
    out.push(frame.monitor);
    out.extend_from_slice(&frame.jpeg);
    out
}

/// Decode the payload of a [`crate::KIND_VIDEO`] frame.
pub fn decode_video(payload: &[u8]) -> Result<VideoFrame> {
    if payload.len() < 5 {
        bail!("video payload too short: {} bytes", payload.len());
    }
    let width = u16::from_be_bytes([payload[0], payload[1]]);
    let height = u16::from_be_bytes([payload[2], payload[3]]);
    let monitor = payload[4];
    Ok(VideoFrame {
        width,
        height,
        monitor,
        jpeg: payload[5..].to_vec(),
    })
}

/// Normalise a host identity as typed by a human: strip whitespace and
/// dashes, so `"544 228 382"` and `"544-228-382"` both match `"544228382"`.
/// Used by the relay and the web bridge so every side agrees.
pub fn normalize_id(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

/// Generate a 9-digit numeric identity, in the style remote-desktop users
/// expect to read aloud. Entropy comes from the system clock; collisions are
/// resolved by the relay (which overwrites stale entries).
pub fn generate_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix the low 30 bits of time with a counter, fold to 9 digits.
    let mixed = (nanos ^ (n.wrapping_mul(0x9E37_79B9_7F4A_7C15))) % 1_000_000_000;
    format!("{mixed:09}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_roundtrips_through_json() {
        let message = Control::StartStream {
            monitor: 1,
            quality: 55,
            fps: 20,
        };
        let decoded = Control::decode(&message.encode()).unwrap();
        match decoded {
            Control::StartStream {
                monitor,
                quality,
                fps,
            } => {
                assert_eq!((monitor, quality, fps), (1, 55, 20));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn video_roundtrips() {
        let frame = VideoFrame {
            width: 1920,
            height: 1080,
            monitor: 2,
            jpeg: vec![0xff, 0xd8, 0xff, 0xd9],
        };
        let decoded = decode_video(&encode_video(&frame)).unwrap();
        assert_eq!(decoded.width, 1920);
        assert_eq!(decoded.height, 1080);
        assert_eq!(decoded.monitor, 2);
        assert_eq!(decoded.jpeg, vec![0xff, 0xd8, 0xff, 0xd9]);
    }

    #[test]
    fn text_and_release_all_roundtrip() {
        let text = Control::Input(InputEvent::Text("päss word".into()));
        match Control::decode(&text.encode()).unwrap() {
            Control::Input(InputEvent::Text(s)) => assert_eq!(s, "päss word"),
            other => panic!("unexpected: {other:?}"),
        }
        let release = Control::Input(InputEvent::ReleaseAll);
        assert!(matches!(
            Control::decode(&release.encode()).unwrap(),
            Control::Input(InputEvent::ReleaseAll)
        ));
    }

    #[test]
    fn ids_normalise_spaces_and_dashes() {
        assert_eq!(normalize_id("544 228 382"), "544228382");
        assert_eq!(normalize_id(" 544-228-382 "), "544228382");
        assert_eq!(normalize_id("544228382"), "544228382");
        assert_eq!(normalize_id(""), "");
    }

    #[test]
    fn generated_ids_are_nine_digits() {
        for _ in 0..50 {
            let id = generate_id();
            assert_eq!(id.len(), 9);
            assert!(id.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
