//! KB-Desk core: the shared wire protocol.
//!
//! # Framing (original design)
//!
//! Every message on the wire is a single *frame*:
//!
//! ```text
//! ┌────────────┬──────┬───────────────────────────┐
//! │ u32 length │ kind │ payload (length-1 bytes)   │
//! │ big-endian │ u8   │                            │
//! └────────────┴──────┴───────────────────────────┘
//! ```
//!
//! * `length` counts the `kind` byte plus the payload.
//! * `kind` selects the payload interpretation:
//!   * [`KIND_CONTROL`] — UTF-8 JSON of [`Control`].
//!   * [`KIND_VIDEO`] — compact binary screen frame (see [`VideoFrame`]).
//!
//! The design is intentionally minimal and is our own; it does not copy the
//! framing of any other project.

pub mod frame;
pub mod protocol;

pub use frame::{read_packet, write_packet, Packet, KIND_CONTROL, KIND_VIDEO, MAX_MESSAGE};
pub use protocol::{
    decode_video, encode_video, generate_id, Control, InputEvent, KeySpec, MouseButton, Role,
    VideoFrame, PROTOCOL_VERSION,
};

/// Default TCP port used by the relay, host listeners, and clients.
pub const DEFAULT_PORT: u16 = 21118;
