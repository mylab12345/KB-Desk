//! Screen capture.
//!
//! Two backends, selected at compile time:
//!
//! * **Linux / X11** — pure-Rust protocol client via `x11rb` (no C build deps).
//!   Works on X11 desktops and on Wayland sessions that expose XWayland.
//! * **Windows and macOS** — the `xcap` crate, which wraps GDI / CoreGraphics.
//!
//! Any other target falls back to a stub that reports a clear error instead of
//! failing to compile.

#[cfg(target_os = "linux")]
pub use linux::Capture;

/// X11 capture backend (pure-Rust protocol client via `x11rb`, no C build deps).
#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{bail, Context, Result};
    use image::{codecs::jpeg::JpegEncoder, ExtendedColorType};
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{ConnectionExt, ImageFormat, Window};
    use x11rb::rust_connection::RustConnection;

    /// A connection to the X server plus the root window geometry.
    pub struct Capture {
        conn: RustConnection,
        root: Window,
        width: u16,
        height: u16,
    }

    impl Capture {
        /// Connect to the display named by `$DISPLAY` (or the default).
        pub fn new() -> Result<Self> {
            let (conn, screen_num) = x11rb::connect(None).context(
                "opening the X11 display (Wayland sessions typically need an XWayland display)",
            )?;
            // `Window` is a plain integer alias, so copy it out and release the
            // borrow before moving `conn` into the struct.
            let root = conn.setup().roots[screen_num].root;
            let geometry = conn.get_geometry(root)?.reply()?;
            Ok(Self {
                conn,
                root,
                width: geometry.width,
                height: geometry.height,
            })
        }

        /// Screen size in pixels.
        pub fn dimensions(&self) -> (u16, u16) {
            (self.width, self.height)
        }

        /// Grab the whole screen and encode it as JPEG.
        pub fn capture_jpeg(&self, quality: u8) -> Result<(u16, u16, Vec<u8>)> {
            let image = self
                .conn
                .get_image(
                    ImageFormat::Z_PIXMAP,
                    self.root,
                    0,
                    0,
                    self.width,
                    self.height,
                    u32::MAX,
                )?
                .reply()?;

            // ZPixmap at depth 24/30/32 is 4 bytes per pixel, stored as BGRX
            // on little-endian X servers. Depth 16 is uncommon; reject it
            // rather than emit garbage.
            let bytes_per_pixel = match image.depth {
                24 | 30 | 32 => 4usize,
                other => bail!("unsupported X11 pixel depth {other}"),
            };

            let (w, h) = (self.width as usize, self.height as usize);
            let mut rgb = Vec::with_capacity(w * h * 3);
            for chunk in image.data.chunks_exact(bytes_per_pixel) {
                // B, G, R, [X]
                rgb.push(chunk[2]);
                rgb.push(chunk[1]);
                rgb.push(chunk[0]);
            }
            // Guard against a short read leaving the buffer undersized.
            rgb.resize(w * h * 3, 0);

            let mut jpeg = Vec::new();
            let mut encoder = JpegEncoder::new_with_quality(&mut jpeg, quality.clamp(1, 100));
            encoder
                .encode(&rgb, self.width as u32, self.height as u32, ExtendedColorType::Rgb8)
                .context("encoding JPEG")?;
            Ok((self.width, self.height, jpeg))
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use desktop::Capture;

/// Windows / macOS capture backend built on `xcap`.
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod desktop {
    use anyhow::{bail, Context, Result};
    use image::{codecs::jpeg::JpegEncoder, ExtendedColorType};
    use xcap::Monitor;

    /// One monitor, captured through the OS compositor.
    pub struct Capture {
        monitor: Monitor,
        width: u16,
        height: u16,
    }

    impl Capture {
        /// Pick the primary monitor, or the first one if none is marked primary.
        pub fn new() -> Result<Self> {
            let mut monitors =
                Monitor::all().context("enumerating monitors (check screen-recording permission)")?;
            if monitors.is_empty() {
                bail!("no monitors reported by the operating system");
            }
            let idx = monitors
                .iter()
                .position(|m| m.is_primary().unwrap_or(false))
                .unwrap_or(0);
            let monitor = monitors.swap_remove(idx);

            let width = clamp_dim(monitor.width().context("reading monitor width")?);
            let height = clamp_dim(monitor.height().context("reading monitor height")?);
            if width == 0 || height == 0 {
                bail!("monitor reports a {width}x{height} size");
            }
            Ok(Self {
                monitor,
                width,
                height,
            })
        }

        /// Screen size in pixels.
        pub fn dimensions(&self) -> (u16, u16) {
            (self.width, self.height)
        }

        /// Grab the whole screen and encode it as JPEG.
        pub fn capture_jpeg(&self, quality: u8) -> Result<(u16, u16, Vec<u8>)> {
            let image = self.monitor.capture_image().context(
                "capturing the screen (on macOS grant Screen Recording to this app; \
                 on Wayland use an X11/XWayland session)",
            )?;
            let (w, h) = (image.width(), image.height());
            if w == 0 || h == 0 {
                bail!("captured a zero-sized frame");
            }
            let mut jpeg = Vec::new();
            let mut encoder = JpegEncoder::new_with_quality(&mut jpeg, quality.clamp(1, 100));
            encoder
                .encode(image.as_raw(), w, h, ExtendedColorType::Rgba8)
                .context("encoding JPEG")?;
            Ok((clamp_dim(w), clamp_dim(h), jpeg))
        }
    }

    /// The wire protocol stores dimensions as `u16`.
    fn clamp_dim(v: u32) -> u16 {
        v.min(u16::MAX as u32) as u16
    }
}

/// Placeholder backend for platforms without an implementation yet.
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub use other::Capture;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
mod other {
    use anyhow::{bail, Result};

    pub struct Capture;

    impl Capture {
        pub fn new() -> Result<Self> {
            bail!(
                "KB-Desk capture is implemented for Linux/X11, Windows and macOS; \
                 add a backend for this platform in crates/kbdesk-host/src/capture.rs"
            )
        }

        pub fn dimensions(&self) -> (u16, u16) {
            (0, 0)
        }

        pub fn capture_jpeg(&self, _quality: u8) -> Result<(u16, u16, Vec<u8>)> {
            bail!("capture backend not available on this platform")
        }
    }
}
