//! Remote input injection.
//!
//! `enigo` provides the platform-specific pointer/keyboard backend (X11,
//! Wayland, Windows, macOS). Injection runs on a dedicated OS thread because
//! the backend handle is not safe to share across the async runtime, and input
//! events arrive over a standard channel.
//!
//! The injector tracks every key and mouse button it is holding down, so a
//! [`InputEvent::ReleaseAll`] (sent by viewers on focus loss/disconnect), or
//! simply the end of the session, can put the controlled machine back into a
//! clean state instead of leaving a modifier or button stuck forever.

use anyhow::Result;
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
use kbdesk_core::{InputEvent, KeySpec, MouseButton};
use std::collections::HashSet;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use tracing::{info, warn};

/// Cheap, cloneable handle used by the network loop to feed input.
pub struct InputHandle {
    tx: Sender<InputEvent>,
}

impl InputHandle {
    /// Queue an event. Silently ignored if the injector thread has stopped.
    pub fn send(&self, event: InputEvent) {
        let _ = self.tx.send(event);
    }
}

/// Spawn the injector thread. If the thread cannot start, the returned handle
/// simply discards events; viewing still works, only control is disabled.
pub fn spawn() -> InputHandle {
    let (tx, rx) = channel::<InputEvent>();
    let spawn_result = thread::Builder::new()
        .name("kbdesk-input".into())
        .spawn(move || {
            let mut enigo = match Enigo::new(&Settings::default()) {
                Ok(enigo) => enigo,
                Err(e) => {
                    warn!("input injection unavailable: {e}");
                    return;
                }
            };
            info!("input injector ready");
            let mut held = Held::default();
            while let Ok(event) = rx.recv() {
                if let Err(e) = apply(&mut enigo, &mut held, event) {
                    warn!("input injection error: {e}");
                }
            }
            // Session ended (all senders dropped): never leave keys stuck.
            held.release_all(&mut enigo);
            info!("input injector stopped");
        });
    if let Err(e) = spawn_result {
        warn!("could not start input thread: {e}");
    }
    InputHandle { tx }
}

/// Keys/buttons this injector is currently holding down on the host.
#[derive(Default)]
struct Held {
    keys: HashSet<Key>,
    /// The keys in press order, so they can be released in reverse.
    key_list: Vec<Key>,
    buttons: HashSet<MouseButton>,
}

impl Held {
    fn press_key(&mut self, key: Key) {
        if self.keys.insert(key) {
            self.key_list.push(key);
        }
    }

    fn release_key(&mut self, key: &Key) {
        if self.keys.remove(key) {
            self.key_list.retain(|k| k != key);
        }
    }

    /// Release everything (buttons first, keys in reverse press order).
    fn release_all(&mut self, enigo: &mut Enigo) {
        if self.key_list.is_empty() && self.buttons.is_empty() {
            return;
        }
        for button in self.buttons.drain() {
            let _ = enigo.button(to_button(button), Direction::Release);
        }
        for key in self.key_list.drain(..).rev() {
            let _ = enigo.key(key, Direction::Release);
        }
        self.keys.clear();
        tracing::debug!("released all held input");
    }
}

fn to_button(button: MouseButton) -> Button {
    match button {
        MouseButton::Left => Button::Left,
        MouseButton::Middle => Button::Middle,
        MouseButton::Right => Button::Right,
        MouseButton::Back => Button::Back,
        MouseButton::Forward => Button::Forward,
    }
}

fn apply(enigo: &mut Enigo, held: &mut Held, event: InputEvent) -> Result<()> {
    match event {
        InputEvent::MouseMove { x, y } => enigo.move_mouse(x, y, Coordinate::Abs)?,
        InputEvent::MouseButton { button, down } => {
            if down {
                held.buttons.insert(button);
            } else {
                held.buttons.remove(&button);
            }
            let direction = if down {
                Direction::Press
            } else {
                Direction::Release
            };
            enigo.button(to_button(button), direction)?;
        }
        InputEvent::MouseScroll { dx, dy } => {
            if dy != 0 {
                enigo.scroll(dy, Axis::Vertical)?;
            }
            if dx != 0 {
                enigo.scroll(dx, Axis::Horizontal)?;
            }
        }
        InputEvent::Key { key, down } => {
            let key = to_key(&key);
            if down {
                held.press_key(key);
                enigo.key(key, Direction::Press)?;
            } else {
                held.release_key(&key);
                enigo.key(key, Direction::Release)?;
            }
        }
        InputEvent::Text(text) => {
            // Type the string as-is (used by "paste text" in the web viewer).
            if !text.is_empty() {
                enigo.text(&text)?;
            }
        }
        InputEvent::ReleaseAll => held.release_all(enigo),
    }
    Ok(())
}

/// Map a protocol [`KeySpec`] to an `enigo` key.
///
/// Named keys follow the browser's `KeyboardEvent.code`/`key` vocabulary
/// (`"ArrowUp"`, `"ControlLeft"`, `"NumpadAdd"`, …) because the web viewer is
/// the richest sender; the native client's names are kept as aliases.
fn to_key(spec: &KeySpec) -> Key {
    match spec {
        KeySpec::Char(c) => Key::Unicode(*c),
        KeySpec::Named(name) => match name.as_str() {
            "Enter" | "Return" | "NumpadEnter" => Key::Return,
            "Tab" => Key::Tab,
            "Escape" | "Esc" => Key::Escape,
            "Backspace" => Key::Backspace,
            "Space" | " " => Key::Space,
            "Delete" => Key::Delete,
            // enigo only exposes some keys per-platform; cfg'd arms fall
            // through to the harmless `other => Key::Other(0)` fallback
            // on platforms without the key.
            #[cfg(not(target_os = "macos"))]
            "Insert" => Key::Insert,
            "Home" => Key::Home,
            "End" => Key::End,
            "PageUp" => Key::PageUp,
            "PageDown" => Key::PageDown,
            "ArrowUp" | "Up" => Key::UpArrow,
            "ArrowDown" | "Down" => Key::DownArrow,
            "ArrowLeft" | "Left" => Key::LeftArrow,
            "ArrowRight" | "Right" => Key::RightArrow,
            "Shift" => Key::Shift,
            "ShiftLeft" => Key::LShift,
            "ShiftRight" => Key::RShift,
            "Control" | "Ctrl" => Key::Control,
            "ControlLeft" => Key::LControl,
            "ControlRight" => Key::RControl,
            "Alt" => Key::Alt,
            #[cfg(not(target_os = "macos"))]
            "AltLeft" => Key::LMenu,
            #[cfg(target_os = "macos")]
            "AltLeft" => Key::Option,
            #[cfg(target_os = "windows")]
            "AltRight" | "AltGr" => Key::RMenu,
            #[cfg(target_os = "macos")]
            "AltRight" | "AltGr" => Key::ROption,
            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            "AltRight" | "AltGr" => Key::Alt,
            "Meta" | "Super" | "OS" | "Windows" | "Win" => Key::Meta,
            #[cfg(target_os = "windows")]
            "MetaLeft" | "SuperLeft" => Key::LWin,
            #[cfg(target_os = "macos")]
            "MetaLeft" | "SuperLeft" => Key::Command,
            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            "MetaLeft" | "SuperLeft" => Key::Meta,
            #[cfg(target_os = "windows")]
            "MetaRight" | "SuperRight" => Key::RWin,
            #[cfg(target_os = "macos")]
            "MetaRight" | "SuperRight" => Key::RCommand,
            #[cfg(not(any(target_os = "windows", target_os = "macos")))]
            "MetaRight" | "SuperRight" => Key::Meta,
            "CapsLock" => Key::CapsLock,
            #[cfg(not(target_os = "macos"))]
            "NumLock" => Key::Numlock,
            #[cfg(all(unix, not(target_os = "macos")))]
            "ScrollLock" => Key::ScrollLock,
            #[cfg(target_os = "windows")]
            "ScrollLock" => Key::Scroll,
            #[cfg(not(target_os = "macos"))]
            "PrintScreen" | "PrintScr" | "Snapshot" => Key::PrintScr,
            #[cfg(not(target_os = "macos"))]
            "Pause" => Key::Pause,
            #[cfg(target_os = "windows")]
            "ContextMenu" | "Menu" | "Apps" => Key::Apps,
            "F1" => Key::F1,
            "F2" => Key::F2,
            "F3" => Key::F3,
            "F4" => Key::F4,
            "F5" => Key::F5,
            "F6" => Key::F6,
            "F7" => Key::F7,
            "F8" => Key::F8,
            "F9" => Key::F9,
            "F10" => Key::F10,
            "F11" => Key::F11,
            "F12" => Key::F12,
            "F13" => Key::F13,
            "F14" => Key::F14,
            "F15" => Key::F15,
            "F16" => Key::F16,
            "F17" => Key::F17,
            "F18" => Key::F18,
            "F19" => Key::F19,
            "F20" => Key::F20,
            #[cfg(not(target_os = "macos"))]
            "F21" => Key::F21,
            #[cfg(not(target_os = "macos"))]
            "F22" => Key::F22,
            #[cfg(not(target_os = "macos"))]
            "F23" => Key::F23,
            #[cfg(not(target_os = "macos"))]
            "F24" => Key::F24,
            "Numpad0" => Key::Numpad0,
            "Numpad1" => Key::Numpad1,
            "Numpad2" => Key::Numpad2,
            "Numpad3" => Key::Numpad3,
            "Numpad4" => Key::Numpad4,
            "Numpad5" => Key::Numpad5,
            "Numpad6" => Key::Numpad6,
            "Numpad7" => Key::Numpad7,
            "Numpad8" => Key::Numpad8,
            "Numpad9" => Key::Numpad9,
            "NumpadAdd" => Key::Add,
            "NumpadSubtract" => Key::Subtract,
            "NumpadMultiply" => Key::Multiply,
            "NumpadDivide" => Key::Divide,
            "NumpadDecimal" => Key::Decimal,
            "AudioVolumeUp" | "VolumeUp" => Key::VolumeUp,
            "AudioVolumeDown" | "VolumeDown" => Key::VolumeDown,
            "AudioVolumeMute" | "VolumeMute" => Key::VolumeMute,
            "MediaPlayPause" => Key::MediaPlayPause,
            "MediaTrackNext" => Key::MediaNextTrack,
            "MediaTrackPrevious" => Key::MediaPrevTrack,
            #[cfg(not(target_os = "macos"))]
            "MediaStop" => Key::MediaStop,
            #[cfg(target_os = "windows")]
            "BrowserBack" => Key::BrowserBack,
            #[cfg(target_os = "windows")]
            "BrowserForward" => Key::BrowserForward,
            #[cfg(target_os = "windows")]
            "BrowserRefresh" => Key::BrowserRefresh,
            #[cfg(target_os = "windows")]
            "BrowserHome" => Key::BrowserHome,
            other => single_char(other).unwrap_or(Key::Other(0)),
        },
    }
}

fn single_char(s: &str) -> Option<Key> {
    let mut chars = s.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => Some(Key::Unicode(c)),
        _ => None,
    }
}
