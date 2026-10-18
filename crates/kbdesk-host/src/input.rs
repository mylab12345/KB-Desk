//! Remote input injection.
//!
//! `enigo` provides the platform-specific pointer/keyboard backend (X11,
//! Wayland, Windows, macOS). Injection runs on a dedicated OS thread because
//! the backend handle is not safe to share across the async runtime, and input
//! events arrive over a standard channel.

use anyhow::Result;
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
use kbdesk_core::{InputEvent, KeySpec, MouseButton};
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
            while let Ok(event) = rx.recv() {
                if let Err(e) = apply(&mut enigo, event) {
                    warn!("input injection error: {e}");
                }
            }
            info!("input injector stopped");
        });
    if let Err(e) = spawn_result {
        warn!("could not start input thread: {e}");
    }
    InputHandle { tx }
}

fn apply(enigo: &mut Enigo, event: InputEvent) -> Result<()> {
    match event {
        InputEvent::MouseMove { x, y } => enigo.move_mouse(x, y, Coordinate::Abs)?,
        InputEvent::MouseButton { button, down } => {
            let button = match button {
                MouseButton::Left => Button::Left,
                MouseButton::Middle => Button::Middle,
                MouseButton::Right => Button::Right,
                MouseButton::Back => Button::Back,
                MouseButton::Forward => Button::Forward,
            };
            let direction = if down {
                Direction::Press
            } else {
                Direction::Release
            };
            enigo.button(button, direction)?;
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
            let direction = if down {
                Direction::Press
            } else {
                Direction::Release
            };
            enigo.key(to_key(&key), direction)?;
        }
    }
    Ok(())
}

/// Map a protocol [`KeySpec`] to an `enigo` key.
///
/// Only keys that exist on every supported platform are named here; anything
/// else falls back to a Unicode character so typing still works.
fn to_key(spec: &KeySpec) -> Key {
    match spec {
        KeySpec::Char(c) => Key::Unicode(*c),
        KeySpec::Named(name) => match name.as_str() {
            "Enter" | "Return" => Key::Return,
            "Tab" => Key::Tab,
            "Escape" => Key::Escape,
            "Backspace" => Key::Backspace,
            "Space" => Key::Space,
            "Delete" => Key::Delete,
            "Home" => Key::Home,
            "End" => Key::End,
            "PageUp" => Key::PageUp,
            "PageDown" => Key::PageDown,
            "ArrowUp" => Key::UpArrow,
            "ArrowDown" => Key::DownArrow,
            "ArrowLeft" => Key::LeftArrow,
            "ArrowRight" => Key::RightArrow,
            "Shift" => Key::Shift,
            "ShiftLeft" => Key::LShift,
            "ShiftRight" => Key::RShift,
            "Control" => Key::Control,
            "ControlLeft" => Key::LControl,
            "ControlRight" => Key::RControl,
            "Alt" => Key::Alt,
            "Meta" | "Super" => Key::Meta,
            "CapsLock" => Key::CapsLock,
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
