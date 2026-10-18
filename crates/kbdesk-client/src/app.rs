//! The viewer GUI.

use crate::net::{ClientCmd, FrameData, Shared};
use egui::{Color32, Pos2, Rect, Sense, TextureHandle, TextureOptions};
use kbdesk_core::{InputEvent, KeySpec, MouseButton};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;

pub struct KbDeskApp {
    tx: UnboundedSender<ClientCmd>,
    shared: Arc<Mutex<Shared>>,

    // Connection form.
    server: String,
    relay_id: String,
    password: String,
    quality: u8,
    fps: u8,

    // View state.
    texture: Option<TextureHandle>,
    frame_size: (u16, u16),
    connected: bool,
}

impl KbDeskApp {
    pub fn new(tx: UnboundedSender<ClientCmd>, shared: Arc<Mutex<Shared>>) -> Self {
        Self {
            tx,
            shared,
            server: std::env::var("KB_DESK_SERVER").unwrap_or_else(|_| "127.0.0.1:21118".into()),
            relay_id: std::env::var("KB_DESK_ID").unwrap_or_default(),
            password: std::env::var("KB_DESK_PASSWORD").unwrap_or_default(),
            quality: 70,
            fps: 15,
            texture: None,
            frame_size: (1, 1),
            connected: false,
        }
    }

    fn send_input(&self, event: InputEvent) {
        let _ = self.tx.send(ClientCmd::Input(event));
    }

    fn connect(&self) {
        let relay_id = self.relay_id.trim();
        let _ = self.tx.send(ClientCmd::Connect {
            addr: self.server.trim().to_string(),
            relay_id: if relay_id.is_empty() {
                None
            } else {
                Some(relay_id.to_string())
            },
            password: self.password.clone(),
            monitor: 0,
            quality: self.quality,
            fps: self.fps,
        });
    }

    fn draw_screen(&mut self, ui: &mut egui::Ui) {
        // Pick up a new frame if the network thread flagged one.
        let pending = {
            let mut shared = self.shared.lock().unwrap();
            if shared.dirty {
                shared.dirty = false;
                shared.frame.clone()
            } else {
                None
            }
        };
        if let Some(frame) = pending {
            match decode_frame(&frame) {
                Ok(image) => {
                    self.frame_size = (frame.width.max(1), frame.height.max(1));
                    match &mut self.texture {
                        Some(texture) => texture.set(image, TextureOptions::LINEAR),
                        None => {
                            self.texture = Some(ui.ctx().load_texture(
                                "kbdesk-screen",
                                image,
                                TextureOptions::LINEAR,
                            ))
                        }
                    }
                }
                Err(e) => tracing::warn!("could not decode frame: {e:#}"),
            }
        }

        let Some(texture) = self.texture.clone() else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    "Not connected.\n\nEnter the relay or host address (and ID for a relay), \
                     the password, then press Connect.",
                );
            });
            return;
        };

        // Fit the frame into the available area, preserving aspect ratio.
        let available = ui.available_size();
        let (fw, fh) = self.frame_size;
        let aspect = fw as f32 / fh as f32;
        let mut size = available;
        if size.x / size.y > aspect {
            size.x = size.y * aspect;
        } else {
            size.y = size.x / aspect;
        }

        let (rect, _response) = ui.allocate_exact_size(size, Sense::click_and_drag());
        ui.painter().image(
            texture.id(),
            rect,
            Rect::from_min_max(Pos2::new(0.0, 0.0), Pos2::new(1.0, 1.0)),
            Color32::WHITE,
        );

        if self.connected {
            self.forward_input(ui, rect, fw, fh);
        }
    }

    fn forward_input(&self, ui: &egui::Ui, rect: Rect, fw: u16, fh: u16) {
        let events = ui.input(|i| i.events.clone());
        let hovered = ui
            .input(|i| i.pointer.hover_pos())
            .is_some_and(|p| rect.contains(p));

        let to_screen = |p: Pos2| -> Option<(i32, i32)> {
            if !rect.contains(p) {
                return None;
            }
            let u = (p.x - rect.min.x) / rect.width().max(1.0);
            let v = (p.y - rect.min.y) / rect.height().max(1.0);
            Some(((u * fw as f32) as i32, (v * fh as f32) as i32))
        };

        for event in events {
            match event {
                egui::Event::PointerMoved(pos) => {
                    if let Some((x, y)) = to_screen(pos) {
                        self.send_input(InputEvent::MouseMove { x, y });
                    }
                }
                egui::Event::PointerButton {
                    pos,
                    button,
                    pressed,
                    ..
                } => {
                    if let Some((x, y)) = to_screen(pos) {
                        self.send_input(InputEvent::MouseMove { x, y });
                        if let Some(button) = to_mouse_button(button) {
                            self.send_input(InputEvent::MouseButton { button, down: pressed });
                        }
                    }
                }
                egui::Event::MouseWheel { delta, .. } => {
                    if hovered {
                        self.send_input(InputEvent::MouseScroll {
                            dx: delta.x as i32,
                            dy: delta.y as i32,
                        });
                    }
                }
                egui::Event::Key {
                    key,
                    pressed,
                    repeat,
                    ..
                } => {
                    if repeat {
                        continue;
                    }
                    if let Some(spec) = key_to_spec(key) {
                        self.send_input(InputEvent::Key { key: spec, down: pressed });
                    }
                }
                egui::Event::Text(text) => {
                    for c in text.chars() {
                        self.send_input(InputEvent::Key {
                            key: KeySpec::Char(c),
                            down: true,
                        });
                        self.send_input(InputEvent::Key {
                            key: KeySpec::Char(c),
                            down: false,
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

impl eframe::App for KbDeskApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.connected = self.shared.lock().unwrap().connected;

        egui::Panel::top("kbdesk-controls").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label("Address:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.server)
                        .desired_width(170.0)
                        .hint_text("relay or host ip:port"),
                );
                ui.label("ID:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.relay_id)
                        .desired_width(90.0)
                        .hint_text("relay only"),
                );
                ui.label("Password:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .password(true)
                        .desired_width(120.0),
                );

                if self.connected {
                    if ui.button("Disconnect").clicked() {
                        let _ = self.tx.send(ClientCmd::Disconnect);
                    }
                } else if ui.button("Connect").clicked() {
                    self.connect();
                }
            });

            ui.horizontal_wrapped(|ui| {
                ui.label("Quality:");
                ui.add(egui::Slider::new(&mut self.quality, 10..=95));
                ui.label("FPS:");
                ui.add(egui::Slider::new(&mut self.fps, 1..=30));
            });

            let status = self.shared.lock().unwrap().status.clone();
            ui.label(format!("Status: {status}"));
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            self.draw_screen(ui);
        });
    }
}

fn decode_frame(frame: &FrameData) -> anyhow::Result<egui::ColorImage> {
    let image = image::load_from_memory(&frame.jpeg)?.to_rgb8();
    Ok(egui::ColorImage::from_rgb(
        [image.width() as usize, image.height() as usize],
        image.as_raw(),
    ))
}

fn to_mouse_button(button: egui::PointerButton) -> Option<MouseButton> {
    match button {
        egui::PointerButton::Primary => Some(MouseButton::Left),
        egui::PointerButton::Secondary => Some(MouseButton::Right),
        egui::PointerButton::Middle => Some(MouseButton::Middle),
        _ => None,
    }
}

/// Map non-printable keys to protocol names. Printable characters are handled
/// via [`egui::Event::Text`] instead, so text keys return `None` here.
fn key_to_spec(key: egui::Key) -> Option<KeySpec> {
    use egui::Key;
    let name = match key {
        Key::Enter => "Enter",
        Key::Tab => "Tab",
        Key::Escape => "Escape",
        Key::Backspace => "Backspace",
        Key::Delete => "Delete",
        Key::Home => "Home",
        Key::End => "End",
        Key::PageUp => "PageUp",
        Key::PageDown => "PageDown",
        Key::ArrowUp => "ArrowUp",
        Key::ArrowDown => "ArrowDown",
        Key::ArrowLeft => "ArrowLeft",
        Key::ArrowRight => "ArrowRight",
        Key::ShiftLeft => "ShiftLeft",
        Key::ShiftRight => "ShiftRight",
        Key::ControlLeft => "ControlLeft",
        Key::ControlRight => "ControlRight",
        Key::AltLeft => "Alt",
        Key::AltRight => "Alt",
        Key::SuperLeft => "Meta",
        Key::SuperRight => "Meta",
        Key::CapsLock => "CapsLock",
        Key::F1 => "F1",
        Key::F2 => "F2",
        Key::F3 => "F3",
        Key::F4 => "F4",
        Key::F5 => "F5",
        Key::F6 => "F6",
        Key::F7 => "F7",
        Key::F8 => "F8",
        Key::F9 => "F9",
        Key::F10 => "F10",
        Key::F11 => "F11",
        Key::F12 => "F12",
        _ => return None,
    };
    Some(KeySpec::Named(name.to_string()))
}
