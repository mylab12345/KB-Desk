//! KB-Desk viewer / control application.
//!
//! Original, from-scratch implementation. Not derived from any other remote
//! desktop project.

mod app;
mod net;

use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let shared = Arc::new(Mutex::new(net::Shared::default()));
    let tx = net::spawn_network(shared.clone());

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([640.0, 420.0])
            .with_title("KB-Desk"),
        ..Default::default()
    };

    eframe::run_native(
        "KB-Desk",
        options,
        Box::new(move |_cc| Ok(Box::new(app::KbDeskApp::new(tx, shared)))),
    )
}
