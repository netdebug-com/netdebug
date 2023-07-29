// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use libconntrack::connection::ConnectionTrackerMsg;

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust! Fool!", name)
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct DesktopContext {
    pub log_dir: String,
    pub pcap_device: String, // TODO: make this a Vec<> to hold multiple devices
    pub connection_tracker: tokio::sync::mpsc::UnboundedSender<ConnectionTrackerMsg>,
    pub max_connections_per_tracker: usize,
}

impl DesktopContext {
    pub fn new(
        log_dir: String,
        max_connections_per_tracker: usize,
        connection_tracker: tokio::sync::mpsc::UnboundedSender<ConnectionTrackerMsg>,
        pcap_device: Option<String>,
    ) -> DesktopContext {
        let pcap_device = match pcap_device {
            Some(d) => d,
            None => {
                let d = libconntrack::pcap::lookup_egress_device().unwrap();
                d.name
            }
        };
        DesktopContext {
            log_dir,
            pcap_device,
            connection_tracker,
            max_connections_per_tracker,
        }
    }
}

fn main() {
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<ConnectionTrackerMsg>();

    let _context = DesktopContext::new("logs".to_string(), 2048, tx, None);

    /*
    let connection_tracker = tokio::spawn(async {
        ConnectionTracker::new();
    });
    */

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
