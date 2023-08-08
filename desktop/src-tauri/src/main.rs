// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{collections::HashSet, net::IpAddr};

use libconntrack::connection::{ConnectionTracker, ConnectionTrackerMsg};
use log::warn;

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust! Fool!", name)
}

#[tauri::command]
async fn dump_connection_keys(
    context: tauri::State<'_, DesktopContext>,
) -> Result<Vec<String>, String> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    if let Err(e) = context
        .connection_tracker
        .send(ConnectionTrackerMsg::GetConnectionKeys { tx })
    {
        return Err(format!("dump_connection_keys():: {}", e));
    }
    match rx.recv().await {
        Some(keys) => Ok(keys.iter().map(|k| format!("{}", k).to_string()).collect()),
        None => Err("Failed to return any keys!? Check logs".to_string()),
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct DesktopContext {
    pub log_dir: String,
    pub pcap_device_name: String, // TODO: make this a Vec<> to hold multiple devices
    pub local_addrs: HashSet<IpAddr>,
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
            Some(name) => libconntrack::pcap::lookup_pcap_device_by_name(&name),
            None => libconntrack::pcap::lookup_egress_device(),
        };

        let (pcap_device_name, local_ips) = match pcap_device {
            Ok(d) => {
                let ips: HashSet<IpAddr> =
                    HashSet::from_iter(d.addresses.iter().map(|a| a.addr.clone()));
                (d.name, ips)
            }
            Err(e) => {
                panic!("Fatal: couldn't find a valid pcap device: {}", e);
            }
        };
        DesktopContext {
            log_dir,
            pcap_device_name,
            local_addrs: local_ips,
            connection_tracker,
            max_connections_per_tracker,
        }
    }
}

fn main() {
    // if RUST_LOG isn't set explicitly, set RUST_LOG=info as a default
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "info");
    }
    // if RUST_BACKTRACE isn't set explicitly, set RUST_BACKTRACE=1 as a default
    if let Err(_) = std::env::var("RUST_BACKTRACE") {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    pretty_env_logger::init();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<ConnectionTrackerMsg>();

    let context = DesktopContext::new("logs".to_string(), 2048, tx, None);

    // launch the pcap grabber as a normal thread in the background
    let context_clone = context.clone();
    let _pcap_thread = std::thread::spawn(move || {
        let context = context_clone; // save some typing/sanity
        if let Err(e) = libconntrack::pcap::blocking_pcap_loop(
            context.pcap_device_name,
            None,
            context.connection_tracker,
        ) {
            panic!("pcap thread returned: {}", e);
        }
    });

    let context_clone = context.clone();
    // now launch the tauri front-end + backend event loop magic
    tauri::Builder::default()
        .manage(context)
        .setup(|_app| {
            // launch the connection tracker as a tokio::task in the background
            let _connection_tracker_task = tauri::async_runtime::spawn(async move {
                let context = context_clone; // save some typing/sanity
                let raw_sock = match
                    libconntrack::pcap::bind_writable_pcap_by_name(context.pcap_device_name)
                        {
                            Ok(raw) => raw,
                            Err(e) => {
                                warn!("Couldn't bind raw socket writer: {}  (run as root?)", e);
                                std::process::exit(1);
                            },
                        };
                let mut connection_tracker = ConnectionTracker::new(
                    context.log_dir,
                    context.max_connections_per_tracker,
                    context.local_addrs,
                    raw_sock,
                )
                .await;
                // loop forever tracking messages sent on the channel
                connection_tracker.rx_loop(rx).await;
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![greet, dump_connection_keys])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
