mod websocket;

use clap::Parser;
use libconntrack::{
    connection::{ConnectionTracker, ConnectionTrackerMsg},
    dns_tracker::DnsTracker,
    pcap::{lookup_egress_device, lookup_pcap_device_by_name},
};
use log::info;
use std::{error::Error, net::IpAddr};
use tokio::sync::mpsc::UnboundedSender;
use warp::Filter;
use websocket::websocket_handler;

/// Netdebug desktop
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// the base of the WASM build directory, where web-client{.js,_bs.wasm} live
    #[arg(long, default_value = "desktop/html")]
    pub html_root: String,

    /// the base of the WASM build directory, where web-client{.js,_bs.wasm} live
    #[arg(long, default_value = "desktop/web-gui/pkg")]
    pub wasm_root: String,

    /// which TCP port to listen on
    #[arg(long, default_value_t = 33434)] // traceroute port, for fun
    pub listen_port: u16,

    /// which pcap device to listen on; default is autodetect
    #[arg(long, default_value = None)]
    pub pcap_device: Option<String>,

    /// Where to write connection log files?  Will create if doesn't exist
    #[arg(long, default_value = "logs")]
    pub log_dir: String,

    /// How big to make the LRU Cache on each ConnectionTracker
    #[arg(long, default_value_t = 4096)]
    pub max_connections_per_tracker: usize,
}

fn init_logging() {
    // if RUST_LOG isn't set explicitly, set RUST_LOG=info as a default
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "info");
    }
    // if RUST_BACKTRACE isn't set explicitly, set RUST_BACKTRACE=1 as a default
    if let Err(_) = std::env::var("RUST_BACKTRACE") {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    pretty_env_logger::init();
}

/**
 * STUB!
 *
 * Iterate through the ethernet interfaces and return the ones that either (1)
 * were specified on the command line or (2) seem alive/active/worth listening
 * to.
 *
 * Right now, just return the one with the default route if not specified.
 * The API supports multiple interfaces to future proof for VPNs, etc.
 */

fn find_interesting_interfaces(
    device_name: &Option<String>,
) -> Result<Vec<pcap::Device>, Box<dyn Error>> {
    let device = match device_name {
        Some(name) => lookup_pcap_device_by_name(name)?,
        None => lookup_egress_device()?,
    };

    Ok(vec![device])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logging();

    let args = Args::parse();

    // create a channel for the ConnectionTracker
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<ConnectionTrackerMsg>();

    let devices = find_interesting_interfaces(&args.pcap_device)?;
    let local_addrs = devices
        .iter()
        .map(|d| d.addresses.iter().map(|a| a.addr).collect::<Vec<IpAddr>>())
        .flatten()
        .collect();

    for dev in &devices {
        // launch the pcap grabber as a normal OS thread in the background
        let tx_clone = tx.clone();
        let device_name = dev.name.clone();
        let _pcap_thread = std::thread::spawn(move || {
            if let Err(e) = libconntrack::pcap::blocking_pcap_loop(device_name, None, tx_clone) {
                panic!("pcap thread returned: {}", e);
            }
        });
    }
    // launch the DNS tracker
    let (dns_tx, _) = DnsTracker::new().spawn().await;

    // launch the connection tracker as a tokio::task in the background
    let args_clone = args.clone();
    let _connection_tracker_task = tokio::spawn(async move {
        let raw_sock =
            libconntrack::pcap::bind_writable_pcap_by_name(devices[0].name.clone()).unwrap();
        let args = args_clone;
        let mut connection_tracker = ConnectionTracker::new(
            args.log_dir,
            args.max_connections_per_tracker,
            local_addrs,
            raw_sock,
        )
        .await;
        connection_tracker.set_dns_tracker(dns_tx);
        // loop forever tracking messages sent on the channel
        connection_tracker.rx_loop(rx).await;
    });

    info!(
        "Running desktop version: {}",
        desktop_common::get_git_hash_version()
    );
    let listen_addr = ([127, 0, 0, 1], args.listen_port);
    warp::serve(make_desktop_http_routes(&args.wasm_root, &args.html_root, tx).await)
        .run(listen_addr)
        .await;
    Ok(())
}

/***** A bunch of copied/funged code from libwebserver - think about how to refactor */

pub async fn make_desktop_http_routes(
    wasm_root: &String,
    html_root: &String,
    connection_tracker: UnboundedSender<ConnectionTrackerMsg>,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let webclient =
        libwebserver::http_routes::make_webclient_route(&wasm_root).with(warp::log("webclient"));
    let ws = make_desktop_ws_route(connection_tracker).with(warp::log("websocket"));
    let static_path = warp::fs::dir(html_root.clone()).with(warp::log("static"));

    // this is the order that the filters try to match; it's important that
    // it's in this order to make sure the routing works correctly
    let routes = ws.or(webclient).or(static_path);
    routes
}

// this function just wraps the connection tracker to make sure the types are understood
fn with_connection_tracker(
    connection_tracker: UnboundedSender<ConnectionTrackerMsg>,
) -> impl warp::Filter<
    Extract = (UnboundedSender<ConnectionTrackerMsg>,),
    Error = std::convert::Infallible,
> + Clone {
    let connection_tacker = connection_tracker.clone();
    warp::any().map(move || connection_tacker.clone())
}

fn make_desktop_ws_route(
    connection_tracker: UnboundedSender<ConnectionTrackerMsg>,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("ws")
        .and(with_connection_tracker(connection_tracker))
        .and(warp::ws())
        .and_then(websocket_desktop)
}
pub async fn websocket_desktop(
    connection_tracker: UnboundedSender<ConnectionTrackerMsg>,
    ws: warp::ws::Ws,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(ws.on_upgrade(move |websocket| websocket_handler(connection_tracker, websocket)))
}
