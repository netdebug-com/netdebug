mod websocket;

use chrono::Duration;
use clap::Parser;
use libconntrack::{
    connection::{ConnectionTracker, ConnectionTrackerMsg, ConnectionTrackerSender},
    connection_storage_handler::ConnectionStorageHandler,
    dns_tracker::{DnsTracker, DnsTrackerMessage},
    in_band_probe::spawn_raw_prober,
    process_tracker::{ProcessTracker, ProcessTrackerMessage},
    utils::PerfMsgCheck,
};
use log::info;
use std::{collections::HashSet, error::Error, net::IpAddr};
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

    /// How big to make the LRU Cache on each ConnectionTracker
    #[arg(long, default_value_t = 4096)]
    pub max_connections_per_tracker: usize,

    /// The URL of the GRPC storage server. E.g., http://localhost:50051
    #[arg(long, default_value=None)]
    pub storage_server_url: Option<String>,
}

const MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE: usize = 8192;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    common::init::netdebug_init();

    let args = Args::parse();

    // create a channel for the ConnectionTracker
    let (tx, rx) = tokio::sync::mpsc::channel::<PerfMsgCheck<ConnectionTrackerMsg>>(
        MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
    );

    let devices = libconntrack::pcap::find_interesting_pcap_interfaces(&args.pcap_device)?;
    let local_addrs = devices
        .iter()
        .map(|d| d.addresses.iter().map(|a| a.addr).collect::<Vec<IpAddr>>())
        .flatten()
        .collect::<HashSet<IpAddr>>();
    // launch the process tracker
    let process_tracker = ProcessTracker::new();
    let (process_tracker, _join) = process_tracker.spawn(Duration::milliseconds(500)).await;

    // launch the DNS tracker; cache localhost entries
    let (dns_tx, _) = DnsTracker::spawn(/* expiring cache capacity */ 4096).await;
    let dns_tx_clone = dns_tx.clone();
    for ip in local_addrs.clone() {
        dns_tx
            .send(DnsTrackerMessage::CacheForever {
                ip,
                hostname: "localhost".to_string(),
            })
            .unwrap();
    }

    for dev in &devices {
        // launch the pcap grabber as a normal OS thread in the background
        // pcap on windows doesn't understand tokio/async
        let tx_clone = tx.clone();
        let device_name = dev.name.clone();
        let _pcap_thread =
            libconntrack::pcap::run_blocking_pcap_loop_in_thread(device_name, None, tx_clone, None);
    }

    // launch the connection tracker as a tokio::task in the background
    let args_clone = args.clone();
    let connection_manager_tx = tx.clone();
    let _connection_tracker_task = tokio::spawn(async move {
        let raw_sock =
            libconntrack::pcap::bind_writable_pcap_by_name(devices[0].name.clone()).unwrap();
        let prober_tx = spawn_raw_prober(raw_sock, MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE).await;
        let args = args_clone;
        // Spawn a ConnectionTracker task
        let storage_service_msg_tx = if let Some(url) = args.storage_server_url {
            Some(ConnectionStorageHandler::spawn_from_url(url, 1000).await)
        } else {
            None
        };
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_msg_tx,
            args.max_connections_per_tracker,
            local_addrs,
            prober_tx,
            MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
        );
        connection_tracker.set_tx_rx(connection_manager_tx, rx);
        connection_tracker.set_dns_tracker(dns_tx_clone);
        // loop forever tracking messages sent on the channel
        connection_tracker.rx_loop().await;
    });

    info!(
        "Running desktop version: {}",
        desktop_common::get_git_hash_version()
    );
    let listen_addr = ([127, 0, 0, 1], args.listen_port);
    warp::serve(
        make_desktop_http_routes(
            &args.wasm_root,
            &args.html_root,
            tx,
            dns_tx,
            process_tracker,
        )
        .await,
    )
    .run(listen_addr)
    .await;
    Ok(())
}

/***** A bunch of copied/funged code from libwebserver - think about how to refactor */

pub async fn make_desktop_http_routes(
    wasm_root: &String,
    html_root: &String,
    connection_tracker: ConnectionTrackerSender,
    dns_tracker: UnboundedSender<DnsTrackerMessage>,
    process_tracker: UnboundedSender<ProcessTrackerMessage>,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let webclient =
        libwebserver::http_routes::make_webclient_route(&wasm_root).with(warp::log("webclient"));
    let ws = make_desktop_ws_route(connection_tracker, dns_tracker, process_tracker)
        .with(warp::log("websocket"));
    let static_path = warp::fs::dir(html_root.clone()).with(warp::log("static"));

    // this is the order that the filters try to match; it's important that
    // it's in this order to make sure the routing works correctly
    let routes = ws.or(webclient).or(static_path);
    routes
}

// this function just wraps the connection tracker to make sure the types are understood
fn with_connection_tracker(
    connection_tracker: ConnectionTrackerSender,
) -> impl warp::Filter<Extract = (ConnectionTrackerSender,), Error = std::convert::Infallible> + Clone
{
    let connection_tracker = connection_tracker.clone();
    warp::any().map(move || connection_tracker.clone())
}

fn with_dns_tracker(
    dns_tracker: UnboundedSender<DnsTrackerMessage>,
) -> impl warp::Filter<
    Extract = (UnboundedSender<DnsTrackerMessage>,),
    Error = std::convert::Infallible,
> + Clone {
    let dns_tracker = dns_tracker.clone();
    warp::any().map(move || dns_tracker.clone())
}

fn with_process_tracker(
    process_tracker: UnboundedSender<ProcessTrackerMessage>,
) -> impl warp::Filter<
    Extract = (UnboundedSender<ProcessTrackerMessage>,),
    Error = std::convert::Infallible,
> + Clone {
    let process_tracker = process_tracker.clone();
    warp::any().map(move || process_tracker.clone())
}

fn make_desktop_ws_route(
    connection_tracker: ConnectionTrackerSender,
    dns_tracker: UnboundedSender<DnsTrackerMessage>,
    process_tracker: UnboundedSender<ProcessTrackerMessage>,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("ws")
        .and(with_connection_tracker(connection_tracker))
        .and(with_dns_tracker(dns_tracker))
        .and(with_process_tracker(process_tracker))
        .and(warp::ws())
        .and_then(websocket_desktop)
}
pub async fn websocket_desktop(
    connection_tracker: ConnectionTrackerSender,
    dns_tracker: UnboundedSender<DnsTrackerMessage>,
    process_tracker: UnboundedSender<ProcessTrackerMessage>,
    ws: warp::ws::Ws,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(ws.on_upgrade(move |websocket| {
        websocket_handler(connection_tracker, dns_tracker, process_tracker, websocket)
    }))
}
