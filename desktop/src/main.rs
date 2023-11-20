mod websocket;

use chrono::Duration;
use clap::Parser;
use common_wasm::timeseries_stats::{
    CounterProvider, CounterProviderWithTimeUpdate, ExportedStatRegistry, SuperRegistry,
};
use libconntrack::topology_client::{self, TopologyServerSender};
use libconntrack::{
    connection_tracker::{ConnectionTracker, ConnectionTrackerMsg, ConnectionTrackerSender},
    dns_tracker::{DnsTracker, DnsTrackerMessage},
    in_band_probe::spawn_raw_prober,
    process_tracker::{ProcessTracker, ProcessTrackerSender},
    utils::PerfMsgCheck,
};
use log::info;
use std::{collections::HashSet, error::Error, net::IpAddr, sync::Arc};
use tokio::sync::mpsc::UnboundedSender;
use warp::Filter;
use websocket::websocket_handler;

use libconntrack::topology_client::TopologyServerConnection;

type SharedExportedStatRegistries = Arc<Vec<ExportedStatRegistry>>;

/// Netdebug desktop
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// which TCP port to listen on
    #[arg(long, default_value_t = 33434)] // traceroute port, for fun
    pub listen_port: u16,

    /// which pcap device to listen on; default is autodetect
    #[arg(long, default_value = None)]
    pub pcap_device: Option<String>,

    /// How big to make the LRU Cache on each ConnectionTracker
    #[arg(long, default_value_t = 4096)]
    pub max_connections_per_tracker: usize,

    /// The URL of the Topology Server. E.g., ws://localhost:3030
    #[arg(long, default_value = "ws://localhost:3030/desktop")]
    pub topology_server_url: String,
}

const MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE: usize = 8192;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    common::init::netdebug_init();

    let args = Args::parse();
    let system_epoch = std::time::Instant::now();

    let mut counter_registries = SuperRegistry::new(system_epoch);
    // create a channel for the ConnectionTracker
    let (tx, rx) = tokio::sync::mpsc::channel::<PerfMsgCheck<ConnectionTrackerMsg>>(
        MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
    );

    let topology_client = TopologyServerConnection::spawn(
        args.topology_server_url.clone(),
        MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
        std::time::Duration::from_secs(30),
        counter_registries.new_registry("topology_server_connection"),
    );

    let devices = libconntrack::pcap::find_interesting_pcap_interfaces(&args.pcap_device)?;
    let local_addrs = devices
        .iter()
        .flat_map(|d| d.addresses.iter().map(|a| a.addr).collect::<Vec<IpAddr>>())
        .collect::<HashSet<IpAddr>>();
    // launch the process tracker
    let process_tracker = ProcessTracker::new(
        MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
        counter_registries.new_registry("process_tracker"),
    );
    let (process_tx, _join) = process_tracker.spawn(Duration::milliseconds(500)).await;

    // launch the DNS tracker; cache localhost entries
    let (dns_tx, _) = DnsTracker::spawn(/* expiring cache capacity */ 4096).await;
    let dns_tx_clone = dns_tx.clone();
    let process_tx_clone = process_tx.clone();
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

    let conn_track_counters = counter_registries.new_registry("conn_tracker");
    let topology_client_clone = topology_client.clone();
    let _connection_tracker_task = tokio::spawn(async move {
        let raw_sock =
            libconntrack::pcap::bind_writable_pcap_by_name(devices[0].name.clone()).unwrap();
        let prober_tx = spawn_raw_prober(raw_sock, MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE).await;
        let args = args_clone;
        // Spawn a ConnectionTracker task
        let mut connection_tracker = ConnectionTracker::new(
            Some(topology_client_clone),
            args.max_connections_per_tracker,
            local_addrs,
            prober_tx,
            MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
            conn_track_counters,
        );
        connection_tracker.set_tx_rx(connection_manager_tx, rx);
        connection_tracker.set_dns_tracker(dns_tx_clone);
        connection_tracker.set_process_tracker(process_tx_clone);
        // loop forever tracking messages sent on the channel
        connection_tracker.rx_loop().await;
    });

    info!(
        "Running desktop version: {}",
        desktop_common::get_git_hash_version()
    );
    let listen_addr = ([127, 0, 0, 1], args.listen_port);

    warp::serve(make_common_desktop_http_routes(
        tx,
        dns_tx,
        process_tx,
        topology_client,
        Arc::new(counter_registries.registries()),
    ))
    .run(listen_addr)
    .await;
    Ok(())
}

pub fn make_counter_routes(
    registries: SharedExportedStatRegistries,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("counters" / "get_counters").map(move || {
        // IndexMap iterates over entries in insertion order
        let mut map = indexmap::IndexMap::<String, u64>::new();
        registries.update_time();
        registries.append_counters(&mut map);
        serde_json::to_string_pretty(&map).unwrap()
    })
}

/***** A bunch of copied/funged code from libwebserver - think about how to refactor */

pub fn make_common_desktop_http_routes(
    connection_tracker: ConnectionTrackerSender,
    dns_tracker: UnboundedSender<DnsTrackerMessage>,
    process_tracker: ProcessTrackerSender,
    topology_client: TopologyServerSender,
    counter_registries: SharedExportedStatRegistries,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let ws = make_desktop_ws_route(
        connection_tracker,
        dns_tracker,
        process_tracker,
        topology_client,
        counter_registries.clone(),
    )
    .with(warp::log("websocket"));
    let counter_path =
        make_counter_routes(counter_registries).with(warp::log("counters/get_counters"));

    ws.or(counter_path)
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
    process_tracker: ProcessTrackerSender,
) -> impl warp::Filter<Extract = (ProcessTrackerSender,), Error = std::convert::Infallible> + Clone
{
    let process_tracker = process_tracker.clone();
    warp::any().map(move || process_tracker.clone())
}

fn with_topology_client(
    topology_client: TopologyServerSender,
) -> impl warp::Filter<Extract = (TopologyServerSender,), Error = std::convert::Infallible> + Clone
{
    let topology_client = topology_client.clone();
    warp::any().map(move || topology_client.clone())
}

fn with_counter_registries(
    counter_registries: SharedExportedStatRegistries,
) -> impl warp::Filter<Extract = (SharedExportedStatRegistries,), Error = std::convert::Infallible> + Clone
{
    warp::any().map(move || counter_registries.clone())
}

fn make_desktop_ws_route(
    connection_tracker: ConnectionTrackerSender,
    dns_tracker: UnboundedSender<DnsTrackerMessage>,
    process_tracker: ProcessTrackerSender,
    topology_client: TopologyServerSender,
    counter_registries: SharedExportedStatRegistries,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("ws")
        .and(with_connection_tracker(connection_tracker))
        .and(with_dns_tracker(dns_tracker))
        .and(with_process_tracker(process_tracker))
        .and(with_topology_client(topology_client))
        .and(with_counter_registries(counter_registries))
        .and(warp::ws())
        .and_then(websocket_desktop)
}
pub async fn websocket_desktop(
    connection_tracker: ConnectionTrackerSender,
    dns_tracker: UnboundedSender<DnsTrackerMessage>,
    process_tracker: ProcessTrackerSender,
    topology_client: TopologyServerSender,
    counter_registries: SharedExportedStatRegistries,
    ws: warp::ws::Ws,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(ws.on_upgrade(move |websocket| {
        websocket_handler(
            connection_tracker,
            dns_tracker,
            process_tracker,
            topology_client,
            counter_registries,
            websocket,
        )
    }))
}
