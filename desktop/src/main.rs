use axum::extract::State;
use axum::{response, routing, Router};
use chrono::Duration;
use clap::Parser;
use common_wasm::timeseries_stats::{
    CounterProvider, CounterProviderWithTimeUpdate, SharedExportedStatRegistries, SuperRegistry,
};
use desktop_common::{get_git_hash_version, CongestedLinksReply};
use libconntrack::connection_tracker::TimeMode;
use libconntrack::dns_tracker::DnsTrackerSender;
use libconntrack::system_tracker::SystemTracker;
use libconntrack::topology_client::{TopologyServerMessage, TopologyServerSender};
use libconntrack::utils::{channel_rpc, channel_rpc_perf};
use libconntrack::{
    connection_tracker::{ConnectionTracker, ConnectionTrackerMsg, ConnectionTrackerSender},
    dns_tracker::{DnsTracker, DnsTrackerMessage},
    prober::spawn_raw_prober,
    process_tracker::{ProcessTracker, ProcessTrackerSender},
    utils::PerfMsgCheck,
};
use libconntrack_wasm::{
    bidir_bandwidth_to_chartjs, AggregateStatEntry, ChartJsBandwidth, ConnectionMeasurements,
    DnsTrackerEntry, ExportedNeighborState, NetworkInterfaceState,
};
use log::info;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::{collections::HashSet, error::Error, net::IpAddr};
use tokio::sync::mpsc::channel;
use tokio::sync::RwLock;
use tower_http::cors::{self, AllowOrigin, CorsLayer};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};

use libconntrack::topology_client::TopologyServerConnection;

// When running electron forge in dev mode, it (or rather the webpack
// it uses) starts the HTTP dev-server on this URL/origin. We need to
// set-up tower/axum to allow cross-origin requests from this origin
const ELECTRON_DEV_SERVER_ORIGIN: &str = "http://localhost:3000";

/// Struct to hold all of the various trackers
/// We can clone this arbitrarily with no state/locking issues
#[derive(Clone, Debug, Default)]
pub struct Trackers {
    pub connection_tracker: Option<ConnectionTrackerSender>,
    pub dns_tracker: Option<DnsTrackerSender>,
    pub process_tracker: Option<ProcessTrackerSender>,
    pub topology_client: Option<TopologyServerSender>,
    // implemented as a shared lock
    pub system_tracker: Option<Arc<RwLock<SystemTracker>>>,
    pub counter_registries: Option<SharedExportedStatRegistries>,
}

impl Trackers {
    /// Return an empty set of trackers to be filled in later
    pub fn empty() -> Trackers {
        Trackers::default()
    }
}

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
    #[arg(long, default_value = "wss://topology.netdebug.com:443/desktop")]
    pub topology_server_url: String,
}

const MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE: usize = 8192;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    common::init::netdebug_init();

    let args = Args::parse();
    let system_epoch = std::time::Instant::now();

    // are we really, really running the multi-threaded runtime?
    info!(
        "Current tokio scheduler flavor is: {:?}",
        tokio::runtime::Handle::current().runtime_flavor()
    );
    let mut trackers = Trackers::empty();

    let mut counter_registries = SuperRegistry::new(system_epoch);
    // create a channel for the ConnectionTracker
    let (connection_tracker_tx, rx) = tokio::sync::mpsc::channel::<
        PerfMsgCheck<ConnectionTrackerMsg>,
    >(MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE);

    let devices = libconntrack::pcap::find_interesting_pcap_interfaces(&args.pcap_device)?;
    let local_addrs = devices
        .iter()
        .flat_map(|d| d.addresses.iter().map(|a| a.addr).collect::<Vec<IpAddr>>())
        .collect::<HashSet<IpAddr>>();
    // TODO! Change this logic so that the binding to the interface can change over time
    let raw_sock = libconntrack::pcap::bind_writable_pcap_by_name(devices[0].name.clone()).unwrap();
    let prober_tx = spawn_raw_prober(raw_sock, MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE);

    let system_tracker = Arc::new(RwLock::new(
        SystemTracker::new(
            counter_registries.new_registry("system_tracker"),
            1024, /* max network histories to keep */
            1024, /* max pings per gateway to keep */
            connection_tracker_tx.clone(),
            prober_tx.clone(),
        )
        .await,
    ));
    SystemTracker::spawn_system_tracker_background_tasks(
        system_tracker.clone(),
        std::time::Duration::from_millis(500),
    );
    trackers.system_tracker = Some(system_tracker.clone());

    let topology_client = TopologyServerConnection::spawn(
        args.topology_server_url.clone(),
        MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
        std::time::Duration::from_secs(30),
        counter_registries.registries(),
        counter_registries.new_registry("topology_server_connection"),
    );
    trackers.topology_client = Some(topology_client.clone());

    // launch the process tracker
    let process_tracker = ProcessTracker::new(
        MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
        counter_registries.new_registry("process_tracker"),
    );
    let (process_tx, _join) = process_tracker.spawn(Duration::milliseconds(500)).await;
    trackers.process_tracker = Some(process_tx.clone());

    // launch the DNS tracker; cache localhost entries
    let (dns_tx, _) = DnsTracker::spawn(
        /* expiring cache capacity */ 4096,
        counter_registries.new_registry("dns_tracker"),
        /* max msg queue entries */
        4096,
    )
    .await;
    trackers.dns_tracker = Some(dns_tx.clone());
    let dns_tx_clone = dns_tx.clone();
    let process_tx_clone = process_tx.clone();
    for ip in local_addrs.clone() {
        dns_tx
            .try_send(DnsTrackerMessage::CacheForever {
                ip,
                hostname: "localhost".to_string(),
            })
            .unwrap();
    }

    for dev in &devices {
        // launch the pcap grabber as a normal OS thread in the background
        // pcap on windows doesn't understand tokio/async
        let tx_clone = connection_tracker_tx.clone();
        let device_name = dev.name.clone();
        let _pcap_thread =
            libconntrack::pcap::run_blocking_pcap_loop_in_thread(device_name, None, tx_clone, None);
    }

    // launch the connection tracker as a tokio::task in the background
    let args_clone = args.clone();
    let connection_manager_tx = connection_tracker_tx.clone();
    trackers.connection_tracker = Some(connection_manager_tx.clone());

    let conn_track_counters = counter_registries.new_registry("conn_tracker");
    let topology_client_clone = topology_client.clone();
    let _connection_tracker_task = tokio::spawn(async move {
        let args = args_clone;
        // Spawn a ConnectionTracker task
        let mut connection_tracker = ConnectionTracker::new(
            Some(topology_client_clone),
            args.max_connections_per_tracker,
            local_addrs,
            prober_tx,
            MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
            conn_track_counters,
            false, // desktop need to rate limit probes
        );
        connection_tracker.set_tx_rx(connection_manager_tx, rx);
        connection_tracker.set_dns_tracker(dns_tx_clone);
        connection_tracker.set_process_tracker(process_tx_clone);
        // loop forever tracking messages sent on the channel
        connection_tracker.rx_loop().await;
    });

    info!("Running desktop version: {}", get_git_hash_version());
    let listen_addr = ("127.0.0.1", args.listen_port);

    trackers.counter_registries = Some(counter_registries.registries());

    let shared_state = Arc::new(trackers.clone());
    info!("Starting Axum");
    // Setup CORS to make sure that the electron in dev-mode can request
    // resources.
    let allowed_origins = vec![ELECTRON_DEV_SERVER_ORIGIN.parse().unwrap()];
    let cors = CorsLayer::new()
        .allow_methods(cors::Any)
        .allow_origin(AllowOrigin::list(allowed_origins));
    // Basic Request logging
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(tracing::Level::DEBUG));
    let app = Router::new()
        .route("/api/get_counters", routing::get(handle_get_counters))
        .route("/api/get_flows", routing::get(handle_get_flows))
        .route("/api/get_dns_cache", routing::get(handle_get_dns_cache))
        .route(
            "/api/get_aggregate_bandwidth",
            routing::get(handle_get_aggregate_bandwidth),
        )
        .route("/api/get_dns_flows", routing::get(handle_get_dns_flows))
        .route("/api/get_app_flows", routing::get(handle_get_app_flows))
        .route("/api/get_host_flows", routing::get(handle_get_host_flows))
        .route("/api/get_my_ip", routing::get(handle_get_my_ip))
        .route(
            "/api/get_congested_links",
            routing::get(handle_get_congested_links),
        )
        .route(
            "/api/get_system_network_history",
            routing::get(handle_get_system_network_history),
        )
        .route("/api/get_devices", routing::get(handle_get_devices))
        .layer(cors)
        .layer(trace_layer)
        .with_state(shared_state);

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}

async fn handle_get_counters(State(trackers): State<Arc<Trackers>>) -> String {
    // IndexMap iterates over entries in insertion order
    let mut map = indexmap::IndexMap::<String, u64>::new();
    {
        let locked_registries = trackers
            .counter_registries
            .as_ref()
            .unwrap()
            .lock()
            .unwrap();
        locked_registries.update_time();
        locked_registries.append_counters(&mut map);
    }
    serde_json::to_string_pretty(&map).unwrap()
}

// TODO: for all teh handle_FOO handlers. Instead of returning empty on an error, we should
// actually propagate an proper error back to the UI.
// TODO: our usagae of SLA logging is inconsistent. Some have SLAs, some don't for now, I'm
// simply copying what we used for websocket

async fn handle_get_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<ConnectionMeasurements>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetConnectionMeasurements {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetConnectionMeasurements",
            Some(tokio::time::Duration::from_millis(200)),
        )
        .await
        .unwrap_or_default(),
    )
}

async fn handle_get_dns_cache(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<HashMap<IpAddr, DnsTrackerEntry>> {
    let (tx, mut rx) = channel(1);
    let req = DnsTrackerMessage::DumpReverseMap { tx };
    response::Json(
        channel_rpc(
            trackers.dns_tracker.clone().unwrap(),
            req,
            &mut rx,
            "dns_tracker/DumpReverseMap",
            None,
        )
        .await
        .unwrap_or_default(),
    )
}

async fn handle_get_aggregate_bandwidth(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<ChartJsBandwidth>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetTrafficCounter",
            Some(tokio::time::Duration::from_millis(50)),
        )
        .await
        .map(bidir_bandwidth_to_chartjs)
        .unwrap_or_default(),
    )
}

async fn handle_get_dns_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<AggregateStatEntry>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetDnsTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetDnsTrafficCounters",
            Some(tokio::time::Duration::from_millis(100)),
        )
        .await
        .unwrap_or_default(),
    )
}

async fn handle_get_app_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<AggregateStatEntry>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetAppTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetAppTrafficCounters",
            Some(tokio::time::Duration::from_millis(100)),
        )
        .await
        .unwrap_or_default(),
    )
}

async fn handle_get_host_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<AggregateStatEntry>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetHostTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetHostTrafficCounters",
            Some(tokio::time::Duration::from_millis(100)),
        )
        .await
        .unwrap_or_default(),
    )
}

async fn handle_get_my_ip(State(trackers): State<Arc<Trackers>>) -> response::Json<IpAddr> {
    // TODO: should return a list of IPs or a pair of v4/v6.
    let (tx, mut rx) = channel(1);
    let req = TopologyServerMessage::GetMyIpAndUserAgent { reply_tx: tx };
    response::Json(
        channel_rpc_perf(
            trackers.topology_client.clone().unwrap(),
            req,
            &mut rx,
            "topology_server/GetMyIp",
            None,
        )
        .await
        .map(|perf_msg| {
            let (ip, _) = perf_msg.perf_check_get("handle_get_my_ip");
            ip
        })
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    )
}

async fn handle_get_devices(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<ExportedNeighborState>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetCachedNeighbors { tx };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "ConnectionTracker/GetNeighborState",
            None,
        )
        .await
        .unwrap_or_default(),
    )
}

async fn handle_get_congested_links(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<CongestedLinksReply> {
    // 1. request connection measurements from conntracker
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetConnectionMeasurements {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    let conn_measurements = match channel_rpc_perf(
        trackers.connection_tracker.clone().unwrap(),
        req,
        &mut rx,
        "congested links -- connection_tracker/GetConnectionMeasurements",
        None,
    )
    .await
    {
        Ok(m) => m,
        Err(_) => return response::Json(CongestedLinksReply::default()),
    };

    // 2. send the measurements to the topology server for analysis
    let (tx, mut rx) = channel(1);
    let req = TopologyServerMessage::InferCongestion {
        connection_measurements: conn_measurements.clone(),
        reply_tx: tx,
    };
    let congestion_summary = channel_rpc_perf(
        trackers.topology_client.clone().unwrap(),
        req,
        &mut rx,
        "congested links -- topology_server/InferCongestion",
        None,
    )
    .await
    .map(|perf_msg| perf_msg.perf_check_get("handle_congested_links"))
    .unwrap_or_default();
    response::Json(CongestedLinksReply {
        congestion_summary,
        connection_measurements: conn_measurements,
    })
}

async fn handle_get_system_network_history(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<NetworkInterfaceState>> {
    response::Json(
        trackers
            .system_tracker
            .clone()
            .unwrap()
            .read()
            .await
            .get_network_interface_histories(),
    )
}
