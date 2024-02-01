mod rest_endpoints;
use chrono::Duration;
use clap::Parser;
use common_wasm::timeseries_stats::{SharedExportedStatRegistries, SuperRegistry};
use desktop_common::get_git_hash_version;
use libconntrack::dns_tracker::DnsTrackerSender;
use libconntrack::pcap::{
    pcap_find_all_local_addrs, spawn_pcap_monitor_all_interfaces, PcapMonitorOptions,
};
use libconntrack::system_tracker::SystemTracker;
use libconntrack::{
    connection_tracker::{ConnectionTracker, ConnectionTrackerMsg, ConnectionTrackerSender},
    dns_tracker::{DnsTracker, DnsTrackerMessage},
    prober::spawn_raw_prober,
    process_tracker::{ProcessTracker, ProcessTrackerSender},
    utils::PerfMsgCheck,
};
use log::info;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::RwLock;

use libconntrack::topology_client::{TopologyServerConnection, TopologyServerSender};

use crate::rest_endpoints::setup_axum_router;

const NON_DNS_PAYLOAD_LEN: usize = 64;

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

    let local_addrs = pcap_find_all_local_addrs()?;
    // TODO! Change this logic so that the binding to the interface can change over time
    let raw_sock = libconntrack::pcap::bind_writable_pcap();
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

    let pcap_options = PcapMonitorOptions {
        filter_rule: None,
        connection_tracker_tx,
        payload_len_for_non_dns: NON_DNS_PAYLOAD_LEN,
        startup_delay: Some(chrono::Duration::milliseconds(150)),
        stats_polling_frequency: None,
    };
    let pcap_monitor_tx =
        spawn_pcap_monitor_all_interfaces(MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE, pcap_options);
    system_tracker.write().await.pcap_monitor_tx = Some(pcap_monitor_tx);

    info!("Running desktop version: {}", get_git_hash_version());
    let listen_addr = ("127.0.0.1", args.listen_port);

    trackers.counter_registries = Some(counter_registries.registries());

    let shared_state = Arc::new(trackers.clone());
    info!("Starting Axum");
    let routes = setup_axum_router().with_state(shared_state);

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();
    axum::serve(listener, routes).await.unwrap();
    Ok(())
}
