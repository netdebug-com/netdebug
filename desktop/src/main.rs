mod rest_endpoints;
use chrono::Duration;
use clap::Parser;
use common_wasm::timeseries_stats::{SharedExportedStatRegistries, SuperRegistry};
use gui_types::get_git_hash_version;
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
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use libconntrack::topology_client::{
    DataStorageSender, TopologyRpcSender, TopologyServerConnection,
};

use crate::rest_endpoints::setup_axum_router;

const NON_DNS_PAYLOAD_LEN: usize = 64;

/// Struct to hold all of the various trackers
/// We can clone this arbitrarily with no state/locking issues
#[derive(Clone, Debug, Default)]
pub struct Trackers {
    pub connection_tracker: Option<ConnectionTrackerSender>,
    pub dns_tracker: Option<DnsTrackerSender>,
    pub process_tracker: Option<ProcessTrackerSender>,
    pub topology_rpc_client: Option<TopologyRpcSender>,
    pub data_storage_client: Option<DataStorageSender>,
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

/// The local configuration data we read from disk. This is the same schema
/// that we define in electron for electron store.
/// see `main.ts: new ElectronConfigStore()...`
/// IF YOU MAKE A CHANGE HERE, ALSO CHANGE THE SCHEMA IN MAIN.
/// TODO: find a better way to sync the schema
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct LocalConfigData {
    pub accepted_eula_version: Option<i32>,
    /// Note, we *require* the device_uuid to be present if we read/use the
    /// config file. Electron will make sure it exists. And the desktop binary
    /// can always be run w/o a config file
    pub device_uuid: Uuid,
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

    /// Json file where local configuration is stored. This is the same file used by the
    /// electron-store npm package.
    #[arg(long, default_value=None)]
    pub local_config_file: Option<String>,
}

const MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE: usize = 8192;

#[derive(thiserror::Error, Debug)]
pub enum LocalConfigError {
    #[error("Invalid config file format")]
    InvalidConfig(#[from] serde_json::Error),
    #[error("Could not read config file")]
    Io(#[from] std::io::Error),
}

fn get_local_config(config_file_name: Option<String>) -> Result<LocalConfigData, LocalConfigError> {
    match config_file_name {
        Some(config_file_name) => {
            let path_to_file = std::path::Path::new(&config_file_name);
            let file_contents = std::fs::read_to_string(path_to_file)?;
            let config_data = serde_json::from_str::<LocalConfigData>(&file_contents)?;
            Ok(config_data)
        }
        None => {
            warn!(
                "No local config directory given. Not reading config and using default device_uuid"
            );
            Ok(LocalConfigData::default())
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    common::init::netdebug_init();

    let args = Args::parse();
    let config_data = get_local_config(args.local_config_file.clone()).unwrap_or_else(|err| {
        panic!(
            "Failed to read config file `{:?}`: {}",
            args.local_config_file, err
        )
    });
    info!("Successfully read local config: {:?}", config_data);
    let system_epoch = std::time::Instant::now();

    // Getting tokio RuntimeMetrics only works if we have tokio_unstable defined
    let metrics = tokio::runtime::Handle::current().metrics();
    // are we really, really running the multi-threaded runtime?
    info!(
        "Current tokio scheduler flavor is: {:?} with {} workers",
        tokio::runtime::Handle::current().runtime_flavor(),
        metrics.num_workers()
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

    let (topology_rpc_client, data_storage_client) = TopologyServerConnection::spawn(
        args.topology_server_url.clone(),
        MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
        std::time::Duration::from_secs(30),
        config_data.device_uuid,
        counter_registries.registries(),
        counter_registries.new_registry("topology_server_connection"),
    );
    trackers.topology_rpc_client = Some(topology_rpc_client.clone());
    trackers.data_storage_client = Some(data_storage_client.clone());

    let system_tracker = Arc::new(RwLock::new(
        SystemTracker::new(
            counter_registries.new_registry("system_tracker"),
            1024, /* max network histories to keep */
            1024, /* max pings per gateway to keep */
            connection_tracker_tx.clone(),
            prober_tx.clone(),
            Some(data_storage_client.clone()),
        )
        .await,
    ));
    SystemTracker::spawn_system_tracker_background_tasks(
        system_tracker.clone(),
        std::time::Duration::from_millis(500),
    );
    trackers.system_tracker = Some(system_tracker.clone());

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
        Some(data_storage_client.clone()),
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
    let data_storage_client_clone = data_storage_client.clone();
    let _connection_tracker_task = tokio::spawn(async move {
        let args = args_clone;
        // Spawn a ConnectionTracker task
        let mut connection_tracker = ConnectionTracker::new(
            Some(data_storage_client_clone),
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
    spawn_pcap_monitor_all_interfaces(pcap_options);

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

#[cfg(test)]
mod test {
    use std::{
        fs::File,
        io::{ErrorKind, Write},
        str::FromStr,
    };

    use super::*;
    use temp_dir::{self, TempDir};

    #[test]
    fn test_get_config() {
        assert_eq!(get_local_config(None).unwrap(), LocalConfigData::default());

        let res = get_local_config(Some("/does/not/exist".to_owned()));
        assert!(res.is_err());
        match res.unwrap_err() {
            LocalConfigError::Io(io_err) => assert_eq!(io_err.kind(), ErrorKind::NotFound),
            _ => panic!("unexpected error"),
        }
        let tempdir = TempDir::new().unwrap();

        // An empty file should error
        let empty_file = tempdir.child("an-empty-file").to_str().unwrap().to_owned();
        File::create(empty_file.clone()).unwrap();
        let res = get_local_config(Some(empty_file));
        match res.unwrap_err() {
            LocalConfigError::InvalidConfig(_) => (),
            _ => panic!("unexpected error"),
        }

        // not having a device_uuid should be an error
        let config_file = tempdir.child("config.json").to_str().unwrap().to_owned();
        File::create(config_file.clone())
            .unwrap()
            .write_all("{ \"accepted_eula_version\": 3 }".as_bytes())
            .unwrap();

        let res = get_local_config(Some(config_file.clone()));
        match res.unwrap_err() {
            LocalConfigError::InvalidConfig(_) => (),
            _ => panic!("unexpected error"),
        }

        // Now test with a proper config:
        File::create(config_file.clone())
            .unwrap()
            .write_all("{ \"device_uuid\": \"d92bdbe2-cdd1-47d9-a1fb-3d9dc84d310f\" }".as_bytes())
            .unwrap();

        let config_data = get_local_config(Some(config_file.clone())).unwrap();
        assert_eq!(config_data.accepted_eula_version, None);
        assert_eq!(
            config_data.device_uuid,
            Uuid::from_str("d92bdbe2-cdd1-47d9-a1fb-3d9dc84d310f").unwrap()
        );
    }
}
