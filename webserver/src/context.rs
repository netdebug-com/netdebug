use std::{
    collections::HashSet, error::Error, net::IpAddr, str::FromStr, sync::Arc, time::Duration,
};

use clap::Parser;
use common_wasm::timeseries_stats::{SharedExportedStatRegistries, SuperRegistry};
use log::info;
use pwhash::{sha512_crypt, HashSetup};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use libconntrack::{
    connection_tracker::{ConnectionTracker, ConnectionTrackerSender},
    pcap::{bind_writable_pcap, lookup_pcap_device_by_name},
    prober::spawn_raw_prober,
    topology_client::TopologyRpcSender,
};
use uuid::Uuid;

use crate::{
    remotedb_client::{RemoteDBClient, RemoteDBClientSender},
    secrets_db::Secrets,
    spawn_webserver_connection_log_wrapper, topology_server,
};

/// We use a v5 NAMESPACE_DNS UUID as the "device_uuid" for connections we log from the
/// webserver (i.e., webtest connections).
/// The final UUID for this is: fa7825d6-6905-5acd-a29f-69be8d81c330
const UUID_DNS_NAME_FOR_SERVER_CONN: &[u8] = b"topology.netdebug.com";

// All of the web server state that's maintained across
// parallel threads.  This will be wrapped in an
// Arc::new(Mutex::new(...)) for thread and borrower checker
// safety
#[derive(Debug, Clone)]
pub struct WebServerContext {
    pub user_db: UserDb,                    // only used for demo auth for now
    pub html_root: String,                  // path to "html" directory
    pub wasm_root: String,                  // path to wasm pkg directory
    pub pcap_device: pcap::Device,          // which ethernet device are we capturing from?
    pub local_tcp_listen_port: u16,         // what port are we listening on?
    pub local_ips: HashSet<IpAddr>,         // which IP addresses do we listen on?
    pub max_connections_per_tracker: usize, // how big to make the LruCache
    // communications channel to the connection_tracker
    // TODO: make a pool for multi-threading
    pub connection_tracker: ConnectionTrackerSender,
    pub topology_server: TopologyRpcSender,
    pub counter_registries: SharedExportedStatRegistries,
    pub remotedb_client: Option<RemoteDBClientSender>,
    /// All of the shared secrets needed for off-box services
    /// Assumes that the only people with access to the machine/binary/file are NetDebug employees
    pub secrets: Secrets,
    /// Are we running in production or dev mode?
    pub production: bool,
}

const MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE: usize = 8192;
const MAX_MSGS_PER_TOPOLOGY_SERVER_QUEUE: usize = 8192;

impl WebServerContext {
    pub fn new(args: &Args) -> Result<WebServerContext, Box<dyn Error>> {
        let secrets = match Secrets::from_toml_file(&args.secrets_file) {
            Ok(s) => s,
            Err(e) => panic!(
                "Error loading the secrets file {} :: {}",
                &args.secrets_file, e
            ),
        };
        let pcap_device = match &args.pcap_device {
            Some(d) => lookup_pcap_device_by_name(d)?,
            None => {
                if args.production {
                    libconntrack::pcap::lookup_egress_device()?
                } else {
                    // if we're not in production mode, just capture
                    // loopback traffic.
                    let loopback_if_name = match std::env::consts::OS {
                        "linux" =>"lo",
                        "windows" => "\\Device\\NPF_Loopback",
                        "macos" => "lo0",
                        _unknown => panic!(
                            "Unsupported OS type \"{}\" ; don't know loopback interface name; specify manually", 
                            _unknown),

                    }.to_string();
                    lookup_pcap_device_by_name(&loopback_if_name)?
                }
            }
        };
        let mut local_ips = HashSet::new();
        for a in &pcap_device.addresses {
            local_ips.insert(a.addr);
        }
        // windows localhost NPF_Loopback doesn't allocate IPs on the virtual interface!
        // so manually add them
        if !args.production && std::env::consts::OS == "windows" && local_ips.is_empty() {
            local_ips.extend([
                IpAddr::from_str("127.0.0.1").unwrap(),
                IpAddr::from_str("::1").unwrap(),
            ])
        }
        if local_ips.is_empty() {
            return Err(format!(
                "Didn't find any local IP addresses on interface {}",
                pcap_device.name
            )
            .into());
        }

        let mut counter_registries = SuperRegistry::new(std::time::Instant::now());
        let conn_track_counter = counter_registries.new_registry("conn_track");
        // create a connection tracker
        //
        let (tx, rx) = tokio::sync::mpsc::channel(MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE);
        let (topology_server_tx, topology_server_rx) =
            tokio::sync::mpsc::channel(MAX_MSGS_PER_TOPOLOGY_SERVER_QUEUE);
        let remotedb_client = if args.no_timescaledb {
            None
        } else {
            Some(
                RemoteDBClient::spawn(
                    secrets.clone(),
                    MAX_MSGS_PER_TOPOLOGY_SERVER_QUEUE,
                    Duration::from_secs(5),
                    counter_registries.new_registry("remotedb_client"),
                )
                .unwrap(),
            )
        };
        let remotedb_client_clone = remotedb_client.clone();
        let context = WebServerContext {
            user_db: UserDb::new(),
            html_root: args.html_root.clone(),
            wasm_root: args.wasm_root.clone(),
            pcap_device,
            local_tcp_listen_port: args.listen_port,
            local_ips: local_ips.clone(),
            connection_tracker: tx.clone(),
            topology_server: topology_server_tx.clone(),
            max_connections_per_tracker: args.max_connections_per_tracker,
            counter_registries: counter_registries.registries(),
            remotedb_client,
            secrets,
            production: args.production,
        };

        // TODO Spawn lots for multi-processing
        if !args.web_server_only {
            let max_connections_per_tracker = context.max_connections_per_tracker;
            // Spawn a ConnectionTracker task
            let db_path = args.topology_server_db_path.clone();
            tokio::spawn(async move {
                info!("Launching the topology server now with db_path={}", db_path);
                topology_server::TopologyServer::spawn_with_tx_rx(
                    topology_server_tx.clone(),
                    topology_server_rx,
                )
                .await
                .unwrap();
                let optional_conn_storage_tx = remotedb_client_clone.map(|db| {
                    spawn_webserver_connection_log_wrapper(
                        db,
                        Uuid::new_v5(&Uuid::NAMESPACE_DNS, UUID_DNS_NAME_FOR_SERVER_CONN),
                    )
                });
                let prober_tx = spawn_raw_prober(
                    bind_writable_pcap(local_ips.clone()),
                    MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
                );
                info!("Launching the connection tracker (single instance for now)");
                let mut connection_tracker = ConnectionTracker::new(
                    optional_conn_storage_tx,
                    max_connections_per_tracker,
                    local_ips,
                    prober_tx,
                    MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
                    conn_track_counter,
                    // the webserver doesn't need rate limiting
                    true,
                );
                connection_tracker.set_tx_rx(tx, rx);
                let _ret: () = connection_tracker.rx_loop().await;
            });
        }

        Ok(context)
    }
}

/// Netdebug webserver
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Used to enable production flags vs. (default) dev mode
    /// production implies https unless '--force-unencrypted-http' is set
    #[arg(long)]
    pub production: bool,

    /// DANGER: override default and allow --production with unencrypted http
    #[arg(long, default_value_t = false)]
    pub force_unencrypted: bool,

    /// Fully qualified path to TLS Certificate (use Certbot!)
    #[arg(
        long,
        default_value = "/etc/letsencrypt/live/topology.netdebug.com/fullchain.pem"
    )]
    pub tls_cert: String,

    /// Fully qualified path to TLS private key (use Certbot!)
    #[arg(
        long,
        default_value = "/etc/letsencrypt/live/topology.netdebug.com/privkey.pem"
    )]
    pub tls_key: String,

    /// the base of the HTML directory, e.g., where index.html lives
    #[arg(long, default_value = "webserver/html")]
    pub html_root: String,

    /// the base of the WASM build directory, where web-client{.js,_bs.wasm} live
    #[arg(long, default_value = "webserver/web-client/pkg")]
    pub wasm_root: String,

    /// which TCP port to listen on
    #[arg(long, default_value_t = 3030)]
    pub listen_port: u16,

    /// which pcap device to listen on; default is autodetect
    #[arg(long, default_value = None)]
    pub pcap_device: Option<String>,

    /// Web-server only - no libpcap probing
    #[arg(long, default_value_t = false)]
    pub web_server_only: bool,

    /// How big to make the LRU Cache on each ConnectionTracker
    #[arg(long, default_value_t = 4096)]
    pub max_connections_per_tracker: usize,

    /// The SQLite db path, e.g., a filename
    #[arg(long, default_value = "./connections.sqlite3")]
    pub topology_server_db_path: String,

    /// The path to the shared secrets file - SSH!
    #[arg(long, default_value = ".secrets.toml")]
    pub secrets_file: String,

    /// If set, the remote timescaledb will not be used.
    #[arg(long, default_value_t = false)]
    pub no_timescaledb: bool,
}

pub type Context = Arc<RwLock<WebServerContext>>;

pub const COOKIE_LOGIN_NAME: &str = "DEMO_COOKIE";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginInfo {
    pub user: String,
    pub passwd: String,
}

// for now, just use a password to block people from accessing
// the demo
#[derive(Debug, Clone)]
pub struct UserDb {
    demo_password_hash: String,
}

impl UserDb {
    fn new() -> UserDb {
        UserDb {
            // TODO: fix with better password
            demo_password_hash: "$6$rounds=1000$R3CbOV3p683eA3ec$gL1sOOmUjfDcY7ahAz.vqjNvG.klg02IIIwGV0hUZIzaR7h4JRhvpM5idfssULVh6DFNItcXWKYc8Pqz2olZd1"
                .to_string(),
        }
    }

    /**
     * Only used for testing
     */
    pub fn testing_demo(hash: String) -> UserDb {
        UserDb {
            demo_password_hash: hash,
        }
    }

    pub fn new_password(passwd: &str) -> Result<String, pwhash::error::Error> {
        // generate a random salt
        let salt: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16) // function only looks at first 16 chars
            .map(char::from)
            .collect();
        let hash_params = HashSetup {
            salt: Some(salt.as_str()),
            rounds: Some(6),
        };

        sha512_crypt::hash_with(hash_params, passwd)
    }

    pub fn validate_password(&self, _user: &str, passwd: &str) -> bool {
        // no 'users' yet - just test password
        sha512_crypt::verify(passwd, self.demo_password_hash.as_str())
    }

    pub fn generate_auth_cooke(&self, _user: &str) -> String {
        // TODO - fix when we need real auth
        "SUCCESS".to_string()
    }

    /**
     * Did the user provide a correctly authorized cookie?
     */
    pub fn validate_cookie(&self, cookie: String) -> bool {
        cookie == "SUCCESS"
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    use crate::context::{UserDb, WebServerContext};
    use std::{sync::Arc, time::Instant};
    use tokio::sync::RwLock;

    pub const TEST_PASSWD: &str = "test";
    pub fn make_test_context() -> Context {
        let test_pass = TEST_PASSWD;
        let test_hash = UserDb::new_password(test_pass).unwrap();
        // create trackers but don't connect them to anything...
        let (connection_tracker_tx, _rx) = tokio::sync::mpsc::channel(128);
        let (topology_server_tx, _rx) = tokio::sync::mpsc::channel(128);
        let (remotedb_client, _rx) = tokio::sync::mpsc::channel(128);
        let counter_registries = SuperRegistry::new(Instant::now()).registries();
        Arc::new(RwLock::new(WebServerContext {
            user_db: UserDb::testing_demo(test_hash),
            html_root: "html".to_string(),
            wasm_root: "web-client/pkg".to_string(),
            pcap_device: libconntrack::pcap::lookup_egress_device().unwrap(),
            local_tcp_listen_port: 3030,
            local_ips: HashSet::new(),
            connection_tracker: connection_tracker_tx,
            topology_server: topology_server_tx,
            max_connections_per_tracker: 4096,
            counter_registries,
            remotedb_client: Some(remotedb_client),
            secrets: Secrets::default(),
            production: false,
        }))
    }

    #[test]
    fn uuid_for_webserver_conn_log() {
        let expected = "fa7825d6-6905-5acd-a29f-69be8d81c330";
        assert_eq!(
            Uuid::new_v5(&Uuid::NAMESPACE_DNS, UUID_DNS_NAME_FOR_SERVER_CONN),
            Uuid::from_str(expected).unwrap()
        );
    }
}
