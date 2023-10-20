use std::{collections::HashSet, error::Error, net::IpAddr, sync::Arc};

use clap::Parser;
use log::info;
use pwhash::{sha512_crypt, HashSetup};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use libconntrack::{
    connection::{ConnectionTracker, ConnectionTrackerSender},
    connection_storage_handler::ConnectionStorageHandler,
    in_band_probe::spawn_raw_prober,
    pcap::{bind_writable_pcap, lookup_pcap_device_by_name},
};

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
}

const MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE: usize = 8192;

impl WebServerContext {
    pub fn new(args: &Args) -> Result<WebServerContext, Box<dyn Error>> {
        let pcap_device = match &args.pcap_device {
            Some(d) => lookup_pcap_device_by_name(&d)?,
            None => {
                if args.production {
                    libconntrack::pcap::lookup_egress_device()?
                } else {
                    // if we're not in production mode, just capture
                    // loopback traffic.
                    // TODO: 'lo' is linux specific - lookup for non-Linux
                    lookup_pcap_device_by_name(&"lo".to_string())?
                }
            }
        };
        let mut local_ips = HashSet::new();
        for a in &pcap_device.addresses {
            local_ips.insert(a.addr);
        }
        let local_addrs = local_ips.clone();

        // create a connection tracker
        //
        let (tx, rx) = tokio::sync::mpsc::channel(MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE);
        let context = WebServerContext {
            user_db: UserDb::new(),
            html_root: args.html_root.clone(),
            wasm_root: args.wasm_root.clone(),
            pcap_device,
            local_tcp_listen_port: args.listen_port,
            local_ips: local_ips,
            connection_tracker: tx.clone(),
            max_connections_per_tracker: args.max_connections_per_tracker,
        };

        // TODO Spawn lots for multi-processing
        if !args.web_server_only {
            let (storage_server_url, max_connections_per_tracker, device) = (
                args.storage_server_url.clone(),
                context.max_connections_per_tracker,
                context.pcap_device.clone(),
            );
            // Spawn a ConnectionTracker task
            let storage_service_future = if let Some(url) = storage_server_url {
                Some(ConnectionStorageHandler::spawn_from_url(url, 1000))
            } else {
                None
            };
            tokio::spawn(async move {
                info!("Launching the connection tracker (single instance for now)");
                let storage_service_msg_tx = if let Some(future) = storage_service_future {
                    Some(future.await)
                } else {
                    None
                };
                let prober_tx = spawn_raw_prober(
                    bind_writable_pcap(device).unwrap(),
                    MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
                )
                .await;
                let mut connection_tracker = ConnectionTracker::new(
                    storage_service_msg_tx,
                    max_connections_per_tracker,
                    local_addrs,
                    prober_tx,
                    MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
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
    #[arg(long)]
    pub production: bool,

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

    /// The URL of the GRPC storage server. E.g., http://localhost:50051
    #[arg(long, default_value=None)]
    pub storage_server_url: Option<String>,
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

    pub fn new_password(passwd: &String) -> Result<String, pwhash::error::Error> {
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

    pub fn validate_password(&self, _user: &String, passwd: &String) -> bool {
        // no 'users' yet - just test password
        sha512_crypt::verify(passwd, self.demo_password_hash.as_str())
    }

    pub fn generate_auth_cooke(&self, _user: &String) -> String {
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
    use std::sync::Arc;
    use tokio::sync::RwLock;

    pub const TEST_PASSWD: &str = "test";
    pub fn make_test_context() -> Context {
        let test_pass = TEST_PASSWD;
        let test_hash = UserDb::new_password(&test_pass.to_string()).unwrap();
        // create a connection tracker to nothing for the test context
        let (tx, _rx) = tokio::sync::mpsc::channel(128);
        Arc::new(RwLock::new(WebServerContext {
            user_db: UserDb::testing_demo(test_hash),
            html_root: "html".to_string(),
            wasm_root: "web-client/pkg".to_string(),
            pcap_device: libconntrack::pcap::lookup_egress_device().unwrap(),
            local_tcp_listen_port: 3030,
            local_ips: HashSet::new(),
            connection_tracker: tx,
            max_connections_per_tracker: 4096,
        }))
    }
}
