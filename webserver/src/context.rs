use std::{collections::HashSet, error::Error, net::IpAddr, sync::Arc};

use clap::Parser;
use log::info;
use pwhash::{sha512_crypt, HashSetup};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc::UnboundedSender, RwLock};

use crate::{
    connection::{ConnectionTracker, ConnectionTrackerMsg},
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
    pub send_idle_probes: bool,             // should we also probe when the connection is idle?
    pub max_connections_per_tracker: usize, // how big to make the LruCache
    pub log_dir: String,                    // where to put connection logfiles
    // communications channel to the connection_tracker
    // TODO: make a pool for multi-threading
    pub connection_tracker: UnboundedSender<ConnectionTrackerMsg>,
}

impl WebServerContext {
    pub fn new(args: &Args) -> Result<WebServerContext, Box<dyn Error>> {
        let pcap_device = match &args.pcap_device {
            Some(d) => lookup_pcap_device_by_name(&d)?,
            None => {
                if args.production {
                    crate::pcap::lookup_egress_device()?
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
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let context = WebServerContext {
            user_db: UserDb::new(),
            html_root: args.html_root.clone(),
            wasm_root: args.wasm_root.clone(),
            pcap_device,
            local_tcp_listen_port: args.listen_port,
            local_ips: local_ips,
            connection_tracker: tx,
            send_idle_probes: args.send_idle_probes,
            max_connections_per_tracker: args.max_connections_per_tracker,
            log_dir: args.log_dir.clone(),
        };

        if let Err(e) = check_log_dir(&context.log_dir) {
            log::error!("Failed to create log_dir {} :: {}", context.log_dir, e);
            std::process::exit(1); // fatal error
        }
        let context_clone = Arc::new(RwLock::new(context.clone()));
        // Spawn a ConnectionTracker task
        // TODO Spawn lots for multi-processing
        if !args.web_server_only {
            tokio::spawn(async move {
                info!("Launching the connection tracker (single instance for now)");
                let raw_sock = bind_writable_pcap(&context_clone).await.unwrap();
                let mut connection_tracker =
                    ConnectionTracker::new(context_clone, local_addrs, raw_sock).await;
                connection_tracker.rx_loop(rx).await;
            });
        }

        Ok(context)
    }
}

/**
 * Try to create if it doesn't exist
 */

fn check_log_dir(log_dir: &str) -> Result<(), std::io::Error> {
    let path = std::path::Path::new(log_dir);
    if !path.is_dir() {
        std::fs::create_dir(log_dir)
    } else {
        Ok(())
    }
}

/// Simple program to greet a person
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

    /// Should we send extra probes when the connection is idle? BUGGY!
    #[arg(long, default_value_t = false)]
    pub send_idle_probes: bool,

    /// Where to write connection log files?  Will create if doesn't exist
    #[arg(long, default_value = "logs")]
    pub log_dir: String,

    /// How big to make the LRU Cache on each ConnectionTracker
    #[arg(long, default_value_t = 4096)]
    pub max_connections_per_tracker: usize,
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
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        Arc::new(RwLock::new(WebServerContext {
            user_db: UserDb::testing_demo(test_hash),
            html_root: "html".to_string(),
            wasm_root: "web-client/pkg".to_string(),
            pcap_device: crate::pcap::lookup_egress_device().unwrap(),
            local_tcp_listen_port: 3030,
            local_ips: HashSet::new(),
            connection_tracker: tx,
            send_idle_probes: false,
            max_connections_per_tracker: 4096,
            log_dir: ".".to_string(),
        }))
    }
}
