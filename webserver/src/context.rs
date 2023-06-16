use std::{error::Error, sync::Arc};

use clap::Parser;
use pwhash::{sha512_crypt, HashSetup};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

// All of the web server state that's maintained across
// parallel threads.  This will be wrapped in an
// Arc::new(Mutex::new(...)) for thread and borrower checker
// safety
#[derive(Debug, Clone)]
pub struct WebServerContext {
    pub user_db: UserDb,
    pub html_root: String,
    pub wasm_root: String,
    pub pcap_device: pcap::Device,
}

impl WebServerContext {
    pub fn new(args: &Args) -> Result<WebServerContext, Box<dyn Error>> {
        let pcap_device = match &args.pcap_device {
            Some(d) => crate::pcap::lookup_pcap_device_by_name(&d)?,
            None => crate::pcap::lookup_egress_device()?,
        };
        Ok(WebServerContext {
            user_db: UserDb::new(),
            html_root: args.html_root.clone(),
            wasm_root: args.wasm_root.clone(),
            pcap_device,
        })
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
