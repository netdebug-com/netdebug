use std::sync::Arc;

use pwhash::{sha512_crypt, HashSetup};
use rand::{distributions::Alphanumeric, Rng};
use tokio::sync::Mutex;

// All of the web server state that's maintained across
// parallel threads.  This will be wrapped in an
// Arc::new(Mutex::new(...)) for thread and borrower checker
// safety
#[derive(Debug, Clone)]
pub struct WebServerContext {
    pub user_db: UserDb,
}

impl WebServerContext {
    pub fn new() -> WebServerContext {
        WebServerContext {
            user_db: UserDb::new(),
        }
    }
}

pub type Context = Arc<Mutex<WebServerContext>>;

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
            demo_password_hash: "$6$G/gkPn17kHYo0gTF$xhDFU0QYExdMH2ghOWKrrVtu1BuTpNMSJ\
     URCXk43.EYekmK8iwV6RNqftUUC8mqDel1J7m3JEbUkbu4YyqSyv/"
                .to_string(),
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

    pub fn validate_password(self, _user: String, passwd: String) -> bool {
        // no 'users' yet - just test password
        sha512_crypt::verify(passwd, self.demo_password_hash.as_str())
    }
}
