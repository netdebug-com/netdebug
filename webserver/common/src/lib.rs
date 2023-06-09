/**
 * Attention: everything in this library (including transitively) must
 * complile for both native rust as well as for WASM, so:
 * 1) No Threads
 * 2) No System dependencies (e.g., clocks)
 * 3) Probably more things
 *
 * Might want to consider moving this to Google Protobufs so we can
 * get forwards and backwards compatibility, but for now we can do a version
 * check at the start and reload the client if need be.
 */
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    VersionCheck {
        git_hash: String,
    },
    // Initial message from server
    Ping1FromServer {
        server_timestamp_us: f64,
    },
    // Client replies, copying server_timestamp_ns back and attaching its own ts
    Ping2FromClient {
        server_timestamp_us: f64,
        client_timestamp_us: f64,
    },
    // Final reply from server, echoing client's ts back to it
    Ping3FromServer {
        client_timestamp_us: f64,
    },
}

impl Message {
    pub fn make_version_check() -> Message {
        Message::VersionCheck {
            git_hash: env!("GIT_HASH").to_string(),
        }
    }

    pub fn check_version(git_hash: String) -> bool {
        // Note that the webserver, the webclient, and this library
        // should all use the same GIT_HASH and this is created
        // at compile time by build.rs
        git_hash == env!("GIT_HASH")
    }
}
