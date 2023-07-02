use std::{fmt::Display, net::IpAddr};

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

pub const PROBE_MAX_TTL: u8 = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    VersionCheck {
        git_hash: String,
    },
    // Initial message from server
    Ping1FromServer {
        server_timestamp_ms: f64,
    },
    // Client replies, copying server_timestamp_ns back and attaching its own ts
    Ping2FromClient {
        server_timestamp_ms: f64,
        client_timestamp_ms: f64,
    },
    // Final reply from server, echoing client's ts back to it
    // and server_rtt = server recv - server_timestamp_us
    Ping3FromServer {
        server_rtt: f64,
        client_timestamp_ms: f64,
    },
    ProbeReport {
        report: ProbeReport,
        probe_round: u32,
    },
}

impl Message {
    pub fn make_version_check() -> Message {
        Message::VersionCheck {
            git_hash: env!("GIT_HASH").to_string(),
        }
    }

    pub fn check_version(git_hash: &String) -> bool {
        // Note that the webserver, the webclient, and this library
        // should all use the same GIT_HASH and this is created
        // at compile time by build.rs
        git_hash == env!("GIT_HASH")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeReport {
    pub report: Vec<ProbeReportEntry>,
}

impl Display for ProbeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (probe_id, e) in self.report.iter().enumerate() {
            writeln!(f, "Probe {:3} - {:?}", probe_id + 1, e)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProbeReportEntry {
    // the notion of 'comment' might get abused - consider strongly typing everything(?)
    ReplyFound {
        ttl: u8,
        out_timestamp_ms: f64,
        rtt_ms: f64,
        src_ip: IpAddr,
        comment: String,
    },
    NoReply {
        ttl: u8,
        out_timestamp_ms: f64,
        comment: String,
    },
    NoOutgoing {
        ttl: u8,
        comment: String,
    },
    ReplyNoProbe {
        ttl: u8,
        in_timestamp_ms: f64,
        src_ip: IpAddr,
        comment: String,
    },
    // TODO: add GoodRR etc. for w/ Record Route
}

impl ProbeReport {
    pub fn new(report: Vec<ProbeReportEntry>) -> ProbeReport {
        ProbeReport { report }
    }
}
