use std::{fmt::Display, net::IpAddr, time::Duration};

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use typescript_type_def::TypeDef;

use crate::{
    AggregatedGatewayPingData, ConnectionKey, ConnectionMeasurements, DnsTrackerEntry,
    NetworkInterfaceState,
};

#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug, Serialize, Deserialize, TypeDef)]
pub enum DesktopLogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl Display for DesktopLogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use DesktopLogLevel::*;
        match self {
            Error => write!(f, "ERROR"),
            Warn => write!(f, "WARN"),
            Info => write!(f, "INFO"),
            Debug => write!(f, "DEBUG"),
        }
    }
}

/// Messages sent over the websocket from the desktop app (both
/// rust and electron) to the topology server.
#[derive(Clone, Debug, Serialize, Deserialize, TypeDef)]
#[serde(tag = "tag", content = "data")]
pub enum DesktopToTopologyServer {
    Hello,
    StoreConnectionMeasurement {
        connection_measurements: Box<ConnectionMeasurements>,
    },
    InferCongestion {
        connection_measurements: Vec<ConnectionMeasurements>,
    },
    PushCounters {
        #[type_def(type_of = "String")]
        timestamp: DateTime<Utc>,
        #[type_def(type_of = "std::collections::HashMap<String, u64>")]
        counters: IndexMap<String, u64>,
        os: String,
        version: String,
        #[serde(default)]
        client_id: String,
    },
    PushLog {
        #[type_def(type_of = "String")]
        timestamp: DateTime<Utc>,
        level: DesktopLogLevel,
        scope: String,
        msg: String,
        os: String,
        version: String,
        client_id: String,
    },
    PushNetworkInterfaceState {
        network_interface_state: NetworkInterfaceState,
    },
    PushGatewayPingData {
        ping_data: Vec<AggregatedGatewayPingData>,
    },
    PushDnsEntries {
        dns_entries: Vec<DnsTrackerEntry>,
    },
    Ping,
}

/// Messages sent over the websocket from the web/topology server back
/// to the desktop app.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TopologyServerToDesktop {
    Hello {
        client_ip: IpAddr,
        user_agent: String,
    },
    InferCongestionReply {
        congestion_summary: CongestionSummary,
    },
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, TypeDef)]
pub struct CongestedLinkKey {
    /// The hop-count from the origin to the src_ip
    pub src_hop_count: u8,
    /// The start of the link
    #[type_def(type_of = "String")]
    pub src_ip: IpAddr,
    /// The other side/end of the 'link'
    #[type_def(type_of = "String")]
    pub dst_ip: IpAddr,
    /// The number of router hops/ttl between the two
    pub src_to_dst_hop_count: u8,
}

/**
 * A CongestedLink tracks the latency and latency variance
 * between two router/ttl hops.  They maybe directly
 * connected, e.g., src_to_dst_hop_count=1, or indirectly
 * connected (e.g., if we don't have data for routers inbetween).
 *
 * Higher variation in latency implies higher congestion!
 *
 * CongestedLink's are uni-directional: the link from A-->B may
 * be more or less congested than the link from B-->A
 *
 * NOTE: src_latencies and dst_latencies Vec<>'s will always have
 * the same size and are indexed so that src_latency[i] and dst_latency[i]
 * will come from the same packet train/time so that they can be compared
 * directly.
 *
 */

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TypeDef)]
pub struct CongestionLatencyPair {
    /// Round-trip time from the origin to the first part of the link
    #[type_def(type_of = "u64")]
    #[serde_as(as = "serde_with::DurationMicroSeconds<u64>")]
    #[serde(rename = "src_rtt_us")]
    pub src_rtt: Duration,
    /// Round-trip time from the origin to the second part of the link
    #[type_def(type_of = "u64")]
    #[serde_as(as = "serde_with::DurationMicroSeconds<u64>")]
    #[serde(rename = "dst_rtt_us")]
    pub dst_rtt: Duration,

    /// which connection did this come from?  Might want to include a
    /// 'start_time' here as well to better uniquely identify it but
    /// hopefully ok for now
    pub connection_key: ConnectionKey,
    /// Which probe-round did this come from?
    pub probe_round: u32,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, TypeDef)]
pub struct CongestedLink {
    /// The src + dst IPs and distance between them for this congested link
    pub key: CongestedLinkKey,
    /// The latency measurements to the src_ip from a common origin, see Note above
    pub latencies: Vec<CongestionLatencyPair>,
    /// The average latency from src to dst (subtracking src from dst latency)
    #[type_def(type_of = "Option<u64>")]
    #[serde_as(as = "Option<serde_with::DurationMicroSeconds<u64>>")]
    #[serde(rename = "mean_latency_us")]
    pub mean_latency: Option<Duration>,
    /// The peak latency from src to dst (subtracking src from dst latency)
    #[type_def(type_of = "Option<u64>")]
    #[serde_as(as = "Option<serde_with::DurationMicroSeconds<u64>>")]
    #[serde(rename = "peak_latency_us")]
    pub peak_latency: Option<Duration>,
    /* TODO: once we have geolocation data for the IPs, return the latencies relative to speed of light times */
}

impl CongestedLink {
    pub fn new(key: CongestedLinkKey) -> CongestedLink {
        CongestedLink {
            key,
            latencies: Vec::new(),
            mean_latency: None,
            peak_latency: None,
        }
    }
}

/**
 * A collection of information about congested linked.  
 */

#[derive(Clone, Debug, Default, Serialize, Deserialize, TypeDef)]
pub struct CongestionSummary {
    pub links: Vec<CongestedLink>,
    // TODO: add an Overall Congestion score based on number of paths that are congested and by how much
}
