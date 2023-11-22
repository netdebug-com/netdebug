use std::{collections::HashMap, net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};

use crate::ConnectionMeasurements;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DesktopToTopologyServer {
    Hello,
    StoreConnectionMeasurement {
        connection_measurements: Box<ConnectionMeasurements>,
    },
    InferCongestion {
        connection_measurements: Vec<ConnectionMeasurements>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TopologyServerToDesktop {
    Hello {
        client_ip: IpAddr,
        user_agent: String,
    },
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CongestedLinkKey {
    /// The start of the link
    pub src_ip: IpAddr,
    /// The other side/end of the 'link'
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CongestionLatencyPair {
    pub src_rtt: Duration,
    pub dst_rtt: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CongestedLink {
    /// The src + dst IPs and distance between them for this congested link
    pub key: CongestedLinkKey,
    /// The latency measurements to the src_ip from a common origin, see Note above
    pub latencies: Vec<CongestionLatencyPair>,
    /// The average latency from src to dst (subtracking src from dst latency)
    pub mean_latency: Option<Duration>,
    /// The peak latency from src to dst (subtracking src from dst latency)
    pub peak_latency: Option<Duration>,
    /// Peak-to-mean congestion heuristic - higher number --> more congestion
    pub peak_to_mean_congestion_heuristic: Option<f64>,
    /* TODO: once we have geolocation data for the IPs, return the latencies relative to speed of light times */
}

impl CongestedLink {
    pub fn new(key: CongestedLinkKey) -> CongestedLink {
        CongestedLink {
            key,
            latencies: Vec::new(),
            mean_latency: None,
            peak_latency: None,
            peak_to_mean_congestion_heuristic: None,
        }
    }
    /**
     * First, links with the congestion heuristic defined
     * appear before ones that do not.
     * If both define the congestion heuristic, then order by degree of congestion (high to low)
     * else, if neither define it, tie break on the key
     *
     * For use with Itertools::sorted_by(), e.g.,
     * let links = vec![...];
     * let most_congested = links.sorted_by(CongestionLink::cmp_by_heuristic).first();
     */
    pub fn cmp_by_heuristic(a: &&mut CongestedLink, b: &&mut CongestedLink) -> std::cmp::Ordering {
        match (
            a.peak_to_mean_congestion_heuristic,
            b.peak_to_mean_congestion_heuristic,
        ) {
            (None, None) => a
                .key
                .src_to_dst_hop_count
                .cmp(&b.key.src_to_dst_hop_count)
                .then(a.key.cmp(&b.key)),
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(a_cong), Some(b_cong)) => {
                // be careful how we handle cmp() with f64
                b_cong
                    .partial_cmp(&a_cong)
                    .expect("Congestion heuristic should never be NaN/0")
            }
        }
    }
}

/**
 * A collection of information about congested linked.  
 */

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CongestionSummary {
    pub links: HashMap<CongestedLinkKey, CongestedLink>,
    // TODO: add an Overall Congestion score based on number of paths that are congested and by how much
}
