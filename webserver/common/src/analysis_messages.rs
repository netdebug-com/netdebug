use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AnalysisInsights {
    LatencySpikeExplaination {
        typical: ProbeReportLatencies,
        worst: ProbeReportLatencies,
        net_delta: f64,
        endhost_delta: f64,
        processing_delta: f64,
        goodness: Goodness,
        blame: Blame,
    },
    HasNat {
        ttl: u8,
    },
    LatencyNatWeirdData {
        nat_avg: f64,
        endhost_avg: f64,
        nat_max: f64,
        endhost_max: f64,
    },
    LatencyRouterWeirdData {
        router_avg: f64,
        endhost_avg: f64,
        router_max: f64,
        endhost_max: f64,
    },
    LastHopNatLatencyVariance {
        last_hop_avg: f64,
        last_hop_max: f64,
        endhost_avg: f64,
        endhost_max: f64,
        last_hop_avg_fraction: f64,
        last_hop_max_fraction: f64,
        goodness: Goodness,
    },
    LastHopRouterLatencyVariance {
        last_hop_avg: f64,
        last_hop_max: f64,
        endhost_avg: f64,
        endhost_max: f64,
        last_hop_avg_fraction: f64,
        last_hop_max_fraction: f64,
        goodness: Goodness,
    },
    ApplicationLatencyVariance {
        endhost_avg: f64,
        endhost_max: f64,
        application_avg: f64,
        application_max: f64,
        delta_avg: f64,
        delta_max: f64,
        fraction_avg: f64,
        fraction_max: f64,
        goodness: Goodness,
    },
    ApplicationLatencyWeirdVariance {
        endhost_avg: f64,
        endhost_max: f64,
        application_avg: f64,
        application_max: f64,
        delta_avg: f64,
        delta_max: f64,
    },
    MissingOutgoingProbes {
        out_drop_count: usize,
        goodness: Goodness,
    },
    NoEndhostReplies,
    NoRouterReplies,
    NoProbes,
}

impl AnalysisInsights {
    pub fn goodness(&self) -> Option<Goodness> {
        use AnalysisInsights::*;
        match self {
            LatencyNatWeirdData { .. }
            | ApplicationLatencyWeirdVariance { .. }
            | NoEndhostReplies
            | NoRouterReplies
            | NoProbes
            | HasNat { .. }
            | LatencyRouterWeirdData { .. } => None,
            LastHopRouterLatencyVariance { goodness, .. }
            | ApplicationLatencyVariance { goodness, .. }
            | MissingOutgoingProbes { goodness, .. }
            | LatencySpikeExplaination { goodness, .. }
            | LastHopNatLatencyVariance { goodness, .. } => Some(*goodness),
        }
    }

    pub fn name(&self) -> String {
        use AnalysisInsights::*;
        match self {
            LatencyNatWeirdData { .. } => "Latency w/ NAT (weird)",
            LatencyRouterWeirdData { .. } => "Latency w/ Router (weird)",
            LastHopNatLatencyVariance { .. } => "Last-Hop Latency (w/ NAT)",
            LastHopRouterLatencyVariance { .. } => "Last-Mile Latency (w/ Router)",
            ApplicationLatencyVariance { .. } => "Application Latency",
            ApplicationLatencyWeirdVariance { .. } => "Application Latency (weird)",
            MissingOutgoingProbes { .. } => "Missing Test Probes",
            NoEndhostReplies => "No Replies from Endhost (test problem)",
            NoRouterReplies => "No Replies from Routers (test problem)",
            NoProbes => "No probes found at all!? (test problem)",
            HasNat { .. } => "Network Address Translation (NAT) Device",
            LatencySpikeExplaination { .. } => "Latency Spike",
        }
        .to_string()
    }

    pub fn comment(&self) -> String {
        "TODO".to_string()
    }
}

impl std::fmt::Display for AnalysisInsights {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // unwrap might be ok here - unless we allow user input into this
        // TODO: change the error type to something else
        let pretty = serde_json::to_string_pretty(self).unwrap();
        write!(f, "{}", pretty)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Copy, Clone)]

pub enum Goodness {
    VeryBad,
    Bad,
    Meh,
    Good,
    VeryGood,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Blame {
    LastMile,    // for when we don't have a ping from the last hop
    IspNetwork,  // for when we have a ping from the last hop
    HomeNetwork, // could be more generic?  what is it's not a home network?
    HostStack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub struct ProbeReportLatencies {
    pub net_rtt: f64,
    pub net_is_nat: bool,
    pub endhost_avg: f64,
    pub endhost_max: f64,
    pub app_rtt: f64,
    pub processing_delay: f64,
    pub percent_net: f64,
    pub percent_endhost: f64,
    pub percent_processing: f64,
    pub probe_round: u32,
}

impl std::fmt::Display for Goodness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Goodness::VeryBad => write!(f, "VeryBad"),
            Goodness::Bad => write!(f, "Bad"),
            Goodness::Meh => write!(f, "Meh"),
            Goodness::Good => write!(f, "Good"),
            Goodness::VeryGood => write!(f, "VeryGood"),
        }
    }
}
