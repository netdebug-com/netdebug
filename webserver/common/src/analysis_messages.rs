use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AnalysisInsights {
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

impl std::fmt::Display for AnalysisInsights {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]

pub enum Goodness {
    VeryBad,
    Bad,
    Meh,
    Good,
    VeryGood,
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
