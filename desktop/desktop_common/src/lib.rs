use std::{collections::HashMap, net::IpAddr};

use libconntrack_wasm::{
    topology_server_messages::CongestionSummary, AggregateStatEntry, ChartJsBandwidth,
    ConnectionMeasurements, DnsTrackerEntry, NetworkInterfaceState,
};
/**
 * Anything in this file must compile for both native rust/x86 AND WASM
 *
 * So no thread, deep OS calls, etc. here
 */
use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef;

pub fn get_git_hash_version() -> String {
    env!("GIT_HASH").to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, TypeDef)]
#[serde(tag = "tag", content = "data")]
pub enum DesktopToGuiMessages {
    VersionCheck(String),
    DumpFlowsReply(Vec<ConnectionMeasurements>),
    DumpDnsCache(HashMap<IpAddr, DnsTrackerEntry>),
    DumpAggregateCountersReply(Vec<ChartJsBandwidth>),
    DumpStatCountersReply(HashMap<String, u64>),
    DumpDnsAggregateCountersReply(Vec<AggregateStatEntry>),
    WhatsMyIpReply {
        ip: IpAddr,
    },
    CongestedLinksReply {
        congestion_summary: CongestionSummary,
        connection_measurements: Vec<ConnectionMeasurements>,
    },
    DumpSystemNetworkHistoryReply {
        network_interface_history: Vec<NetworkInterfaceState>,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TypeDef)]
pub struct CongestedLinksReply {
    pub congestion_summary: CongestionSummary,
    pub connection_measurements: Vec<ConnectionMeasurements>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TypeDef)]
#[serde(tag = "tag")]
pub enum GuiToDesktopMessages {
    DumpFlows,
    DumpDnsCache,
    DumpAggregateCounters,
    DumpStatCounters,
    DumpDnsAggregateCounters,
    DumpSystemNetworkHistory,
    WhatsMyIp,
    CongestedLinksRequest,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_message_json() {
        println!(
            "{}",
            serde_json::to_string(&GuiToDesktopMessages::DumpDnsCache).unwrap()
        );
    }
}
