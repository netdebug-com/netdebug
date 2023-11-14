use libconntrack_wasm::{
    aggregate_counters::{AggregateCounterKind, TrafficCounters},
    ConnectionMeasurements, DnsTrackerEntry,
};
/**
 * Anything in this file must compile for both native rust/x86 AND WASM
 *
 * So no thread, deep OS calls, etc. here
 */
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};
use typescript_type_def::TypeDef;

pub fn get_git_hash_version() -> String {
    env!("GIT_HASH").to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerToGuiMessages {
    VersionCheck(String),
    DumpFlowsReply(Vec<ConnectionMeasurements>),
    DumpDnsCache(HashMap<IpAddr, DnsTrackerEntry>),
    DumpAggregateCountersReply(TrafficCounters),
    DumpStatCountersReply(HashMap<String, u64>),
    DumpDnsAggregateCountersReply(
        HashMap<AggregateCounterKind, (TrafficCounters, Vec<ConnectionMeasurements>)>,
    ),
    WhatsMyIpReply {
        ip: IpAddr,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TypeDef)]
pub enum GuiToServerMessages {
    DumpFlows(),
    DumpDnsCache(),
    DumpAggregateCounters(),
    DumpStatCounters(),
    DumpDnsAggregateCounters(),
    WhatsMyIp(),
}

#[cfg(test)]
mod test {
    use crate::GuiToServerMessages;

    #[test]
    fn test_message_json() {
        println!(
            "{}",
            serde_json::to_string(&GuiToServerMessages::DumpDnsCache()).unwrap()
        );
    }
}
