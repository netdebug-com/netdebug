use libconntrack_wasm::{
    aggregate_counters::TrafficCounters, ConnectionMeasurements, DnsTrackerEntry,
};
/**
 * Anything in this file must compile for both native rust/x86 AND WASM
 *
 * So no thread, deep OS calls, etc. here
 */
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};

pub fn get_git_hash_version() -> String {
    env!("GIT_HASH").to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerToGuiMessages {
    VersionCheck(String),
    DumpFlowsReply(Vec<ConnectionMeasurements>),
    DumpDnsCache(HashMap<IpAddr, DnsTrackerEntry>),
    DumpAggregateCountersReply(TrafficCounters),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuiToServerMessages {
    DumpFlows(),
    DumpDnsCache(),
    DumpAggregateCounters(),
}
