use libconntrack_wasm::{
    topology_server_messages::{CongestionSummary, DesktopToTopologyServer},
    AggregateStatEntry, ChartJsBandwidth, ConnectionMeasurements, DnsTrackerEntry,
    ExportedNeighborState, NetworkInterfaceState,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, TypeDef)]
pub struct CongestedLinksReply {
    pub congestion_summary: CongestionSummary,
    pub connection_measurements: Vec<ConnectionMeasurements>,
}

// A helper type alias. It list all the types that are used in the UI
pub type GuiApiTypes = (
    ConnectionMeasurements,
    DnsTrackerEntry,
    ChartJsBandwidth,
    AggregateStatEntry,
    CongestedLinksReply,
    NetworkInterfaceState,
    ExportedNeighborState,
    DesktopToTopologyServer,
);
