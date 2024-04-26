use chrono::{DateTime, Utc};
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
use uuid::Uuid;

pub fn get_git_hash_version() -> String {
    env!("GIT_HASH").to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TypeDef)]
pub struct CongestedLinksReply {
    pub congestion_summary: CongestionSummary,
    pub connection_measurements: Vec<ConnectionMeasurements>,
}

/// The elements of OrganizationInfo that are safe for anyone to read
/// i.e., "public" in the GUI frontend
#[derive(Debug, Serialize, Deserialize, TypeDef)]
pub struct PublicOrganizationInfo {
    pub id: i64,
    pub name: Option<String>,
    pub description: Option<String>,
    pub admin_contact: Option<String>,
}

pub type OrganizationId = i64;
/// The elements of DeviceInfo that are safe for anyone to read
/// i.e., "public" in the GUI frontend
#[derive(Debug, Serialize, Deserialize, TypeDef, PartialEq, PartialOrd)]
pub struct PublicDeviceInfo {
    /// The unique ID of this device
    #[type_def(type_of = "String")]
    pub uuid: Uuid,
    /// E.g., hostname
    pub name: Option<String>,
    /// Which organization does this belong to by internal ID
    pub organization_id: OrganizationId,
    pub description: Option<String>,
    #[type_def(type_of = "String")]
    pub created: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, TypeDef, PartialEq, PartialOrd)]
pub struct PublicDeviceDetails {
    /// Details is a superset of DeviceInfo
    pub device_info: PublicDeviceInfo,
    /// Number of flows for this device in DB
    pub num_flows_stored: u64,
    /// Number of with sent packet loss; None if No flows
    pub num_flows_with_send_loss: Option<u64>,
    /// Number of with recv packet loss; None if No flows
    pub num_flows_with_recv_loss: Option<u64>,
    /// Timestamp of the oldest flow; None if No flows
    #[type_def(type_of = "String")]
    pub oldest_flow_time: Option<DateTime<Utc>>,
    /// Timestamp of the newest flow; None if No flows
    #[type_def(type_of = "String")]
    pub newest_flow_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, TypeDef)]
pub struct FirstHopPacketLossReportEntry {
    #[type_def(type_of = "String")]
    /// Unique ID of the Device
    pub device_uuid: Uuid,
    /// Name of Device
    pub device_name: Option<String>,
    pub device_description: Option<String>,
    /// Number of outgoing ICMP probes sent to first hop device
    pub probes_sent: u64,
    /// Number of incoming ICMP responses received back from first hop device
    pub probes_recv: u64,
    /// 100 * probes_recv / probes_sent (to make percent, not a fraction)
    pub percent_loss: f64,
}

/// A helper type alias. It list all the types that are used in the UI
/// This is the magic that exports anything with #[derive(TypeDef)] into
/// netdebug_types.ts
pub type GuiApiTypes = (
    ConnectionMeasurements,
    DnsTrackerEntry,
    ChartJsBandwidth,
    AggregateStatEntry,
    CongestedLinksReply,
    NetworkInterfaceState,
    ExportedNeighborState,
    DesktopToTopologyServer,
    FirstHopPacketLossReportEntry,
    PublicOrganizationInfo,
    PublicDeviceInfo,
    PublicDeviceDetails,
);
