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

/// Used for authentication from frontend to backend as a JSON Web Token
/// This is the 'payload' of our JWT that gets signed
/// See https://github.com/Keats/jsonwebtoken for details
/// These should roughly follow https://datatracker.ietf.org/doc/html/rfc7519#section-4.1 but
/// since it's internal, strictly speaking doens't have to.
/// NOTE: DO NOT PUT ANYTHING HERE THAT WE DON'T WANT USERS TO READ - will be plain txt to users
///     Other parts of the JWT stack will sign these to prevent tampering
/// NOTE: The field names are also encoded thus the effort to keep them short "Subject" -> "sub"
pub const AUTH_TOKEN_ISSUER_NETDEBUG: &str = "netdebug.com";
#[derive(Debug, Serialize, Deserialize, TypeDef)]
pub struct AuthTokenClaims {
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    /// 'Issuer': Should always be "netdebug.com" for our internal tokens
    iss: String,
    /// "Subject": in our case, always the Email address of the user
    sub: String,
    /// Domain is typically the user's company but selects which set of data the user can see
    domain: String,
    /// Super user powers in that domain
    admin: bool,
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
