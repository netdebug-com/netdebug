use std::{collections::HashMap, net::IpAddr};

use common::ProbeReportSummary;
use serde::{Serialize, Deserialize};

/***
 * The `struct ConnectionMeasurements` contains only the derived connection state
 * that we want to save/share with the GUI or the remote data server.  It should
 * not contain live connection state information or anything that could be considered
 * privacy sensitive (e.g., packet payloads) except IP addresses.
 */


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionMeasurements {
    pub local_ip: IpAddr,
    pub local_l4_port: u16,
    pub remote_ip: IpAddr,
    pub remote_l4_port: u16,
    pub ip_proto: u8,
    pub probe_report_summary: ProbeReportSummary,
    pub user_annotation: Option<String>, // an human supplied comment on this connection
    pub user_agent: Option<String>, // when created via a web request, store the user-agent header
    pub pids: Option<HashMap<u32, Option<String>>>, // PID --> ProcessName, if we know it
    // TODO: add local_syn, remote_syn IP and TCP options
}