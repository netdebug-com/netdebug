use std::{collections::HashMap, net::IpAddr};

use chrono::serde::ts_nanoseconds;
use chrono::{DateTime, Utc};
use common_wasm::ProbeReportSummary;
use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef;

use crate::traffic_stats::TrafficStatsSummary;
use crate::IpProtocol;

/***
 * The `struct ConnectionMeasurements` contains only the derived connection state
 * that we want to save/share with the GUI or the remote data server.  It should
 * not contain live connection state information or anything that could be considered
 * privacy sensitive (e.g., packet payloads) except IP addresses.
 */

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TypeDef)]
pub struct ConnectionMeasurements {
    pub local_hostname: Option<String>,
    #[type_def(type_of = "String")]
    pub local_ip: IpAddr,
    pub local_l4_port: u16,
    pub remote_hostname: Option<String>,
    #[type_def(type_of = "String")]
    pub remote_ip: IpAddr,
    pub remote_l4_port: u16,
    pub ip_proto: IpProtocol,
    pub probe_report_summary: ProbeReportSummary,
    pub user_annotation: Option<String>, // an human supplied comment on this connection
    pub user_agent: Option<String>, // when created via a web request, store the user-agent header
    pub associated_apps: Option<HashMap<u32, Option<String>>>, // PID --> ProcessName, if we know it
    /// Whether this connection has been (partially) closed. I.e., at least on FIN of RST ]
    /// was received.
    pub close_has_started: bool,
    /// Whether this connection has completed the 4-way TCP teardown (2 FINs that were
    /// ACK'ed)
    pub four_way_close_done: bool,
    // TODO: add local_syn, remote_syn IP and TCP options
    #[serde(with = "ts_nanoseconds", rename = "start_tracking_time_ns")]
    #[type_def(type_of = "f64")]
    pub start_tracking_time: DateTime<Utc>, // time tracker: first saw a packet
    #[type_def(type_of = "f64")]
    #[serde(with = "ts_nanoseconds", rename = "last_packet_time_ns")]
    pub last_packet_time: DateTime<Utc>, // time tracker: last saw a packet
    #[serde(default)]
    pub rx_stats: TrafficStatsSummary,
    #[serde(default)]
    pub tx_stats: TrafficStatsSummary,
}

impl ConnectionMeasurements {
    pub fn get_five_tuple_string(&self) -> String {
        format!(
            "{} {} ({} :: {}) --> {} ({} :: {})",
            self.ip_proto,
            self.local_hostname
                .clone()
                .or(Some("-".to_string()))
                .unwrap(),
            self.local_ip,
            self.local_l4_port,
            self.remote_hostname
                .clone()
                .or(Some("-".to_string()))
                .unwrap(),
            self.remote_ip,
            self.remote_l4_port
        )
    }
}
