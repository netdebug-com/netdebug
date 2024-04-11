use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::serde::ts_nanoseconds;
use chrono::{DateTime, Utc};
use common_wasm::{PingtreeUiResult, ProbeReportSummary};
use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef;

use crate::traffic_stats::TrafficStatsSummary;
use crate::ConnectionKey;

/***
 * The `struct ConnectionMeasurements` contains only the derived connection state
 * that we want to save/share with the GUI or the remote data server.  It should
 * not contain live connection state information or anything that could be considered
 * privacy sensitive (e.g., packet payloads) except IP addresses.
 */

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TypeDef)]
pub struct ConnectionMeasurements {
    pub key: ConnectionKey,
    pub local_hostname: Option<String>,
    pub remote_hostname: Option<String>,
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
    // Pingtrees, that have been iniated and run based on the routers discovered by this connection's
    // inband probes.
    #[serde(default)]
    pub pingtrees: Vec<PingtreeUiResult>,
}

impl ConnectionMeasurements {
    pub fn get_five_tuple_string(&self) -> String {
        format!(
            "{} {} ({} :: {}) --> {} ({} :: {})",
            self.key.ip_proto,
            self.local_hostname.clone().unwrap_or("-".to_string()),
            self.key.local_ip,
            self.key.local_l4_port,
            self.remote_hostname.clone().unwrap_or("-".to_string()),
            self.key.remote_ip,
            self.key.remote_l4_port
        )
    }

    pub fn make_mock() -> ConnectionMeasurements {
        ConnectionMeasurements::make_mock_with_ips("127.0.0.1", "128.8.128.38")
    }

    pub fn make_mock_with_ips(src_ip: &str, dst_ip: &str) -> ConnectionMeasurements {
        ConnectionMeasurements {
            key: ConnectionKey {
                local_ip: IpAddr::from_str(src_ip).unwrap(),
                remote_ip: IpAddr::from_str(dst_ip).unwrap(),
                local_l4_port: 12345,
                remote_l4_port: 443,
                ip_proto: crate::IpProtocol::TCP,
            },
            local_hostname: Some("localhost".to_string()),
            remote_hostname: Some("www.example.com".to_string()),
            probe_report_summary: ProbeReportSummary::new(), // don't fill in any data for now
            user_annotation: Some("mock annotation".to_string()),
            user_agent: Some("mock user agent".to_string()),
            associated_apps: Some(HashMap::from([(4, Some("SuperApp".to_string()))])),
            close_has_started: true,
            four_way_close_done: false,
            start_tracking_time: Utc::now(),
            last_packet_time: Utc::now(),
            rx_stats: TrafficStatsSummary::make_mock(),
            tx_stats: TrafficStatsSummary::make_mock(),
            pingtrees: Vec::new(),
        }
    }
}
