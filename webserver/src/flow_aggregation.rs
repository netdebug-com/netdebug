use std::collections::HashMap;

use itertools::Itertools;
use libconntrack_wasm::{ConnectionMeasurements, IpProtocol};
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedConnectionMeasurement {
    pub num_flows: i64,
    pub num_flows_with_rx_loss: i64,
    pub num_flows_with_tx_loss: i64,
    pub num_tcp_flows: i64,
    pub num_udp_flows: i64,

    pub rx_packets: i64,
    pub tx_packets: i64,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub rx_lost_bytes: i64,
    pub tx_lost_bytes: i64,

    pub tcp_rx_bytes: i64,
    pub tcp_tx_bytes: i64,
    pub udp_rx_bytes: i64,
    pub udp_tx_bytes: i64,
}

impl AggregatedConnectionMeasurement {
    pub fn add_to_aggregate(&mut self, rhs: &ConnectionMeasurements) {
        self.num_flows += 1;
        match rhs.key.ip_proto {
            IpProtocol::TCP => {
                self.num_tcp_flows += 1;
                self.tcp_tx_bytes += rhs.tx_stats_since_prev_export.bytes as i64;
                self.tcp_rx_bytes += rhs.rx_stats_since_prev_export.bytes as i64;
            }
            IpProtocol::UDP => {
                self.num_udp_flows += 1;
                self.udp_tx_bytes += rhs.tx_stats_since_prev_export.bytes as i64;
                self.udp_rx_bytes += rhs.rx_stats_since_prev_export.bytes as i64;
            }
            _ => (),
        }
        if let Some(tx_loss) = rhs.tx_stats_since_prev_export.lost_bytes {
            self.tx_lost_bytes += tx_loss as i64;
            self.num_flows_with_tx_loss += 1;
        }
        if let Some(rx_loss) = rhs.rx_stats_since_prev_export.lost_bytes {
            self.rx_lost_bytes += rx_loss as i64;
            self.num_flows_with_rx_loss += 1;
        }

        self.tx_packets += rhs.tx_stats_since_prev_export.pkts as i64;
        self.tx_bytes += rhs.tx_stats_since_prev_export.bytes as i64;
        self.rx_packets += rhs.rx_stats_since_prev_export.pkts as i64;
        self.rx_bytes += rhs.rx_stats_since_prev_export.bytes as i64;
    }
}

#[derive(Default, Clone, Debug)]
pub struct AggregateByCategory {
    pub total: AggregatedConnectionMeasurement,
    pub by_dns_dest_domain: HashMap<String, AggregatedConnectionMeasurement>,
    pub by_app: HashMap<String, AggregatedConnectionMeasurement>,
}

const UNKNOWN: &str = "<UNKNOWN>";

impl AggregateByCategory {
    pub fn add_to_aggregate(&mut self, m: &ConnectionMeasurements) {
        let domain = match m
            .remote_hostname
            .as_ref()
            .map(|hostname| libconntrack::utils::dns_to_cannonical_domain(hostname))
        {
            Some(Ok(domain)) => domain,
            _ => UNKNOWN.to_string(),
        };
        self.total.add_to_aggregate(m);
        self.by_dns_dest_domain
            .entry(domain)
            .or_default()
            .add_to_aggregate(m);

        // associated_apps is Option<HashMap<u32, Option<String>>>
        let app_names: Vec<Option<String>> = m
            .associated_apps
            .as_ref()
            .map(|apps| apps.values().cloned().collect_vec())
            .unwrap_or_default();
        // lets remove 'None' from the Vec.
        let app_names = app_names.into_iter().flatten().collect_vec();
        if app_names.is_empty() {
            // Hack for DNS
            let name = if m.key.remote_l4_port == 53 {
                "DNS"
            } else {
                UNKNOWN
            };
            self.by_app
                .entry(name.to_string())
                .or_default()
                .add_to_aggregate(m);
        } else {
            for name in app_names {
                self.by_app.entry(name).or_default().add_to_aggregate(m);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use libconntrack_wasm::TrafficStatsSummary;

    use super::*;

    #[test]
    fn test_add_to_aggregate() {
        let mut agg = AggregatedConnectionMeasurement::default();

        // The mock doesn't have anything in *_stats_since_prev_export
        // so the byte/pkt counts should all be 0
        let m = ConnectionMeasurements::make_mock();
        agg.add_to_aggregate(&m);
        assert_eq!(agg.num_flows, 1);
        assert_eq!(agg.num_tcp_flows, 1);
        assert_eq!(agg.num_udp_flows, 0);
        assert_eq!(agg.num_flows_with_rx_loss, 0);
        assert_eq!(agg.num_flows_with_tx_loss, 0);

        assert_eq!(agg.rx_packets, 0);
        assert_eq!(agg.tx_packets, 0);
        assert_eq!(agg.rx_bytes, 0);
        assert_eq!(agg.tx_bytes, 0);
        assert_eq!(agg.rx_lost_bytes, 0);
        assert_eq!(agg.tx_lost_bytes, 0);

        assert_eq!(agg.tcp_rx_bytes, 0);
        assert_eq!(agg.tcp_tx_bytes, 0);
        assert_eq!(agg.udp_rx_bytes, 0);
        assert_eq!(agg.udp_tx_bytes, 0);

        let mut m = ConnectionMeasurements::make_mock();
        m.tx_stats_since_prev_export = TrafficStatsSummary::make_mock();
        // add it twice
        agg.add_to_aggregate(&m);
        agg.add_to_aggregate(&m);
        assert_eq!(agg.num_flows, 3);
        assert_eq!(agg.num_tcp_flows, 3);
        assert_eq!(agg.num_udp_flows, 0);
        assert_eq!(agg.num_flows_with_rx_loss, 0);
        assert_eq!(agg.num_flows_with_tx_loss, 2);

        assert_eq!(agg.rx_packets, 0);
        assert_eq!(agg.tx_packets, 8);
        assert_eq!(agg.rx_bytes, 0);
        assert_eq!(agg.tx_bytes, 12_000);
        assert_eq!(agg.rx_lost_bytes, 0);
        assert_eq!(agg.tx_lost_bytes, 3000);

        assert_eq!(agg.tcp_rx_bytes, 0);
        assert_eq!(agg.tcp_tx_bytes, 12_000);
        assert_eq!(agg.udp_rx_bytes, 0);
        assert_eq!(agg.udp_tx_bytes, 0);

        let mut m = ConnectionMeasurements::make_mock();
        m.key.ip_proto = IpProtocol::UDP;
        m.rx_stats_since_prev_export = TrafficStatsSummary {
            bytes: 4_500,
            pkts: 3,
            burst_pkt_rate: None,
            burst_byte_rate: None,
            last_min_pkt_rate: None,
            last_min_byte_rate: None,
            lost_bytes: Some(100),
            rtt_stats_ms: None,
        };
        agg.add_to_aggregate(&m);
        assert_eq!(agg.num_flows, 4);
        assert_eq!(agg.num_tcp_flows, 3);
        assert_eq!(agg.num_udp_flows, 1);
        assert_eq!(agg.num_flows_with_rx_loss, 1);
        assert_eq!(agg.num_flows_with_tx_loss, 2);

        assert_eq!(agg.rx_packets, 3);
        assert_eq!(agg.tx_packets, 8);
        assert_eq!(agg.rx_bytes, 4_500);
        assert_eq!(agg.tx_bytes, 12_000);
        assert_eq!(agg.rx_lost_bytes, 100);
        assert_eq!(agg.tx_lost_bytes, 3000);

        assert_eq!(agg.tcp_rx_bytes, 0);
        assert_eq!(agg.tcp_tx_bytes, 12_000);
        assert_eq!(agg.udp_rx_bytes, 4_500);
        assert_eq!(agg.udp_tx_bytes, 0);

        let mut m = ConnectionMeasurements::make_mock();
        m.key.ip_proto = IpProtocol::UDP;
        m.tx_stats_since_prev_export = TrafficStatsSummary {
            bytes: 123,
            pkts: 2,
            burst_pkt_rate: None,
            burst_byte_rate: None,
            last_min_pkt_rate: None,
            last_min_byte_rate: None,
            lost_bytes: None,
            rtt_stats_ms: None,
        };
        agg.add_to_aggregate(&m);
        assert_eq!(agg.num_flows, 5);
        assert_eq!(agg.num_tcp_flows, 3);
        assert_eq!(agg.num_udp_flows, 2);
        assert_eq!(agg.num_flows_with_rx_loss, 1);
        assert_eq!(agg.num_flows_with_tx_loss, 2);

        assert_eq!(agg.rx_packets, 3);
        assert_eq!(agg.tx_packets, 10);
        assert_eq!(agg.rx_bytes, 4_500);
        assert_eq!(agg.tx_bytes, 12_123);
        assert_eq!(agg.rx_lost_bytes, 100);
        assert_eq!(agg.tx_lost_bytes, 3000);

        assert_eq!(agg.tcp_rx_bytes, 0);
        assert_eq!(agg.tcp_tx_bytes, 12_000);
        assert_eq!(agg.udp_rx_bytes, 4_500);
        assert_eq!(agg.udp_tx_bytes, 123);

        let mut m = ConnectionMeasurements::make_mock();
        m.rx_stats_since_prev_export = TrafficStatsSummary {
            bytes: 123,
            pkts: 2,
            burst_pkt_rate: None,
            burst_byte_rate: None,
            last_min_pkt_rate: None,
            last_min_byte_rate: None,
            lost_bytes: None,
            rtt_stats_ms: None,
        };
        agg.add_to_aggregate(&m);
        assert_eq!(agg.num_flows, 6);
        assert_eq!(agg.num_tcp_flows, 4);
        assert_eq!(agg.num_udp_flows, 2);
        assert_eq!(agg.num_flows_with_rx_loss, 1);
        assert_eq!(agg.num_flows_with_tx_loss, 2);

        assert_eq!(agg.rx_packets, 5);
        assert_eq!(agg.tx_packets, 10);
        assert_eq!(agg.rx_bytes, 4_623);
        assert_eq!(agg.tx_bytes, 12_123);
        assert_eq!(agg.rx_lost_bytes, 100);
        assert_eq!(agg.tx_lost_bytes, 3000);

        assert_eq!(agg.tcp_rx_bytes, 123);
        assert_eq!(agg.tcp_tx_bytes, 12_000);
        assert_eq!(agg.udp_rx_bytes, 4_500);
        assert_eq!(agg.udp_tx_bytes, 123);
    }

    #[test]
    fn test_aggregate_by_category() {
        let m1 = ConnectionMeasurements::make_mock();
        let m2 = ConnectionMeasurements {
            remote_hostname: None,
            ..ConnectionMeasurements::make_mock()
        };
        let m3a = ConnectionMeasurements {
            associated_apps: Some(HashMap::new()),
            ..ConnectionMeasurements::make_mock()
        };
        let m3b = ConnectionMeasurements {
            associated_apps: None,
            ..ConnectionMeasurements::make_mock()
        };
        let m4 = ConnectionMeasurements {
            // not a valid domain
            remote_hostname: Some("asdf@@@###".to_string()),
            ..ConnectionMeasurements::make_mock()
        };

        let mut x = AggregateByCategory::default();
        x.add_to_aggregate(&m1);
        x.add_to_aggregate(&m2.clone());
        x.add_to_aggregate(&m2);
        x.add_to_aggregate(&m3a.clone());
        x.add_to_aggregate(&m3a);
        x.add_to_aggregate(&m3b);
        x.add_to_aggregate(&m4.clone());
        x.add_to_aggregate(&m4.clone());
        x.add_to_aggregate(&m4.clone());
        x.add_to_aggregate(&m4);

        assert_eq!(x.total.num_flows, 10);
        assert_eq!(x.by_app.len(), 2);
        assert_eq!(x.by_dns_dest_domain.len(), 2);

        // m3a and m3b do not have an app. we have 2x m3a and 1x m3b ==> 3 flows
        assert_eq!(x.by_app.get(UNKNOWN).unwrap().num_flows, 3);
        // the 7 other flows have the value from the mock
        assert_eq!(x.by_app.get("SuperApp").unwrap().num_flows, 7);

        // m1, m3a, m3b have example.com domain ==> 4 total flows (m3a twice)
        assert_eq!(
            x.by_dns_dest_domain.get("example.com").unwrap().num_flows,
            4
        );
        // The 6 other flows have unknown domain
        assert_eq!(x.by_dns_dest_domain.get(UNKNOWN).unwrap().num_flows, 6);
    }

    #[test]
    fn test_aggregate_by_category_magic_apps() {
        let mut by_category = AggregateByCategory::default();

        let mut m1 = ConnectionMeasurements::make_mock();
        m1.key.remote_l4_port = 53;
        m1.tx_stats_since_prev_export = TrafficStatsSummary {
            bytes: 1000,
            pkts: 5,
            ..Default::default()
        };
        m1.associated_apps = None;

        by_category.add_to_aggregate(&m1);

        // with an empty map
        m1.associated_apps = Some(HashMap::new());
        by_category.add_to_aggregate(&m1);

        // entry is none.
        let mut associated_apps = HashMap::new();
        associated_apps.insert(1, None);
        m1.associated_apps = Some(associated_apps);
        by_category.add_to_aggregate(&m1);

        assert_eq!(by_category.total.num_flows, 3);
        assert_eq!(by_category.by_app.keys().collect_vec(), vec!["DNS"]);
        assert_eq!(by_category.by_app.get("DNS").unwrap().num_flows, 3);
    }
}
