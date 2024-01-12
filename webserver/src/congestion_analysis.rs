use std::{collections::HashMap, net::IpAddr, str::FromStr, time::Duration};

use itertools::Itertools;
use libconntrack_wasm::{
    topology_server_messages::{
        CongestedLink, CongestedLinkKey, CongestionLatencyPair, CongestionSummary,
    },
    ConnectionKey, ConnectionMeasurements,
};
use log::warn;

/**
 * This code should stay here/in closed-source/libwebserver.  It is not YET super secret but will
 * eventually:
 * 1) will be once we add geo-location info and congestion vs. speed of light delays
 * 2) Cross-correlate across other measurements from other users
 * 3) Shot fireballs out of its ass, ala Braveheart (place holder for other cool things)
 *
 * NOTE: Do a lot of the math in microseconds b/c
 * (1) that's very precise for WAN measurements
 * (2) likely beyond the precisions of the clock accuracy
 */
pub fn recompute_compute_mean_and_peak(link: &mut CongestedLink) {
    let mut peak_micros = 0;
    let mut sum_micros = 0;
    let mut count = 0;
    for latency_pair in &link.latencies {
        let dst_lat = latency_pair.dst_rtt;
        let src_lat = latency_pair.src_rtt;
        // NOTE: std::time:Duration will panic!() if negative
        if dst_lat < src_lat {
            warn!(
                "Destination latency less than source latency!! dst={:?} src={:?} {:?}",
                dst_lat, src_lat, link
            );
            continue;
        }
        let latency = dst_lat.as_micros() - src_lat.as_micros();
        sum_micros += latency;
        count += 1;
        if peak_micros < latency {
            peak_micros = latency;
        }
    }
    if count > 0 {
        link.mean_latency = Some(Duration::from_micros(sum_micros as u64 / count as u64));
        link.peak_latency = Some(Duration::from_micros(peak_micros as u64));
    }
}

#[derive(Clone, Debug)]
struct HopInfo {
    pub ip: IpAddr,
    pub ttl: u8,
    pub rtt: Duration,
}

impl HopInfo {
    fn new(ip: IpAddr, ttl: u8, rtt: Duration) -> HopInfo {
        HopInfo { ip, ttl, rtt }
    }

    fn new_origin_v4() -> HopInfo {
        HopInfo {
            ip: IpAddr::from_str("127.0.0.1").unwrap(),
            ttl: 0,
            rtt: Duration::from_micros(0),
        }
    }
}

/**
 * Create a new CongestionSummary from a list of ConnectionMeasurements
 *
 * This is also secret stuff, so don't merge into open-source.  It's not
 * THAT secret for now, but once we include alias resolution and geo-location
 * and cross-user info, it will be.
 */

pub fn congestion_summary_from_measurements(
    measurements: Vec<ConnectionMeasurements>,
    skip_weird: bool,
) -> CongestionSummary {
    let mut links: HashMap<CongestedLinkKey, CongestedLink> = HashMap::new();

    // A ConnectionMeasurements struct is all info for a single, one-way five-tuple
    for measurement in &measurements {
        // Reset the sender with each measurement
        let mut prev_found = HopInfo::new_origin_v4();
        let mut next_found = None;
        // for trace/report in that ConnectionMeasurement
        // FYI: can't use ReportSummary b/c it doesn't match up the rtts precisely
        for report in &measurement.probe_report_summary.raw_reports {
            for ttl in report.probes.keys().sorted() {
                let probe = report.probes.get(ttl).unwrap();
                /*
                 * All the probes in a single report/trace should take the same path, baring
                 * a route change that happened during the <1ms length of the probe train.
                 * But still, we need to be careful how we handle.
                 */
                if skip_weird && !probe.get_comment().is_empty() {
                    continue; // skip things that are weird
                }
                if let Some(ip) = probe.get_ip() {
                    if let Some(rtt) = probe.get_rtt_ms() {
                        let current =
                            HopInfo::new(ip, *ttl, Duration::from_micros((rtt * 1000.0) as u64));
                        update_link_congestion(
                            &mut links,
                            &mut prev_found,
                            &current,
                            measurement.key.clone(),
                            report.probe_round,
                        );
                        next_found = Some(current);
                    }
                }
                if let Some(current) = next_found.as_ref() {
                    // if we have multiple routers for the same TTL in the same trace, just
                    // arbitrarily take the last one
                    prev_found = current.clone();
                }
            }
        }
    }
    // now compute all of the stats
    for link in links.values_mut() {
        recompute_compute_mean_and_peak(link);
    }
    CongestionSummary {
        links: links.values().cloned().collect_vec(),
    }
}

fn update_link_congestion(
    links: &mut HashMap<CongestedLinkKey, CongestedLink>,
    prev_found: &mut HopInfo,
    current: &HopInfo,
    connection_key: ConnectionKey,
    probe_round: u32,
) {
    let key = congested_link_key_from_hop_info(prev_found, current);
    let link = links.entry(key.clone()).or_insert(CongestedLink::new(key));

    link.latencies.push(CongestionLatencyPair {
        src_rtt: prev_found.rtt,
        dst_rtt: current.rtt,
        connection_key,
        probe_round,
    });
}

fn congested_link_key_from_hop_info(prev: &HopInfo, curr: &HopInfo) -> CongestedLinkKey {
    let src_ip = if prev.ttl == 0 {
        // need to match v4 vs v6 from curr HopInfo
        if curr.ip.is_ipv4() {
            IpAddr::from_str("127.0.0.1").unwrap()
        } else {
            IpAddr::from_str("::1").unwrap()
        }
    } else {
        prev.ip
    };
    CongestedLinkKey {
        src_hop_count: prev.ttl,
        src_ip,
        dst_ip: curr.ip,
        src_to_dst_hop_count: curr.ttl - prev.ttl,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::Utc;
    use common_wasm::{ProbeReportEntry, ProbeReportSummary, ProbeRoundReport};
    use libconntrack_wasm::{ConnectionKey, ConnectionMeasurements, TrafficStatsSummary};

    #[test]
    fn test_trivial_congestion_summary() {
        let data = make_simple_test_data();
        let congestion_summary = congestion_summary_from_measurements(data, true);
        assert_eq!(congestion_summary.links.len(), 10);
        for link in congestion_summary.links.iter() {
            assert_eq!(link.key.src_to_dst_hop_count, 1);
            assert_eq!(link.mean_latency.unwrap(), Duration::from_millis(1));
            assert_eq!(link.peak_latency.unwrap(), Duration::from_millis(1));
        }
    }

    // one measurement, one trace, 10-ttls, 1-ms each hop
    fn make_simple_test_data() -> Vec<ConnectionMeasurements> {
        let probes = (1..=10).map(|ttl| {
            let entry = ProbeReportEntry::RouterReplyFound {
                ttl,
                out_timestamp_ms: ttl as f64,
                rtt_ms: ttl as f64,
                src_ip: IpAddr::from([ttl, ttl, ttl, ttl]),
                comment: "".to_string(),
            };
            (ttl, entry)
        });
        let report = ProbeRoundReport {
            probes: HashMap::from_iter(probes),
            probe_round: 1,
            application_rtt: None,
        };
        let key = ConnectionKey {
            local_ip: IpAddr::from([1, 1, 1, 1]),
            remote_ip: IpAddr::from([2, 2, 2, 2]),
            local_l4_port: 1,
            remote_l4_port: 2,
            ip_proto: libconntrack_wasm::IpProtocol::TCP,
        };
        vec![ConnectionMeasurements {
            key,
            local_hostname: None,
            remote_hostname: None,
            probe_report_summary: ProbeReportSummary {
                raw_reports: vec![report],
                summary: HashMap::new(),
            },
            user_annotation: None,
            user_agent: None,
            associated_apps: None,
            close_has_started: false,
            four_way_close_done: false,
            start_tracking_time: Utc::now(),
            last_packet_time: Utc::now(),
            rx_stats: make_simple_traffic_stats_summary(),
            tx_stats: make_simple_traffic_stats_summary(),
        }]
    }

    fn make_simple_traffic_stats_summary() -> TrafficStatsSummary {
        TrafficStatsSummary {
            bytes: 10,
            pkts: 2,
            ..Default::default()
        }
    }
}
