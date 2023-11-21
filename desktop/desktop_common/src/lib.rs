use std::{collections::HashMap, net::IpAddr, time::Duration};

use common_wasm::timeseries_stats::ExportedBuckets;
use libconntrack_wasm::{
    AggregateCounterKind, BidirBandwidthHistory, ConnectionMeasurements, DnsTrackerEntry,
};
/**
 * Anything in this file must compile for both native rust/x86 AND WASM
 *
 * So no thread, deep OS calls, etc. here
 */
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use typescript_type_def::TypeDef;

pub fn get_git_hash_version() -> String {
    env!("GIT_HASH").to_string()
}

/// Represents the data for a single bandwidth chart with data arranged for direct plotting
/// with `chart.js`.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TypeDef)]
pub struct ChartJsBandwidth {
    /// The label of this chart. E.g., `Last 5 Seconds`
    pub label: String,
    /// The total amount of time this Chart can hold, i.e., `bucket_time_window * num_buckets`.
    /// This isn't necessarily the amount of data the chart is holding
    #[type_def(type_of = "u64")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(rename = "total_duration_sec")]
    pub total_time_window: Duration,
    /// The maximum value of the y axis (which represents bits/s)
    pub y_max_bps: f64,
    /// The received / download bandwidth history as chart.js points
    pub rx: Vec<ChartJsPoint>,
    /// The sent / upload bandwidth history as chart.js points
    pub tx: Vec<ChartJsPoint>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TypeDef)]
pub struct ChartJsPoint {
    /// x-value. For bandwidth plots this is seconds in the past where the last bucket is `now`, i.e., 0.0
    /// And a value of -2.5 is 2.5secs in the past. (Note these values are all <= 0)
    pub x: f64,
    /// y-value. For bandwidth plots this is bit-per-second
    pub y: f64,
}

/// Takes a ExportedBuckets instance and maps it to a Vec of ChartJs points.
fn exported_buckets_to_chartjs_points(exported_buckets: &ExportedBuckets) -> Vec<ChartJsPoint> {
    let time_window = exported_buckets.bucket_time_window;
    let num_buckets = exported_buckets.buckets.len();
    exported_buckets
        .buckets
        .iter()
        .enumerate()
        .map(|(idx, bytes)| ChartJsPoint {
            // convert to seconds in the past where the last bucket represents `now`
            x: -time_window.as_secs_f64() * (num_buckets - 1 - idx) as f64,
            // Convert to Bit/s
            y: (bytes * 8) as f64 / time_window.as_secs_f64(),
        })
        .collect()
}

pub fn bidir_bandwidth_to_chartjs(bbh: BidirBandwidthHistory) -> Vec<ChartJsBandwidth> {
    // Convert the hashmap of `Label --> ExportedBuckets` to a flat Vec of (label, ExportedBucket)
    // tuples.
    let mut rx_vec: Vec<(String, ExportedBuckets)> = bbh.rx.byte_buckets.into_iter().collect();
    let mut tx_vec: Vec<(String, ExportedBuckets)> = bbh.tx.byte_buckets.into_iter().collect();
    // sort by ascending time window
    rx_vec.sort_by_key(|x| x.1.bucket_time_window);
    tx_vec.sort_by_key(|x| x.1.bucket_time_window);
    // rx and tx should match in terms of #buckets, bucket sizes, etc.
    assert_eq!(rx_vec.len(), tx_vec.len());
    let mut ret = Vec::with_capacity(tx_vec.len());
    for i in 0..tx_vec.len() {
        // The labels should match
        assert_eq!(tx_vec[i].0, rx_vec[i].0);
        // The time-windows should match
        assert_eq!(
            tx_vec[i].1.bucket_time_window,
            rx_vec[i].1.bucket_time_window
        );
        // number of buckets should match
        assert_eq!(tx_vec[i].1.buckets.len(), rx_vec[i].1.buckets.len());

        let rx_points = exported_buckets_to_chartjs_points(&rx_vec[i].1);
        let tx_points = exported_buckets_to_chartjs_points(&tx_vec[i].1);
        let max_y = rx_points
            .iter()
            .chain(&tx_points)
            .map(|p| p.y)
            .reduce(f64::max)
            .unwrap_or_default();

        let total_time_window = tx_points.len() as u32 * tx_vec[i].1.bucket_time_window;
        ret.push(ChartJsBandwidth {
            label: tx_vec[i].0.clone(),
            total_time_window,
            y_max_bps: max_y,
            rx: rx_points,
            tx: tx_points,
        });
    }
    ret
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerToGuiMessages {
    VersionCheck(String),
    DumpFlowsReply(Vec<ConnectionMeasurements>),
    DumpDnsCache(HashMap<IpAddr, DnsTrackerEntry>),
    DumpAggregateCountersReply(Vec<ChartJsBandwidth>),
    DumpStatCountersReply(HashMap<String, u64>),
    DumpDnsAggregateCountersReply(
        HashMap<AggregateCounterKind, (BidirBandwidthHistory, Vec<ConnectionMeasurements>)>,
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
    use std::collections::HashMap;

    use approx::assert_relative_eq;
    use chrono::Utc;
    use common_wasm::timeseries_stats::ExportedBuckets;
    use libconntrack_wasm::{BandwidthHistory, BidirBandwidthHistory};

    use super::*;

    #[test]
    fn test_message_json() {
        println!(
            "{}",
            serde_json::to_string(&GuiToServerMessages::DumpDnsCache()).unwrap()
        );
    }

    #[test]
    fn test_exported_bucket_to_chartjs_points() {
        let eb = ExportedBuckets {
            bucket_time_window: std::time::Duration::from_millis(100),
            buckets: vec![5000, 1000, 0, 4200],
        };
        let chartjs_points = exported_buckets_to_chartjs_points(&eb);
        assert_relative_eq!(chartjs_points[0].x, -0.3);
        assert_relative_eq!(chartjs_points[0].y, 8. * 50_000.);
        assert_relative_eq!(chartjs_points[1].x, -0.2);
        assert_relative_eq!(chartjs_points[1].y, 8. * 10_000.);
        assert_relative_eq!(chartjs_points[2].x, -0.1);
        assert_relative_eq!(chartjs_points[2].y, 0.0);
        assert_relative_eq!(chartjs_points[3].x, 0.0);
        assert_relative_eq!(chartjs_points[3].y, 8. * 42_000.);

        let eb = ExportedBuckets {
            bucket_time_window: std::time::Duration::from_millis(100),
            buckets: Vec::new(),
        };
        assert_eq!(exported_buckets_to_chartjs_points(&eb).len(), 0);
    }

    fn mk_exported_buckets(dur_ms: u64, buckets: &[u64]) -> ExportedBuckets {
        ExportedBuckets {
            bucket_time_window: Duration::from_millis(dur_ms),
            buckets: Vec::from(buckets),
        }
    }

    #[test]
    fn test_bidir_bandwidth_to_chartjs() {
        use std::time::Duration;
        let now = Utc::now();
        let mut rx_map = HashMap::new();
        rx_map.insert(
            "foo".to_owned(),
            mk_exported_buckets(10_000, &[65_000, 10_000, 75_000]),
        );
        rx_map.insert(
            "bar".to_owned(),
            mk_exported_buckets(500, &[100, 400, 300, 200]),
        );
        let mut tx_map = HashMap::new();
        tx_map.insert(
            "foo".to_owned(),
            mk_exported_buckets(10_000, &[165_000, 110_000, 175_000]),
        );
        tx_map.insert(
            "bar".to_owned(),
            mk_exported_buckets(500, &[10, 40, 30, 20]),
        );
        let bbh = BidirBandwidthHistory {
            rx: BandwidthHistory {
                end_bucket_time: now,
                total_duration: Duration::from_secs(100),
                byte_buckets: rx_map,
                pkt_buckets: HashMap::new(),
            },
            tx: BandwidthHistory {
                end_bucket_time: now,
                total_duration: Duration::from_secs(100),
                byte_buckets: tx_map,
                pkt_buckets: HashMap::new(),
            },
        };
        let chartjs = bidir_bandwidth_to_chartjs(bbh);
        assert_eq!(chartjs.len(), 2);
        assert_eq!(chartjs[0].label, "bar");
        assert_relative_eq!(chartjs[0].y_max_bps, 8. * 400. / 0.5);
        assert_relative_eq!(chartjs[0].rx[0].x, -1.5);
        assert_relative_eq!(chartjs[0].rx[1].x, -1.0);
        assert_relative_eq!(chartjs[0].rx[2].x, -0.5);
        assert_relative_eq!(chartjs[0].rx[3].x, 0.0);
        // these are the values from rx_map["bar"]
        assert_relative_eq!(chartjs[0].rx[0].y, 8. * 100. / 0.5);
        assert_relative_eq!(chartjs[0].rx[1].y, 8. * 400. / 0.5);
        assert_relative_eq!(chartjs[0].rx[2].y, 8. * 300. / 0.5);
        assert_relative_eq!(chartjs[0].rx[3].y, 8. * 200. / 0.5);

        assert_relative_eq!(chartjs[0].tx[0].x, -1.5);
        assert_relative_eq!(chartjs[0].tx[1].x, -1.0);
        assert_relative_eq!(chartjs[0].tx[2].x, -0.5);
        assert_relative_eq!(chartjs[0].tx[3].x, 0.0);
        // these are the values from tx_map["bar"]
        assert_relative_eq!(chartjs[0].tx[0].y, 8. * 10. / 0.5);
        assert_relative_eq!(chartjs[0].tx[1].y, 8. * 40. / 0.5);
        assert_relative_eq!(chartjs[0].tx[2].y, 8. * 30. / 0.5);
        assert_relative_eq!(chartjs[0].tx[3].y, 8. * 20. / 0.5);

        assert_eq!(chartjs[1].label, "foo");
        assert_relative_eq!(chartjs[1].y_max_bps, 8. * 175_000. / 10.);
        assert_relative_eq!(chartjs[1].rx[0].x, -20.);
        assert_relative_eq!(chartjs[1].rx[1].x, -10.);
        assert_relative_eq!(chartjs[1].rx[2].x, 0.);
        // these are the values from rx_map["foo"]
        assert_relative_eq!(chartjs[1].rx[0].y, 8. * 65_000. / 10.);
        assert_relative_eq!(chartjs[1].rx[1].y, 8. * 10_000. / 10.);
        assert_relative_eq!(chartjs[1].rx[2].y, 8. * 75_000. / 10.);

        assert_relative_eq!(chartjs[1].tx[0].x, -20.);
        assert_relative_eq!(chartjs[1].tx[1].x, -10.);
        assert_relative_eq!(chartjs[1].tx[2].x, 0.);
        // these are the values from tx_map["foo"]
        assert_relative_eq!(chartjs[1].tx[0].y, 8. * 165_000. / 10.);
        assert_relative_eq!(chartjs[1].tx[1].y, 8. * 110_000. / 10.);
        assert_relative_eq!(chartjs[1].tx[2].y, 8. * 175_000. / 10.);
    }

    #[test]
    fn test_bidir_bandwidth_to_chartjs_empty() {
        use std::time::Duration;
        let now = Utc::now();
        let bbh = BidirBandwidthHistory {
            rx: BandwidthHistory {
                end_bucket_time: now,
                total_duration: Duration::from_secs(100),
                byte_buckets: HashMap::new(),
                pkt_buckets: HashMap::new(),
            },
            tx: BandwidthHistory {
                end_bucket_time: now,
                total_duration: Duration::from_secs(100),
                byte_buckets: HashMap::new(),
                pkt_buckets: HashMap::new(),
            },
        };
        assert_eq!(bidir_bandwidth_to_chartjs(bbh).len(), 0);
    }

    #[test]
    fn test_bidir_bandwidth_to_chartjs_empty_buckets() {
        use std::time::Duration;
        let now = Utc::now();
        let mut empty = HashMap::new();
        empty.insert("foo".to_owned(), mk_exported_buckets(10_000, &[]));
        let bbh = BidirBandwidthHistory {
            rx: BandwidthHistory {
                end_bucket_time: now,
                total_duration: Duration::from_secs(100),
                byte_buckets: empty.clone(),
                pkt_buckets: HashMap::new(),
            },
            tx: BandwidthHistory {
                end_bucket_time: now,
                total_duration: Duration::from_secs(100),
                byte_buckets: empty,
                pkt_buckets: HashMap::new(),
            },
        };
        assert_eq!(bidir_bandwidth_to_chartjs(bbh.clone()).len(), 1);
        assert_eq!(bidir_bandwidth_to_chartjs(bbh.clone())[0].rx.len(), 0);
        assert_eq!(bidir_bandwidth_to_chartjs(bbh)[0].tx.len(), 0);
    }
}
