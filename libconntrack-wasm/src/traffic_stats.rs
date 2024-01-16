use std::{collections::HashMap, fmt::Display, time::Duration};

use chrono::{DateTime, Utc};
use common_wasm::{
    stats_helper::{ExportedSimpleStats, SimpleStats},
    timeseries_stats::{BucketedTimeSeries, ExportedBuckets},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use typescript_type_def::TypeDef;

use crate::{pretty_print_si_units, ConnectionMeasurements};

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TypeDef)]
#[serde(tag = "tag", content = "name")]
pub enum AggregateStatKind {
    DnsDstDomain(String),
    Application(String),
    ConnectionTracker,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TypeDef)]
pub struct AggregateStatEntry {
    pub kind: AggregateStatKind,
    pub bandwidth: Vec<ChartJsBandwidth>,
    pub summary: BidirTrafficStatsSummary,
    pub connections: Vec<ConnectionMeasurements>,
}

/// Keeps track of the maximum observed burst rate (both bytes and packets) in a short
/// time interval (`time_window`). E.g., if `time_window == 10ms` then it will track
/// maximum rate for 10ms bursts.
/// Note that packet and byte rates are tracked independently
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaxBurstRate {
    ts: Option<BucketedTimeSeries<DateTime<Utc>>>,
    time_window: std::time::Duration,
    max_bytes: u64,
    max_pkts: u64,
}

impl MaxBurstRate {
    const NUM_BUCKETS: u32 = 100;
    pub fn new(time_window: std::time::Duration) -> MaxBurstRate {
        MaxBurstRate {
            ts: None,
            time_window,
            max_bytes: 0,
            max_pkts: 0,
        }
    }

    fn add_packet_with_time(&mut self, bytes: u64, timestamp: DateTime<Utc>) {
        if self.ts.is_none() {
            self.ts = Some(BucketedTimeSeries::new_with_create_time(
                timestamp,
                self.time_window / Self::NUM_BUCKETS,
                Self::NUM_BUCKETS as usize,
            ));
        }
        let ts = self.ts.as_mut().unwrap();
        ts.add_value(bytes, timestamp);
        self.max_bytes = self.max_bytes.max(ts.get_sum());
        self.max_pkts = self.max_pkts.max(ts.get_num_entries());
    }

    fn get_byte_rate(&self) -> Option<f64> {
        self.ts.as_ref().and_then(|ts| {
            if ts.full_window_seen() {
                Some(self.max_bytes as f64 / self.time_window.as_secs_f64())
            } else {
                None
            }
        })
    }

    fn get_packet_rate(&self) -> Option<f64> {
        self.ts.as_ref().and_then(|ts| {
            if ts.full_window_seen() {
                Some(self.max_pkts as f64 / self.time_window.as_secs_f64())
            } else {
                None
            }
        })
    }
}

impl Display for MaxBurstRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}, {}",
            pretty_print_si_units(self.get_byte_rate(), "Byte/s"),
            pretty_print_si_units(self.get_packet_rate(), "Pkts/s")
        )?;
        Ok(())
    }
}

/// Used for exported data (to UI, storage, etc.)
/// A summary of a unidirectional flow stats. A flow can be anything: A 5-tuple,
/// aggregated by IP, domain, whatever
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, TypeDef)]
pub struct TrafficStatsSummary {
    /// total number of bytes
    pub bytes: u64,
    /// total number of packets
    pub pkts: u64,
    /// if the flow had enough packets and duration: the maximum
    /// burst we observed (over the configured time window)
    pub burst_pkt_rate: Option<f64>,
    pub burst_byte_rate: Option<f64>,
    // same as above but the average rate over the last one minute.
    // if the total duration was < 1min: over the total duration.
    pub last_min_pkt_rate: Option<f64>,
    pub last_min_byte_rate: Option<f64>,

    /// Lost bytes, as indicated by SACK blocks.
    pub lost_bytes: Option<u64>,

    pub rtt_stats_ms: Option<ExportedSimpleStats>,
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, TypeDef)]
pub struct BidirTrafficStatsSummary {
    pub rx: TrafficStatsSummary,
    pub tx: TrafficStatsSummary,
}

impl Display for TrafficStatsSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}; Last Minute: {} {}; Burst: {} {}; Loss: {}, RTT: {}",
            pretty_print_si_units(Some(self.bytes as f64), "B"),
            pretty_print_si_units(Some(self.pkts as f64), "Pkt"),
            pretty_print_si_units(self.last_min_byte_rate, "B/s"),
            pretty_print_si_units(self.last_min_pkt_rate, "Pkt/s"),
            pretty_print_si_units(self.burst_byte_rate, "B/s"),
            pretty_print_si_units(self.burst_pkt_rate, "Pkt/s"),
            pretty_print_si_units(self.lost_bytes.map(|b| b as f64), "B"),
            match &self.rtt_stats_ms {
                Some(rtt) => rtt.to_string(),
                None => "None".to_owned(),
            }
        )?;
        Ok(())
    }
}

/// Used for exported data (to UI, storage, etc.)
/// A detailed history of the bandwdith/rate of a unidirectional flow.
/// A flow can be anything: A 5-tuple, aggregated by IP, domain, whatever.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TypeDef)]
pub struct BandwidthHistory {
    #[type_def(type_of = "u64")]
    #[serde_as(as = "serde_with::TimestampMicroSeconds")]
    #[serde(rename = "last_time_us")]
    /// The timestamp of the end time of the exported bucktes. This might
    /// will usually be the current walltime and might not be the
    /// time of the last received packet.
    pub end_bucket_time: DateTime<Utc>,
    #[type_def(type_of = "u64")]
    #[serde_as(as = "serde_with::DurationMicroSeconds<u64>")]
    #[serde(rename = "total_duration_us")]
    /// The total time the flow was active (time between first and last
    /// packet)
    pub total_duration: std::time::Duration,

    /// Maps a label to an exported bucket (for bytes) for a certain
    /// bucket size  
    pub byte_buckets: HashMap<String, ExportedBuckets>,
    /// Maps a label to an exported bucket (for packets) for a certain
    /// bucket size  
    pub pkt_buckets: HashMap<String, ExportedBuckets>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TypeDef)]
pub struct BidirBandwidthHistory {
    pub rx: BandwidthHistory,
    pub tx: BandwidthHistory,
}

/// Track statistics for a unidirectional flow (can be per 5-tuple, or higher aggregations).
/// It keeps track of total number of bytes and packets, timestamp for first and last packet
/// seen, the peak burst rate over the given `burst_time_window` time frame, and a history of
/// the bandwidth over the last 5sec, 1min, 1hr.
#[derive(Clone, Debug, PartialEq)]
pub struct TrafficStats {
    /// Total bytes
    bytes: u64,
    /// Total packets
    packets: u64,
    /// Lost bytes, as indicated by SACK blocks. None for non-TCP connections
    lost_bytes: Option<u64>,
    /// Timestamp of first packet
    first_time: DateTime<Utc>,
    /// Timestamp of last packet
    last_time: DateTime<Utc>,
    /// Tracks the maximum burst rate
    max_burst_rate: MaxBurstRate,
    last_5_sec: BucketedTimeSeries<DateTime<Utc>>,
    last_min: BucketedTimeSeries<DateTime<Utc>>,
    last_hour: BucketedTimeSeries<DateTime<Utc>>,
    rtt_stats_ms: Option<SimpleStats>,
}

impl TrafficStats {
    /// How long does a unidirectional flow have to be active before we start returning rates
    /// for it.
    /// TODO: 10ms is what I used previously. Wondering if we should bump that to 1min
    const MIN_ACTIVE_TIME_FOR_RATE_MILLIS: i64 = 10;
    /// now: the time of the first packet
    /// burst_time_window: the time window used for bursts. E.g., 10ms
    pub fn new(now: DateTime<Utc>, burst_time_window: Duration) -> TrafficStats {
        TrafficStats {
            bytes: 0,
            packets: 0,
            lost_bytes: None,
            first_time: now,
            last_time: now,
            max_burst_rate: MaxBurstRate::new(burst_time_window),
            last_5_sec: BucketedTimeSeries::new_with_create_time(
                now,
                Duration::from_millis(10),
                500,
            ),
            last_min: BucketedTimeSeries::new_with_create_time(
                now,
                Duration::from_millis(500),
                120,
            ),
            last_hour: BucketedTimeSeries::new_with_create_time(now, Duration::from_secs(30), 120),
            rtt_stats_ms: None,
        }
    }

    pub fn add_packet_with_time(&mut self, bytes: u64, timestamp: DateTime<Utc>) {
        if (timestamp - self.last_time) < chrono::Duration::seconds(-10) {
            /*
            TODO: SHOULD CLEAR OR DO SOMETHING USEFUL
            Also can't warn! because wasm
            warn!(
                "Time went backwards: last_time: {} vs. now: {}. Resetting stats",
                self.last_time, now
            );
            */
        }
        if self.first_time > timestamp {
            // TS is before now. Need to return since we take the difference between
            return;
        }
        self.last_time = timestamp;

        self.bytes += bytes;
        self.packets += 1;
        self.max_burst_rate.add_packet_with_time(bytes, timestamp);
        self.last_5_sec.add_value(bytes, timestamp);
        self.last_min.add_value(bytes, timestamp);
        self.last_hour.add_value(bytes, timestamp);
    }

    pub fn advance_time(&mut self, now: DateTime<Utc>) {
        if now < self.last_time {
            // check for time going backwards
            return;
        }
        self.last_time = now;
        self.last_5_sec.update_buckets(now);
        self.last_min.update_buckets(now);
        self.last_hour.update_buckets(now);
    }

    pub fn set_lost_bytes(&mut self, lost_bytes: u64) {
        if lost_bytes == 0 {
            self.lost_bytes = None;
        } else {
            self.lost_bytes = Some(lost_bytes);
        }
    }

    pub fn add_lost_bytes(&mut self, new_lost_bytes: u64) {
        if new_lost_bytes == 0 {
            return;
        }
        if self.lost_bytes.is_none() {
            self.lost_bytes = Some(new_lost_bytes)
        } else {
            *self.lost_bytes.as_mut().unwrap() += new_lost_bytes;
        }
    }

    pub fn add_rtt_sample(&mut self, rtt_sample: chrono::Duration) {
        let rtt_stats_ms = self.rtt_stats_ms.get_or_insert_with(SimpleStats::new);
        let rtt_millis = rtt_sample.num_nanoseconds().unwrap() as f64 / 1e6;
        rtt_stats_ms.add_sample(rtt_millis);
    }

    pub fn as_stats_summary(&mut self, now: DateTime<Utc>) -> TrafficStatsSummary {
        self.advance_time(now);
        let active_dur = self.last_time - self.first_time;
        let (pkt_rate, byte_rate) =
            if active_dur > chrono::Duration::milliseconds(Self::MIN_ACTIVE_TIME_FOR_RATE_MILLIS) {
                let dur_sec =
                    Duration::min(self.last_min.total_duration(), active_dur.to_std().unwrap())
                        .as_secs_f64();

                (
                    Some(self.last_min.get_num_entries() as f64 / dur_sec),
                    Some(self.last_min.get_sum() as f64 / dur_sec),
                )
            } else {
                (None, None)
            };
        TrafficStatsSummary {
            bytes: self.bytes,
            pkts: self.packets,
            burst_pkt_rate: self.max_burst_rate.get_packet_rate(),
            burst_byte_rate: self.max_burst_rate.get_byte_rate(),
            last_min_pkt_rate: pkt_rate,
            last_min_byte_rate: byte_rate,
            lost_bytes: self.lost_bytes,
            rtt_stats_ms: self.rtt_stats_ms.clone().map(Into::into),
        }
    }

    pub fn as_bandwidth_history(&mut self, now: DateTime<Utc>) -> BandwidthHistory {
        self.advance_time(now);
        let mut byte_buckets = HashMap::new();
        let mut pkt_buckets = HashMap::new();
        byte_buckets.insert(
            "Last 5 Seconds".to_owned(),
            self.last_5_sec.export_sum_buckets(),
        );
        byte_buckets.insert("Last Minute".to_owned(), self.last_min.export_sum_buckets());
        byte_buckets.insert("Last Hour".to_owned(), self.last_hour.export_sum_buckets());
        pkt_buckets.insert(
            "Last 5 Seconds".to_owned(),
            self.last_5_sec.export_cnt_buckets(),
        );
        pkt_buckets.insert("Last Minute".to_owned(), self.last_min.export_cnt_buckets());
        pkt_buckets.insert("Last Hour".to_owned(), self.last_hour.export_cnt_buckets());
        BandwidthHistory {
            end_bucket_time: now,
            total_duration: (self.last_time - self.first_time).to_std().unwrap(),
            byte_buckets,
            pkt_buckets,
        }
    }
}

/// Keeps track of bi-directional TrafficStats.
/// Each direction will only be instantiated once we see a packets for that
/// direction
#[derive(Clone, Debug, PartialEq)]
pub struct BidirectionalStats {
    burst_time_window: Duration,
    pub rx: Option<TrafficStats>,
    pub tx: Option<TrafficStats>,
}

impl BidirectionalStats {
    pub fn new(burst_time_window: Duration) -> BidirectionalStats {
        BidirectionalStats {
            burst_time_window,
            rx: None,
            tx: None,
        }
    }

    /// return tx or create it
    fn tx_or_create(&mut self, timestamp: DateTime<Utc>) -> &mut TrafficStats {
        if self.tx.is_none() {
            self.tx = Some(TrafficStats::new(timestamp, self.burst_time_window));
        }
        self.tx.as_mut().unwrap()
    }

    /// return rx or create it
    fn rx_or_create(&mut self, timestamp: DateTime<Utc>) -> &mut TrafficStats {
        if self.rx.is_none() {
            self.rx = Some(TrafficStats::new(timestamp, self.burst_time_window));
        }
        self.rx.as_mut().unwrap()
    }

    pub fn add_packet_with_time(&mut self, is_tx: bool, bytes: u64, now: DateTime<Utc>) {
        if is_tx {
            self.tx_or_create(now).add_packet_with_time(bytes, now);
        } else {
            self.rx_or_create(now).add_packet_with_time(bytes, now);
        }
    }

    pub fn add_new_lost_bytes(&mut self, is_tx: bool, lost_bytes: u64, now: DateTime<Utc>) {
        if is_tx {
            self.tx_or_create(now).add_lost_bytes(lost_bytes);
        } else {
            self.rx_or_create(now).add_lost_bytes(lost_bytes);
        }
    }

    pub fn add_rtt_sample(
        &mut self,
        is_tx: bool,
        rtt: Option<chrono::Duration>,
        now: DateTime<Utc>,
    ) {
        if let Some(rtt) = rtt {
            if is_tx {
                self.tx_or_create(now).add_rtt_sample(rtt);
            } else {
                self.rx_or_create(now).add_rtt_sample(rtt);
            }
        }
    }

    /// call `advance_time` on both directions (if the exist)
    pub fn advance_time(&mut self, now: DateTime<Utc>) {
        if let Some(s) = self.tx.as_mut() {
            s.advance_time(now)
        }
        if let Some(s) = self.rx.as_mut() {
            s.advance_time(now)
        }
    }

    fn to_stats_summary(s: &mut Option<TrafficStats>, now: DateTime<Utc>) -> TrafficStatsSummary {
        s.as_mut()
            .map(|s| s.as_stats_summary(now))
            .unwrap_or_default()
    }

    pub fn tx_stats_summary(&mut self, now: DateTime<Utc>) -> TrafficStatsSummary {
        Self::to_stats_summary(&mut self.tx, now)
    }

    pub fn rx_stats_summary(&mut self, now: DateTime<Utc>) -> TrafficStatsSummary {
        Self::to_stats_summary(&mut self.rx, now)
    }

    fn to_bandwidth_history(
        s: &mut Option<TrafficStats>,
        burst_time_window: Duration,
        now: DateTime<Utc>,
    ) -> BandwidthHistory {
        s.as_mut()
            .map(|s| s.as_bandwidth_history(now))
            .unwrap_or_else(|| TrafficStats::new(now, burst_time_window).as_bandwidth_history(now))
    }

    pub fn as_bidir_stats_summary(&mut self, now: DateTime<Utc>) -> BidirTrafficStatsSummary {
        BidirTrafficStatsSummary {
            rx: self.rx_stats_summary(now),
            tx: self.tx_stats_summary(now),
        }
    }

    pub fn as_bidir_bandwidth_history(&mut self, now: DateTime<Utc>) -> BidirBandwidthHistory {
        BidirBandwidthHistory {
            rx: Self::to_bandwidth_history(&mut self.rx, self.burst_time_window, now),
            tx: Self::to_bandwidth_history(&mut self.tx, self.burst_time_window, now),
        }
    }
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

#[cfg(test)]
mod test {
    use super::*;

    use approx::assert_relative_eq;

    #[test]
    fn test_burst_rate() {
        let now = Utc::now();
        let mut burst_rate = MaxBurstRate::new(std::time::Duration::from_millis(10));
        assert_eq!(burst_rate.get_byte_rate(), None);
        assert_eq!(burst_rate.get_packet_rate(), None);

        // Duration is 0: no rate
        burst_rate.add_packet_with_time(100, now);
        assert_eq!(burst_rate.get_byte_rate(), None);
        assert_eq!(burst_rate.get_packet_rate(), None);
        burst_rate.add_packet_with_time(100, now);
        assert_eq!(burst_rate.get_byte_rate(), None);

        // Duration is only 9ms ==> rate is still None
        burst_rate.add_packet_with_time(100, now + chrono::Duration::milliseconds(9));
        assert_eq!(burst_rate.get_byte_rate(), None);
        assert_eq!(burst_rate.get_packet_rate(), None);

        // Now we have enough to get a rate
        burst_rate.add_packet_with_time(150, now + chrono::Duration::milliseconds(15));

        // At this point the first two packets (at time `now`) have already rotated out of the buckets.
        // However, the still contributed to maximum rate, since the time windows with the
        // most bytes was the first 10ms (3* 100 bytes)
        assert_eq!(burst_rate.get_byte_rate().unwrap(), 30. * 1000.); // 300 bytes / 10 ms
        assert_eq!(burst_rate.get_packet_rate().unwrap(), 300.0); // 3 pkts / 10ms

        assert_eq!(burst_rate.to_string(), "30.00 KByte/s, 300.00 Pkts/s");

        // Add more packets. Now the max is the time interval starting at 9ms.
        burst_rate.add_packet_with_time(50, now + chrono::Duration::milliseconds(16));
        burst_rate.add_packet_with_time(200, now + chrono::Duration::milliseconds(17));
        burst_rate.add_packet_with_time(150, now + chrono::Duration::milliseconds(18));
        // bytes: 100 + 150 + 50 + 200 + 150 = 650 bytes ==> 650 / 10ms
        assert_eq!(burst_rate.get_byte_rate().unwrap(), 65. * 1000.);
        // packets: 6 ==> 6 / 10ms
        assert_eq!(burst_rate.get_packet_rate().unwrap(), 500.0);

        // The max byte rate and max packet rate can come from different time windows.
        // Lets add a single large packet.
        burst_rate.add_packet_with_time(1500, now + chrono::Duration::milliseconds(30));
        assert_eq!(burst_rate.get_byte_rate().unwrap(), 150. * 1000.);
        assert_eq!(burst_rate.get_packet_rate().unwrap(), 500.0);
    }

    #[test]
    fn test_bidir_traffic_stats_summary_1() {
        let start = Utc::now();
        let mut bds = BidirectionalStats::new(Duration::from_millis(10));
        assert_eq!(bds.tx_stats_summary(start), TrafficStatsSummary::default());
        assert_eq!(bds.rx_stats_summary(start), TrafficStatsSummary::default());

        // Add a TX packet ==> only TX should have a non-zero summary stat
        bds.add_packet_with_time(true, 100, start);
        assert_eq!(
            bds.tx_stats_summary(start),
            TrafficStatsSummary {
                bytes: 100,
                pkts: 1,
                ..Default::default()
            }
        );
        assert_eq!(bds.rx_stats_summary(start), TrafficStatsSummary::default());

        // Add two rx packets.
        bds.add_packet_with_time(false, 200, start);
        bds.add_packet_with_time(false, 200, start);
        // tx stats are unchanged
        assert_eq!(
            bds.tx_stats_summary(start),
            TrafficStatsSummary {
                bytes: 100,
                pkts: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            bds.rx_stats_summary(start),
            TrafficStatsSummary {
                bytes: 400,
                pkts: 2,
                ..Default::default()
            }
        );

        let bidir_summary = bds.as_bidir_stats_summary(start);
        assert_eq!(
            bidir_summary.rx,
            TrafficStatsSummary {
                bytes: 400,
                pkts: 2,
                ..Default::default()
            }
        );
        assert_eq!(
            bidir_summary.tx,
            TrafficStatsSummary {
                bytes: 100,
                pkts: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_bidir_traffic_stats_summary_2() {
        let start = Utc::now();
        let mut bds = BidirectionalStats::new(Duration::from_millis(10));
        assert_eq!(bds.tx_stats_summary(start), TrafficStatsSummary::default());
        assert_eq!(bds.rx_stats_summary(start), TrafficStatsSummary::default());

        // Add a RX packet ==> only RX should have a non-zero summary stat
        bds.add_packet_with_time(false, 100, start);
        assert_eq!(
            bds.rx_stats_summary(start),
            TrafficStatsSummary {
                bytes: 100,
                pkts: 1,
                ..Default::default()
            }
        );
        assert_eq!(bds.tx_stats_summary(start), TrafficStatsSummary::default());
    }

    #[test]
    fn test_bidir_traffic_stats_summary_advance_time() {
        let start = Utc::now();
        let mut bds = BidirectionalStats::new(Duration::from_millis(10));

        let mut t = start;
        for _ in 1..=70 {
            t += Duration::from_secs(1);
            bds.add_packet_with_time(true, 100, t);
            bds.add_packet_with_time(false, 200, t);
        }
        assert_eq!(
            bds.tx_stats_summary(t).burst_byte_rate.unwrap(),
            10_000. /* 100 bytes / 10ms */
        );
        assert_eq!(
            bds.rx_stats_summary(t).burst_byte_rate.unwrap(),
            20_000. /* 2000 bytes / 10ms */
        );
        assert_eq!(bds.tx_stats_summary(t).last_min_byte_rate.unwrap(), 100.);
        assert_eq!(bds.rx_stats_summary(t).last_min_byte_rate.unwrap(), 200.);
    }

    #[test]
    fn test_traffic_stats_summary() {
        let start = Utc::now();
        let mut stats = TrafficStats::new(start, Duration::from_millis(10));
        // TODO(sorta): the connection.rs has a pretty comprehensive test for
        // the burst rate, so not adding it here for now. Should probably
        // eventually test it here too!

        let mut t = start;
        // For 30 sec: add one 100byte packet per sec.
        for _ in 1..=30 {
            t += Duration::from_secs(1);
            stats.add_packet_with_time(100, t);
        }
        assert_eq!(stats.first_time, start);
        assert_eq!(stats.last_time, t);
        assert_eq!(stats.as_stats_summary(t).bytes, 3000);
        assert_eq!(stats.as_stats_summary(t).pkts, 30);
        assert_eq!(stats.as_stats_summary(t).last_min_byte_rate.unwrap(), 100.);
        assert_eq!(stats.as_stats_summary(t).last_min_pkt_rate.unwrap(), 1.);

        // For 30sec: add two 100 bytes packets per sec
        // Now we have 1 min of data
        for _ in 1..=30 {
            t += Duration::from_secs(1);
            stats.add_packet_with_time(100, t);
            stats.add_packet_with_time(100, t);
        }
        assert_eq!(stats.as_stats_summary(t).bytes, 9_000);
        assert_eq!(stats.as_stats_summary(t).pkts, 90);
        assert_eq!(stats.as_stats_summary(t).last_min_byte_rate.unwrap(), 150.);
        assert_eq!(stats.as_stats_summary(t).last_min_pkt_rate.unwrap(), 1.5);

        // For 60sec: add three 150 bytes packets per sec
        for _ in 1..=60 {
            t += Duration::from_secs(1);
            stats.add_packet_with_time(150, t);
            stats.add_packet_with_time(150, t);
            stats.add_packet_with_time(150, t);
        }
        assert_eq!(stats.last_time, t);
        assert_eq!(
            stats.as_stats_summary(t).bytes,
            9_000 + 27_000 /* 27k == 60 * 3 * 150 */
        );
        assert_eq!(stats.as_stats_summary(t).pkts, 90 + 180);
        // only the last minute should influence the rates
        assert_eq!(stats.as_stats_summary(t).last_min_byte_rate.unwrap(), 450.);
        assert_eq!(stats.as_stats_summary(t).last_min_pkt_rate.unwrap(), 3.0);

        // Check again with a time > 60sec in the future
        t += Duration::from_secs(60);
        assert_eq!(stats.as_stats_summary(t).last_min_byte_rate.unwrap(), 0.);
        assert_eq!(stats.as_stats_summary(t).last_min_pkt_rate.unwrap(), 0.);
    }

    #[test]
    fn test_traffic_stats_bandwidth() {
        let start = Utc::now();
        let mut stats = TrafficStats::new(start, Duration::from_millis(10));

        let mut t = start;
        // for 3 secs, one packet every 10ms
        stats.add_packet_with_time(100, t);
        for _ in 0..299 {
            t += Duration::from_millis(10);
            stats.add_packet_with_time(100, t);
        }
        let hist = stats.as_bandwidth_history(t);
        let last_5_sec_bytes = hist.byte_buckets.get("Last 5 Seconds").unwrap();
        let last_5_sec_pkts = hist.pkt_buckets.get("Last 5 Seconds").unwrap();
        let last_min_bytes = hist.byte_buckets.get("Last Minute").unwrap();
        let last_min_pkts = hist.pkt_buckets.get("Last Minute").unwrap();
        let last_hour_bytes = hist.byte_buckets.get("Last Hour").unwrap();
        let last_hour_pkts = hist.pkt_buckets.get("Last Hour").unwrap();
        assert_eq!(
            last_5_sec_bytes.bucket_time_window,
            Duration::from_millis(10)
        );
        assert_eq!(last_5_sec_bytes.buckets[0..200], [0; 200]);
        assert_eq!(last_5_sec_bytes.buckets[200..], [100; 300]);
        assert_eq!(last_5_sec_pkts.buckets[0..200], [0; 200]);
        assert_eq!(last_5_sec_pkts.buckets[200..], [1; 300]);

        // Last min buckets
        assert_eq!(
            last_min_bytes.bucket_time_window,
            Duration::from_millis(500)
        );
        assert_eq!(last_min_bytes.buckets[0..113], [0; 113]);
        assert_eq!(last_min_bytes.buckets[114..120], [5_000; 6]);
        assert_eq!(last_min_pkts.buckets[0..113], [0; 113]);
        assert_eq!(last_min_pkts.buckets[114..120], [50; 6]);

        // Last hour buckets
        assert_eq!(last_hour_bytes.bucket_time_window, Duration::from_secs(30));
        assert_eq!(last_hour_bytes.buckets[0..59], [0; 59]);
        assert_eq!(last_hour_bytes.buckets[119], 30_000);
        assert_eq!(last_hour_pkts.buckets[0..119], [0; 119]);
        assert_eq!(last_hour_pkts.buckets[119], 300);

        // advance time, everything should be 0
        t += Duration::from_secs(4000);
        let hist = stats.as_bandwidth_history(t);
        let last_5_sec_bytes = hist.byte_buckets.get("Last 5 Seconds").unwrap();
        let last_5_sec_pkts = hist.pkt_buckets.get("Last 5 Seconds").unwrap();
        let last_min_bytes = hist.byte_buckets.get("Last Minute").unwrap();
        let last_min_pkts = hist.pkt_buckets.get("Last Minute").unwrap();
        let last_hour_bytes = hist.byte_buckets.get("Last Hour").unwrap();
        let last_hour_pkts = hist.pkt_buckets.get("Last Hour").unwrap();
        assert_eq!(last_5_sec_bytes.buckets, [0; 500]);
        assert_eq!(last_min_bytes.buckets, [0; 120]);
        assert_eq!(last_hour_bytes.buckets, [0; 120]);
        assert_eq!(last_5_sec_pkts.buckets, [0; 500]);
        assert_eq!(last_min_pkts.buckets, [0; 120]);
        assert_eq!(last_hour_pkts.buckets, [0; 120]);
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
