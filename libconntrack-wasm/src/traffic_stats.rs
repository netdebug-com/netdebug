use std::{collections::HashMap, fmt::Display, time::Duration};

use chrono::{DateTime, Utc};
use common_wasm::timeseries_stats::{BucketedTimeSeries, ExportedBuckets};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use typescript_type_def::TypeDef;

use crate::pretty_print_si_units;

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
            "{} {}; Last Minute: {} {}; Burst: {} {}",
            pretty_print_si_units(Some(self.bytes as f64), "B"),
            pretty_print_si_units(Some(self.pkts as f64), "Pkt"),
            pretty_print_si_units(self.last_min_byte_rate, "B/s"),
            pretty_print_si_units(self.last_min_pkt_rate, "Pkt/s"),
            pretty_print_si_units(self.burst_byte_rate, "B/s"),
            pretty_print_si_units(self.burst_pkt_rate, "Pkt/s"),
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficStats {
    /// Total bytes
    bytes: u64,
    /// Total packets
    packets: u64,
    /// Timestamp of first packet
    first_time: DateTime<Utc>,
    /// Timestamp of last packet
    last_time: DateTime<Utc>,
    /// Tracks the maximum burst rate
    max_burst_rate: MaxBurstRate,
    last_5_sec: BucketedTimeSeries<DateTime<Utc>>,
    last_min: BucketedTimeSeries<DateTime<Utc>>,
    last_hour: BucketedTimeSeries<DateTime<Utc>>,
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
            first_time: now,
            last_time: now,
            max_burst_rate: MaxBurstRate::new(burst_time_window),
            last_5_sec: BucketedTimeSeries::new_with_create_time(
                now,
                Duration::from_millis(10),
                500,
            ),
            last_min: BucketedTimeSeries::new_with_create_time(now, Duration::from_secs(1), 60),
            last_hour: BucketedTimeSeries::new_with_create_time(now, Duration::from_secs(60), 60),
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

    /// Advances the wall-time but does *NOT* update `last_packet_time`. It is used
    /// to rotate the `BucketedTimeSeries` buckets
    pub fn advance_time(&mut self, now: DateTime<Utc>) {
        if now < self.last_time {
            // check for time going backwards
            return;
        }
        self.last_5_sec.update_buckets(now);
        self.last_min.update_buckets(now);
        self.last_hour.update_buckets(now);
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// call `advance_time` on both directions (if the exist)
    pub fn advance_time(&mut self, now: DateTime<Utc>) {
        self.tx.as_mut().map(|s| s.advance_time(now));
        self.rx.as_mut().map(|s| s.advance_time(now));
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

    pub fn as_bidir_bandwidth_history(&mut self, now: DateTime<Utc>) -> BidirBandwidthHistory {
        BidirBandwidthHistory {
            rx: Self::to_bandwidth_history(&mut self.rx, self.burst_time_window, now),
            tx: Self::to_bandwidth_history(&mut self.tx, self.burst_time_window, now),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
        assert_eq!(last_min_bytes.bucket_time_window, Duration::from_secs(1));
        assert_eq!(last_min_bytes.buckets[0..57], [0; 57]);
        assert_eq!(last_min_bytes.buckets[57..60], [10_000; 3]);
        assert_eq!(last_min_pkts.buckets[0..57], [0; 57]);
        assert_eq!(last_min_pkts.buckets[57..60], [100; 3]);

        // Last hour buckets
        assert_eq!(last_hour_bytes.bucket_time_window, Duration::from_secs(60));
        assert_eq!(last_hour_bytes.buckets[0..59], [0; 59]);
        assert_eq!(last_hour_bytes.buckets[59], 30_000);
        assert_eq!(last_hour_pkts.buckets[0..59], [0; 59]);
        assert_eq!(last_hour_pkts.buckets[59], 300);

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
        assert_eq!(last_min_bytes.buckets, [0; 60]);
        assert_eq!(last_hour_bytes.buckets, [0; 60]);
        assert_eq!(last_5_sec_pkts.buckets, [0; 500]);
        assert_eq!(last_min_pkts.buckets, [0; 60]);
        assert_eq!(last_hour_pkts.buckets, [0; 60]);
    }
}
