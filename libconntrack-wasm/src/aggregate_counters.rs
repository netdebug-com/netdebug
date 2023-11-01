use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use common_wasm::timeseries_stats::{BucketIndex, BucketedTimeSeries};
use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef;

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TypeDef)]
pub enum AggregateCounterKind {
    DnsDstDomain { name: String },
    Application { name: String },
    ConnectionTracker,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TypeDef)]
pub struct AggregateCounter {
    pub kind: AggregateCounterKind,
    pub counts: HashMap<String, BucketedTimeSeries>, // "label" --> "BucketedTimeSeries"
}

/**
 * Aggregate Counters group sets of BucketedTimeSeries counters together at different time resolutions and
 * try to represent the whole.
 * It's surprisingly non-trivial.  Roughly inspired by https://github.com/facebook/folly/blob/main/folly/stats/BucketedTimeSeries.h
 */
impl AggregateCounter {
    /**
     * s
     */
    pub fn new(kind: AggregateCounterKind) -> AggregateCounter {
        AggregateCounter {
            kind,
            counts: HashMap::new(),
        }
    }

    pub fn update(&mut self, count: u64) {
        self.update_with_time(count, Instant::now())
    }

    pub fn update_with_time(&mut self, count: u64, now: Instant) {
        for ts in &mut self.counts.values_mut() {
            ts.add_value(count, now);
        }
    }

    pub fn get_kind(&self) -> AggregateCounterKind {
        self.kind.clone()
    }

    pub fn add_time_series(
        &mut self,
        label: String,
        time_window: Duration,
        num_buckets: BucketIndex,
    ) {
        let ts = BucketedTimeSeries::new(time_window, num_buckets);
        self.counts.insert(label, ts);
    }
}

impl std::fmt::Display for AggregateCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} :: ", self.kind)?;
        for (name, ts) in &self.counts {
            write!(
                f,
                "{} :: {} entries {} avg",
                name,
                ts.get_num_entries(),
                ts.get_avg_per_duration()
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, TypeDef)]
pub struct TrafficCounters {
    pub send: AggregateCounter,
    pub recv: AggregateCounter,
    // TODO: add drops here
}

impl TrafficCounters {
    pub fn new() -> TrafficCounters {
        TrafficCounters {
            send: TrafficCounters::create_aggregate_counter(),
            recv: TrafficCounters::create_aggregate_counter(),
        }
    }
    /**
     * Create the aggregate counter for this connection tracker
     * Create them for:
     *  - 10ms buckets over last 5 seconds
     *  - 1second buckets over last 60 seconds
     *  - 1 minute buckets over last hour
     */
    fn create_aggregate_counter() -> AggregateCounter {
        let mut agg_counter = AggregateCounter::new(AggregateCounterKind::ConnectionTracker);
        agg_counter.add_time_series(
            "Last 5 Seconds".to_string(),
            std::time::Duration::from_millis(10),
            500,
        );
        agg_counter.add_time_series(
            "Last Minute".to_string(),
            std::time::Duration::from_secs(1),
            60,
        );
        agg_counter.add_time_series(
            "Last Hour".to_string(),
            std::time::Duration::from_secs(60),
            60,
        );

        agg_counter
    }

    /**
     * Update the send or recv byte traffic counters, depending on whether
     * the src of the packet is local or not
     */

    pub fn update_bytes(&mut self, src_is_local: bool, len: u64) {
        if src_is_local {
            self.send.update(len);
        } else {
            self.recv.update(len);
        }
    }
}
