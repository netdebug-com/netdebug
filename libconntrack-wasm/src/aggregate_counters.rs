use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use common_wasm::timeseries_stats::{BucketIndex, BucketedTimeSeries};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AggregateCounterKind {
    DnsDstDomain,
    Application,
    ConnectionTracker,
}

impl Copy for AggregateCounterKind {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateCounter {
    pub kind: AggregateCounterKind,
    pub name: String,
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
    pub fn new(kind: AggregateCounterKind, name: String) -> AggregateCounter {
        AggregateCounter {
            kind,
            name,
            counts: HashMap::new(),
        }
    }

    pub fn update(&mut self, count: u64) {
        self.update_with_time(count, Instant::now())
    }

    fn update_with_time(&mut self, count: u64, now: Instant) {
        for ts in &mut self.counts.values_mut() {
            ts.add_value(count, now);
        }
    }

    pub fn get_info(&self) -> (String, AggregateCounterKind) {
        (self.name.clone(), self.kind)
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
        write!(f, "{} :: ", self.name)?;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateCounterConnectionTracker {
    pub send: AggregateCounter,
    pub recv: AggregateCounter,
}
