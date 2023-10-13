use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/**
 * Aggregate Counters group sets of BucketedTimeSeries counters together at different time resolutions and
 * try to represent the whole.
 * It's surprisingly non-trivial.  Roughly inspired by https://github.com/facebook/folly/blob/main/folly/stats/BucketedTimeSeries.h
 *
 * Store the data in a circulate buffer of counters (the 'time window') and clear parts
 * of the time window on update.  How much we clear depends on how far apart the new
 * update is relative to the last update.
 *
 * 1. Same wrap + bucker : clear nothing
 * 2. Same wrap + later bucket: clear up to the new bucket (including the new bucket index)
 * 3. Wrap is +1 from prev epoch: clear to the end, and from the beginnig to the new bucket
 * 4. Wrap is +2 or more from prev warp; clear everything
 *
 */

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CounterBucket {
    pub sum: u64,
    pub num_entries: u64,
}

impl CounterBucket {
    pub fn new() -> CounterBucket {
        CounterBucket {
            sum: 0,
            num_entries: 0,
        }
    }

    pub fn add(&mut self, value: u64) {
        // try to do some sane things to avoid wrapping counters
        self.sum = self.sum.saturating_add(value);
        self.num_entries = self.num_entries.saturating_add(1);
    }

    pub fn clear(&mut self) {
        self.sum = 0;
        self.num_entries = 0;
    }
}
type BucketIndex = usize;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BucketedTimeSeries {
    /**
     * Instant can't be serialized and has no default, so we can't just skip it.  But we can
     * make it an Option<Instant> which has a default and just panic if someone tries to update
     * the timeseries when created_time is None.
     *
     * A bit fugly, but I'm moving on to bigger things.
     */
    #[serde(skip)]
    pub created_time: Option<Instant>,
    pub bucket_time_window: Duration,
    pub buckets: Vec<CounterBucket>,
    pub num_buckets: BucketIndex,
    pub last_used_bucket: usize,
    /// Identifies the time range of the buckets so two updates from different times that map to the
    /// same bucket don't get confused
    pub last_num_wraps: BucketIndex, // the number of times the counter has wrapped
}
impl BucketedTimeSeries {
    /**
     * Create a new BucketedTimeSeries
     */
    pub fn new(bucket_time_window: Duration, num_buckets: usize) -> BucketedTimeSeries {
        BucketedTimeSeries::new_with_create_time(Instant::now(), bucket_time_window, num_buckets)
    }

    /**
     * Like `BucketedTimeSeries::new()` but we can specify the start time; useful for deterministic testing
     */
    pub fn new_with_create_time(
        created_time: Instant,
        bucket_time_window: Duration,
        num_buckets: usize,
    ) -> BucketedTimeSeries {
        BucketedTimeSeries {
            created_time: Some(created_time),
            // store Duration in Micros for faster calcs
            bucket_time_window,
            buckets: vec![CounterBucket::new(); num_buckets],
            num_buckets,
            last_used_bucket: 0,
            last_num_wraps: 0,
        }
    }
    fn update_with_time(&mut self, count: u64, now: Instant) {
        // how much time from system start?
        let offset_time = (now
            - self
                .created_time
                .expect("Can't updated a serialized BucketedTimeSeries"))
        .as_micros();
        // break that down by the time series time window
        // thought about storing bucket_time_window as micros to avoid the conversion here but was premature optimization
        let quantized_time = offset_time / self.bucket_time_window.as_micros();
        let bucket_index = quantized_time
            .checked_rem(self.num_buckets as u128)
            .unwrap() as usize; // this is ok as this will only return None if self.num_buckets is zero
        let num_wraps = quantized_time
            .checked_div(self.num_buckets as u128)
            .unwrap() as usize;
        if (num_wraps - self.last_num_wraps) == 0 {
            // implicit: if bucket_index == self.last_bucket_used, then NOOP
            if bucket_index > self.last_used_bucket {
                // zero everything from just after the last bucket used to the new bucket (inclusive)
                for b in (self.last_used_bucket + 1)..=bucket_index {
                    self.buckets[b].clear();
                }
            } else if bucket_index < self.last_used_bucket {
                // recently old data, could happen if the caller was delayed; just allow it without updating
                // anything else
                self.buckets[bucket_index].add(count);
                return;
            }
        } else if (num_wraps - self.last_num_wraps) == 1 {
            // we wrapped one time relative to last update
            if bucket_index < self.last_used_bucket {
                // we wrapped, so need to zero everything from where we are to the end,
                for b in (self.last_used_bucket + 1)..self.num_buckets {
                    self.buckets[b].clear();
                }
                // .. and everything from the beginning to the new bucket_index
                for b in 0..=bucket_index {
                    self.buckets[b].clear();
                }
            } else if bucket_index >= self.last_used_bucket {
                // zero everything
                for b in 0..self.num_buckets {
                    self.buckets[b].clear();
                }
            }
        } else if num_wraps < self.last_num_wraps {
            panic!("Time went backward for our monotonic clock!?");
        } else {
            // wrap > (last_wrap + 1 ), so we need to zero all of our data
            for b in 0..self.num_buckets {
                self.buckets[b].clear();
            }
        }
        self.last_num_wraps = num_wraps;
        self.buckets[bucket_index].add(count);
        self.last_used_bucket = bucket_index;
    }

    /**
     * Get the sum of the counts stored.  Because we have a circular array that spans
     * the previous num_wraps to the current num_wraps, this is just a simple sum
     */
    pub fn get_sum(&self) -> u64 {
        self.buckets.iter().fold(0, |acc, cb| acc + cb.sum)
    }

    /**
     * Average the counts across the time window, taking into account the number of
     * entries in each bucket. Empty buckets count a single zero value, so this is a bit
     * funky.  Need to think if this is actually useful.
     */
    pub fn get_avg_count(&self) -> f64 {
        let mut sum = 0;
        let mut num_entries = 0;
        for b in &self.buckets {
            sum += b.sum;
            num_entries += b.num_entries;
        }
        sum as f64 / num_entries as f64
    }

    /****
     * Average over time, for the the length of the bucket's time
     */

    pub fn get_avg_per_duration(&self) -> f64 {
        let sum = self.get_sum() as f64;
        // has enough time passed that we could have used all of the buckets?
        if self.last_num_wraps == 0 {
            // No - compute a partial time
            sum / self.last_used_bucket as f64
        } else {
            sum / self.num_buckets as f64
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AggregateCounterKind {
    DnsDstDomain,
    Application,
    ConnectionTracker,
}

impl Copy for AggregateCounterKind {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AggregateCounter {
    kind: AggregateCounterKind,
    name: String,
    counts: Vec<BucketedTimeSeries>,
}

impl AggregateCounter {
    /**
     * s
     */
    pub fn new(kind: AggregateCounterKind, name: String) -> AggregateCounter {
        AggregateCounter {
            kind,
            name,
            counts: Vec::new(),
        }
    }

    pub fn update(&mut self, count: u64) {
        self.update_with_time(count, Instant::now())
    }

    fn update_with_time(&mut self, count: u64, now: Instant) {
        for ts in &mut self.counts {
            ts.update_with_time(count, now);
        }
    }

    pub fn get_info(&self) -> (String, AggregateCounterKind) {
        (self.name.clone(), self.kind)
    }

    pub fn add_time_series(&mut self, time_series: BucketedTimeSeries) {
        self.counts.push(time_series)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn time_series_basic() {
        let create_time = Instant::now();
        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 2);
        assert_eq!(ts.get_sum(), 0);
        // add 1 'right away'
        ts.update_with_time(1, create_time);
        assert_eq!(ts.get_sum(), 1);
        assert_eq!(ts.buckets[0].sum, 1);
        // add 2, 1 second after 'right away'
        ts.update_with_time(2, create_time + Duration::from_secs(1));
        assert_eq!(ts.buckets[1].sum, 2);
        assert_eq!(ts.get_sum(), 3);
        // add 3, 2 second after 'right away'; this should create a new wrap and clear the first bucket
        ts.update_with_time(3, create_time + Duration::from_secs(2));
        assert_eq!(ts.buckets[0].sum, 3);
        assert_eq!(ts.get_sum(), 5);
        assert_eq!(ts.last_num_wraps, 1);
        // add 4, 7 seconds after 'right away'; this should clear the time series as the new wrap > old wrap +1
        ts.update_with_time(4, create_time + Duration::from_secs(7));
        assert_eq!(ts.buckets[1].sum, 4);
        assert_eq!(ts.get_sum(), 4);
        assert_eq!(ts.last_num_wraps, 3);
    }

    #[test]
    fn time_series_harder() {
        // thanks to Gregor for showing this test fails
        let create_time = Instant::now();
        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 8);
        assert_eq!(ts.get_sum(), 0);
        // add 1 'right away'
        ts.update_with_time(1, create_time);
        assert_eq!(ts.get_sum(), 1);
        assert_eq!(ts.buckets[0].sum, 1);
        // add 2, 12 second after 'right away', so it should wrap, clear the full counter and be just '2'
        ts.update_with_time(2, create_time + Duration::from_secs(12));
        assert_eq!(ts.get_sum(), 2);
    }

    fn get_bucket_values(ts: &BucketedTimeSeries) -> Vec<u64> {
        let mut ret = Vec::new();
        for b in &ts.buckets {
            ret.push(b.sum);
        }
        ret
    }

    #[test]
    fn test_wrap_a() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.update_with_time(1, create_time);
        ts.update_with_time(2, create_time + dt);
        ts.update_with_time(3, create_time + 2 * dt);
        ts.update_with_time(4, create_time + 3 * dt);
        assert_eq!(get_bucket_values(&ts), &[1, 2, 3, 4]);
        ts.update_with_time(5, create_time + 4 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 2, 3, 4]);
        ts.update_with_time(6, create_time + 5 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 6, 3, 4]);
    }

    #[test]
    fn test_wrap_b() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.update_with_time(1, create_time);
        ts.update_with_time(2, create_time + dt);
        ts.update_with_time(3, create_time + 2 * dt);
        ts.update_with_time(4, create_time + 3 * dt);
        assert_eq!(get_bucket_values(&ts), &[1, 2, 3, 4]);
        ts.update_with_time(5, create_time + 5 * dt);
        assert_eq!(get_bucket_values(&ts), &[0, 5, 3, 4]);
    }

    #[test]
    fn test_wrap_c() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.update_with_time(1, create_time);
        ts.update_with_time(2, create_time + dt);
        ts.update_with_time(3, create_time + 2 * dt);
        ts.update_with_time(4, create_time + 3 * dt);
        ts.update_with_time(5, create_time + 4 * dt);
        ts.update_with_time(6, create_time + 5 * dt);
        ts.update_with_time(7, create_time + 6 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 6, 7, 4]);

        ts.update_with_time(8, create_time + 8 * dt);
        assert_eq!(get_bucket_values(&ts), &[8, 6, 7, 0]);
    }

    #[test]
    fn test_wrap_new_index_same_as_old_idx() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.update_with_time(1, create_time);
        ts.update_with_time(2, create_time + dt);
        ts.update_with_time(3, create_time + 2 * dt);
        ts.update_with_time(4, create_time + 3 * dt);
        ts.update_with_time(5, create_time + 7 * dt);
        assert_eq!(get_bucket_values(&ts), &[0, 0, 0, 5]);
    }

    #[test]
    fn test_wrap_index_larger_than_old_index() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.update_with_time(1, create_time);
        ts.update_with_time(2, create_time + dt);
        ts.update_with_time(3, create_time + 2 * dt);
        ts.update_with_time(4, create_time + 3 * dt);
        ts.update_with_time(5, create_time + 4 * dt);
        ts.update_with_time(6, create_time + 5 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 6, 3, 4]);

        ts.update_with_time(7, create_time + 10 * dt);
        assert_eq!(get_bucket_values(&ts), &[0, 0, 7, 0]);
    }

    #[test]
    fn test_wrap_many_wraps() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.update_with_time(1, create_time);
        ts.update_with_time(2, create_time + dt);
        ts.update_with_time(3, create_time + 2 * dt);
        ts.update_with_time(4, create_time + 3 * dt);
        ts.update_with_time(5, create_time + 4 * dt);
        ts.update_with_time(6, create_time + 5 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 6, 3, 4]);

        // wraps twice
        ts.update_with_time(7, create_time + 13 * dt);
        assert_eq!(get_bucket_values(&ts), &[0, 7, 0, 0]);
    }
}
