use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterBucket {
    pub sum: u64,
    pub max: u64,
    pub num_entries: u64,
}

impl CounterBucket {
    pub fn new() -> CounterBucket {
        CounterBucket::default()
    }

    pub fn add(&mut self, value: u64) {
        // try to do some sane things to avoid wrapping counters
        self.sum = self.sum.saturating_add(value);
        self.max = std::cmp::max(self.max, value);
        self.num_entries = self.num_entries.saturating_add(1);
    }

    pub fn avg(&self) -> f64 {
        if self.num_entries == 0 {
            0.0
        } else {
            self.sum as f64 / self.num_entries as f64
        }
    }

    pub fn clear(&mut self) {
        self.sum = 0;
        self.num_entries = 0;
        self.max = 0;
    }
}
pub type BucketIndex = usize;

/**
 * BucketedTimeSeries.
 * Roughly inspired by https://github.com/facebook/folly/blob/main/folly/stats/BucketedTimeSeries.h
 *
 * This allows us to track values across a sliding time window. E.g., number of bytes in the
 * last minute.
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

    pub fn add_value(&mut self, value: u64, now: Instant) {
        let idx = self.update_buckets(now);
        self.buckets[idx].add(value);
    }

    /// Update and rotate the buckets up to `now`. Return the bucket index that
    /// `now` points tp
    pub fn update_buckets(&mut self, now: Instant) -> usize {
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
        if num_wraps < self.last_num_wraps {
            panic!("Time went backward for our monotonic clock!?");
        } else if num_wraps == self.last_num_wraps {
            // implicit: if bucket_index == self.last_bucket_used, then NOOP
            if bucket_index > self.last_used_bucket {
                // zero everything from just after the last bucket used to the new bucket (inclusive)
                for b in (self.last_used_bucket + 1)..=bucket_index {
                    self.buckets[b].clear();
                }
            } else if bucket_index < self.last_used_bucket {
                // recently old data, could happen if the caller was delayed; just allow it without updating
                // anything else
            }
        } else if num_wraps == self.last_num_wraps + 1 {
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
        } else {
            // wrap > (last_wrap + 1 ), so we need to zero all of our data
            for b in 0..self.num_buckets {
                self.buckets[b].clear();
            }
        }
        self.last_num_wraps = num_wraps;
        self.last_used_bucket = bucket_index;
        bucket_index
    }

    /**
     * Get the sum of the counts stored.  Because we have a circular array that spans
     * the previous num_wraps to the current num_wraps, this is just a simple sum
     */
    pub fn get_sum(&self) -> u64 {
        self.buckets.iter().fold(0, |acc, cb| acc + cb.sum)
    }

    /**
     * Return the maximum of the values stored.
     */
    pub fn get_max(&self) -> u64 {
        self.buckets
            .iter()
            .fold(0, |acc, cb| std::cmp::max(acc, cb.max))
    }

    /**
     * Average across the time window. I.e., `sum / total duration`
     */
    pub fn get_avg(&self) -> f64 {
        let mut sum = 0;
        let mut num_entries = 0;
        for b in &self.buckets {
            sum += b.sum;
            num_entries += b.num_entries;
        }
        if num_entries == 0 {
            0.0
        } else {
            sum as f64 / num_entries as f64
        }
    }

    /**
     * Get the number of entires across the time window
     */
    pub fn get_num_entries(&self) -> u64 {
        let mut entries = 0;
        for b in &self.buckets {
            entries += b.num_entries;
        }
        entries
    }

    /**
     * NOTE that this is subtly but critically different from ```CounterBucket::get_max()```
     *
     * The former grabs the max value across the counter values that are inserted
     * while this grabs the max sum across all of the counters.
     */

    pub fn get_max_bucket(&self) -> u64 {
        let mut max = 0;
        for b in &self.buckets {
            max = b.sum.max(max);
        }
        max
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

    /***
     * Convert the data in the buckets into a time series of the format
     * that chartjs expected, e.g.,
     * # json
     * [ { x: 10, y: 20 }
     *   ....
     * ]
     *
     * This involves re-ordering the data so that the most recent data (e.g., current
     * bucket) is all the way on the right (x=max) and the oldest is all the way on
     * the left (x= min)
     */

    pub fn to_chartjs_data(&self, x_scale: usize, y_scale: f64) -> Vec<serde_json::Value> {
        self.buckets
            .iter()
            .enumerate()
            .map(|(bucket_index, b)| {
                serde_json::json!({
                    "y": b.sum as f64 / y_scale,
                    "x": bucket_index * x_scale as usize
                }
                )
            })
            .collect()
    }
}

/**
 * Keeps track of multiple BucketedTimeseries to allow tracking of data across multiple time
 * windows. E.g., number of bytes in the last minute, last 10 minutes, etc.
 */
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultilevelTimeseries {
    /// The time when this MultilevelTimeseries was created. Also used as the epoch
    /// for the contained BucketedTimeseries
    created_time: Instant,
    /// The different time windows we track. E.g., for 1min and 10min, we'd have
    /// `vec![Duration::from_sec(60), Duration::from_secs(600)`
    window_sizes: Vec<Duration>,
    /// The BicketedTiemSeries corresponding to the window sizes,
    /// `assert_eq!(levels.len(), windos_sizes.len())
    levels: Vec<BucketedTimeSeries>,
    /// An additional CounterBucket where we track the count for all time
    all_time: CounterBucket,
    /// The most recent datapoint
    most_recent_time: Instant,
}

/// Helper function to compute the rate per seconds
/// of something. Returns 0 if the duration is 0
#[inline]
fn compute_rate(sum: u64, dt: Duration) -> f64 {
    let dt_sec = dt.as_secs_f64();
    if dt_sec > 0.0 {
        sum as f64 / dt_sec
    } else {
        0.0
    }
}

impl MultilevelTimeseries {
    /// Create a new MultilevelTimeseries with the durations from `window_sizes`
    /// (e.g., 1min, 10min, 1hr). Each window_size will use `num_buckets` buckets.
    pub fn new(window_sizes: Vec<Duration>, num_buckets: usize) -> Self {
        Self::new_with_create_time(window_sizes, num_buckets, Instant::now())
    }

    pub fn new_with_create_time(
        window_sizes: Vec<Duration>,
        num_buckets: usize,
        created_time: Instant,
    ) -> Self {
        let mut levels = Vec::new();
        for win in &window_sizes {
            // We compute the bucket width in microseconds. We do use integer division and
            // the duration might not be evenly divisable by the number of buckets. However, the
            // resulting error should be insignificant because we already quantize the values
            // on size of a single bucket (we drop a whole bucket at a time when advancing).
            // Also because we are using microseconds, the error can't be more than
            // num_buckets microseconds and we expect to track time windows of seconds to
            // hours.
            let bucket_dur_us = win.as_micros() / (num_buckets as u128);
            levels.push(BucketedTimeSeries::new_with_create_time(
                created_time,
                Duration::from_micros(bucket_dur_us as u64),
                num_buckets,
            ));
        }
        MultilevelTimeseries {
            created_time,
            levels,
            window_sizes,
            all_time: CounterBucket::default(),
            most_recent_time: created_time,
        }
    }

    /// Add `value` at time `now` to all levels. Will rotate
    /// buckets if needed
    pub fn add_value(&mut self, value: u64, now: Instant) {
        self.most_recent_time = now;
        for lvl in &mut self.levels {
            lvl.add_value(value, now);
        }
        self.all_time.add(value);
    }

    /// Rotate buckets so that the observed time window of each
    /// BucketedTimeseries ends at `now`. This method should be called
    /// before calling any `get_X()` method to ensure an accurate value
    /// is returned by the getters.
    pub fn update_buckets(&mut self, now: Instant) {
        self.most_recent_time = now;
        for lvl in &mut self.levels {
            lvl.update_buckets(now);
        }
    }

    /// Get the sum for the given level. Where level_idx corresponds to the
    /// index in `windows_sizes`. If `level_idx >= self.levels.sum()` returns
    /// the `all_time` sum.
    pub fn get_sum(&self, level_idx: usize) -> u64 {
        if level_idx >= self.levels.len() {
            self.all_time.sum
        } else {
            self.levels[level_idx].get_sum()
        }
    }

    /// The avg for the given level. See `get_sum()` for how `level_idx` is handled
    pub fn get_avg(&self, level_idx: usize) -> f64 {
        if level_idx >= self.levels.len() {
            self.all_time.avg()
        } else {
            self.levels[level_idx].get_avg()
        }
    }

    /// The avg for the given level. See `get_sum()` for how `level_idx` is handled
    pub fn get_max(&self, level_idx: usize) -> u64 {
        if level_idx >= self.levels.len() {
            self.all_time.max
        } else {
            self.levels[level_idx].get_max()
        }
    }

    /// The avg for the given level. See `get_sum()` for how `level_idx` is handled
    pub fn get_num_entries(&self, level_idx: usize) -> u64 {
        if level_idx >= self.levels.len() {
            self.all_time.num_entries
        } else {
            self.levels[level_idx].get_num_entries()
        }
    }

    /// The avg for the given level. See `get_sum()` for how `level_idx` is handled
    pub fn get_rate(&self, level_idx: usize) -> f64 {
        if level_idx >= self.levels.len() {
            compute_rate(self.all_time.sum, self.most_recent_time - self.created_time)
        } else {
            let dt = std::cmp::min(
                self.window_sizes[level_idx],
                self.most_recent_time - self.created_time,
            );
            compute_rate(self.levels[level_idx].get_sum(), dt)
        }
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
        ts.add_value(1, create_time);
        assert_eq!(ts.get_sum(), 1);
        assert_eq!(ts.buckets[0].sum, 1);
        // add 2, 1 second after 'right away'
        ts.add_value(2, create_time + Duration::from_secs(1));
        assert_eq!(ts.buckets[1].sum, 2);
        assert_eq!(ts.get_sum(), 3);
        // add 3, 2 second after 'right away'; this should create a new wrap and clear the first bucket
        ts.add_value(3, create_time + Duration::from_secs(2));
        assert_eq!(ts.buckets[0].sum, 3);
        assert_eq!(ts.get_sum(), 5);
        assert_eq!(ts.last_num_wraps, 1);
        // add 4, 7 seconds after 'right away'; this should clear the time series as the new wrap > old wrap +1
        ts.add_value(4, create_time + Duration::from_secs(7));
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
        ts.add_value(1, create_time);
        assert_eq!(ts.get_sum(), 1);
        assert_eq!(ts.buckets[0].sum, 1);
        // add 2, 12 second after 'right away', so it should wrap, clear the full counter and be just '2'
        ts.add_value(2, create_time + Duration::from_secs(12));
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

        ts.add_value(1, create_time);
        ts.add_value(2, create_time + dt);
        ts.add_value(3, create_time + 2 * dt);
        ts.add_value(4, create_time + 3 * dt);
        assert_eq!(get_bucket_values(&ts), &[1, 2, 3, 4]);
        ts.add_value(5, create_time + 4 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 2, 3, 4]);
        ts.add_value(6, create_time + 5 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 6, 3, 4]);
    }

    #[test]
    fn test_wrap_b() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.add_value(1, create_time);
        ts.add_value(2, create_time + dt);
        ts.add_value(3, create_time + 2 * dt);
        ts.add_value(4, create_time + 3 * dt);
        assert_eq!(get_bucket_values(&ts), &[1, 2, 3, 4]);
        ts.add_value(5, create_time + 5 * dt);
        assert_eq!(get_bucket_values(&ts), &[0, 5, 3, 4]);
    }

    #[test]
    fn test_wrap_c() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.add_value(1, create_time);
        ts.add_value(2, create_time + dt);
        ts.add_value(3, create_time + 2 * dt);
        ts.add_value(4, create_time + 3 * dt);
        ts.add_value(5, create_time + 4 * dt);
        ts.add_value(6, create_time + 5 * dt);
        ts.add_value(7, create_time + 6 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 6, 7, 4]);

        ts.add_value(8, create_time + 8 * dt);
        assert_eq!(get_bucket_values(&ts), &[8, 6, 7, 0]);
    }

    #[test]
    fn test_wrap_new_index_same_as_old_idx() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.add_value(1, create_time);
        ts.add_value(2, create_time + dt);
        ts.add_value(3, create_time + 2 * dt);
        ts.add_value(4, create_time + 3 * dt);
        ts.add_value(5, create_time + 7 * dt);
        assert_eq!(get_bucket_values(&ts), &[0, 0, 0, 5]);
    }

    #[test]
    fn test_wrap_index_larger_than_old_index() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.add_value(1, create_time);
        ts.add_value(2, create_time + dt);
        ts.add_value(3, create_time + 2 * dt);
        ts.add_value(4, create_time + 3 * dt);
        ts.add_value(5, create_time + 4 * dt);
        ts.add_value(6, create_time + 5 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 6, 3, 4]);

        ts.add_value(7, create_time + 10 * dt);
        assert_eq!(get_bucket_values(&ts), &[0, 0, 7, 0]);
    }

    #[test]
    fn test_wrap_many_wraps() {
        let create_time = Instant::now();
        let dt = Duration::from_millis(1001);

        let mut ts =
            BucketedTimeSeries::new_with_create_time(create_time, Duration::from_secs(1), 4);

        ts.add_value(1, create_time);
        ts.add_value(2, create_time + dt);
        ts.add_value(3, create_time + 2 * dt);
        ts.add_value(4, create_time + 3 * dt);
        ts.add_value(5, create_time + 4 * dt);
        ts.add_value(6, create_time + 5 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 6, 3, 4]);

        // wraps twice
        ts.add_value(7, create_time + 13 * dt);
        assert_eq!(get_bucket_values(&ts), &[0, 7, 0, 0]);
    }

    #[test]
    fn test_counter_bucket() {
        let mut cb = CounterBucket::default();
        cb.add(5);
        cb.add(10);
        cb.add(2);
        assert_eq!(cb.sum, 17);
        assert_eq!(cb.max, 10);
        assert_eq!(cb.num_entries, 3);
        assert_eq!(cb.avg(), 17. / 3.);

        cb.clear();
        assert_eq!(cb.sum, 0);
        assert_eq!(cb.max, 0);
        assert_eq!(cb.num_entries, 0);
        assert_eq!(cb.avg(), 0.0);

        let cb = CounterBucket::default();
        assert_eq!(cb.avg(), 0.0);
    }

    #[test]
    fn test_bucked_timeseries_getters() {
        let t0 = Instant::now();
        let mut ts = BucketedTimeSeries::new_with_create_time(t0, Duration::from_secs(1), 60);
        for i in 0..60 {
            ts.add_value(i + 1, t0 + Duration::from_secs(i));
            ts.add_value(i + 1, t0 + Duration::from_secs(i));
        }
        let expected_sum = 60 * 61; // 2*  n*(n+1)/2 :-)
        assert_eq!(ts.get_sum(), expected_sum);
        assert_eq!(ts.get_num_entries(), 120);
        assert_eq!(ts.get_avg(), expected_sum as f64 / 120.);
        assert_eq!(ts.get_max(), 60);

        // now call update. Make sure buckets are advanced
        ts.update_buckets(t0 + Duration::from_secs(62));
        // three buckets should have been evicted. with two entries each
        assert_eq!(ts.get_num_entries(), 114);
        // the sum should have been reduced by 2 + 4 + 6 = 12
        assert_eq!(ts.get_sum(), expected_sum - 12);
    }

    #[test]
    fn test_bucked_timeseries_max() {
        let t0 = Instant::now();
        let mut ts = BucketedTimeSeries::new_with_create_time(t0, Duration::from_secs(1), 5);
        ts.add_value(10, t0);

        ts.add_value(25, t0 + Duration::from_secs(1));
        ts.add_value(100, t0 + Duration::from_secs(1));
        ts.add_value(50, t0 + Duration::from_secs(1));

        ts.add_value(23, t0 + Duration::from_secs(2));
        ts.add_value(42, t0 + Duration::from_secs(3));
        assert_eq!(ts.get_num_entries(), 6);
        assert_eq!(ts.get_max(), 100);

        ts.update_buckets(t0 + Duration::from_secs(7));
        assert_eq!(ts.get_max(), 42);
    }

    #[test]
    fn test_compute_rate() {
        assert_eq!(compute_rate(120, Duration::from_secs(2)), 60.);
        assert_eq!(compute_rate(120, Duration::from_millis(500)), 240.);
        assert_eq!(compute_rate(120, Duration::from_millis(0)), 0.0);
    }

    /// Make sure the time windows and levels in a MultilevelTimeseries are
    /// correctly set up.
    #[test]
    fn test_multilevel_timeseries_creation() {
        let t0 = Instant::now();
        let mlts = MultilevelTimeseries::new_with_create_time(
            vec![Duration::from_secs(60), Duration::from_secs(600)],
            60,
            t0,
        );
        assert_eq!(
            mlts.window_sizes,
            vec![Duration::from_secs(60), Duration::from_secs(600)]
        );
        assert_eq!(mlts.levels.len(), 2);
        assert_eq!(mlts.levels[0].bucket_time_window, Duration::from_secs(1));
        assert_eq!(mlts.levels[1].bucket_time_window, Duration::from_secs(10));
    }

    /// Make sure an empty, just craeted MultilevelTimeseries is correct
    #[test]
    fn test_multilevel_timeseries_empty() {
        let t0 = Instant::now();
        let mlts = MultilevelTimeseries::new_with_create_time(
            vec![Duration::from_secs(60), Duration::from_secs(600)],
            60,
            t0,
        );
        assert_eq!(mlts.get_num_entries(0), 0);
        assert_eq!(mlts.get_num_entries(1), 0);
        assert_eq!(mlts.get_num_entries(2), 0);
        assert_eq!(mlts.get_sum(0), 0);
        assert_eq!(mlts.get_sum(1), 0);
        assert_eq!(mlts.get_sum(2), 0);
        // make sure not divide by zero for avg or rate
        assert_eq!(mlts.get_avg(0), 0.0);
        assert_eq!(mlts.get_avg(1), 0.0);
        assert_eq!(mlts.get_avg(2), 0.0);
        assert_eq!(mlts.get_rate(0), 0.0);
        assert_eq!(mlts.get_rate(1), 0.0);
        assert_eq!(mlts.get_rate(2), 0.0);
    }

    /// Test the rate computation of MultilevelTimeseries. Esp. at the beginning
    /// when we didn't have enough data points / timestamps to fill the full time
    /// window yet.
    #[test]
    fn test_multilevel_timeseries_rate() {
        let t0 = Instant::now();
        let mut mlts = MultilevelTimeseries::new_with_create_time(
            vec![Duration::from_secs(60), Duration::from_secs(600)],
            60,
            t0,
        );

        mlts.add_value(10, t0);
        mlts.add_value(10, t0 + Duration::from_secs(10));
        mlts.add_value(50, t0 + Duration::from_secs(30));

        // we omly have 30 seconds worth of data in the MLTS. in this get_rate()
        // will use the 30sec instead of the window size. Make sure that's the case
        assert_eq!(mlts.get_rate(0), 70. / 30.); // 60s
        assert_eq!(mlts.get_rate(1), 70. / 30.); // 600s
        assert_eq!(mlts.get_rate(2), 70. / 30.); // all time
        assert_eq!(mlts.get_sum(0), 70); // 60s
        assert_eq!(mlts.get_sum(1), 70); // 600s
        assert_eq!(mlts.get_sum(2), 70); // all time

        // add more values
        // these three values will end up in 60 and 600 levels
        // the previously added values will be evicted from the 60sec level
        mlts.add_value(200, t0 + Duration::from_secs(120 + 10));
        mlts.add_value(500, t0 + Duration::from_secs(120 + 20));
        mlts.add_value(100, t0 + Duration::from_secs(120 + 30));

        assert_eq!(mlts.get_sum(0), 800); // 60s
        assert_eq!(mlts.get_sum(1), 870); // 600s
        assert_eq!(mlts.get_sum(2), 870); // all time

        // check rates again. the 60s window should now be based on
        // a 60sec duration
        assert_eq!(mlts.get_rate(0), 800. / 60.); // 60s
        assert_eq!(mlts.get_rate(1), 870. / 150.); // 600s
        assert_eq!(mlts.get_rate(2), 870. / 150.); // all time
    }

    #[test]
    fn test_multilevel_timeseries_evictions() {
        let t0 = Instant::now();
        let mut mlts = MultilevelTimeseries::new_with_create_time(
            vec![Duration::from_secs(60), Duration::from_secs(600)],
            60,
            t0,
        );

        for i in 0..60 {
            let dt = Duration::from_secs(10 * i);
            mlts.add_value(42, t0 + dt);
        }
        assert_eq!(mlts.get_sum(0), 6 * 42);
        assert_eq!(mlts.get_sum(1), 60 * 42);
        assert_eq!(mlts.get_sum(2), 60 * 42);
        assert_eq!(mlts.get_num_entries(0), 6);
        assert_eq!(mlts.get_num_entries(1), 60);
        assert_eq!(mlts.get_num_entries(2), 60);

        // now add more data. Will start to evit buckets from the 600sec window
        let t1 = mlts.most_recent_time;
        assert_eq!(mlts.most_recent_time, t0 + Duration::from_secs(590));
        for i in 1..=30 {
            let dt = Duration::from_secs(10 * i);
            mlts.add_value(23, t1 + dt);
        }
        assert_eq!(mlts.get_num_entries(0), 6);
        assert_eq!(mlts.get_num_entries(1), 60);
        assert_eq!(mlts.get_num_entries(2), 90);
        assert_eq!(mlts.get_sum(0), 6 * 23);
        assert_eq!(mlts.get_sum(1), 30 * 23 + 30 * 42);
        assert_eq!(mlts.get_sum(2), 60 * 42 + 30 * 23);

        assert_eq!(mlts.get_rate(0), (6 * 23) as f64 / 60.);
        assert_eq!(mlts.get_rate(1), (30 * 23 + 30 * 42) as f64 / 600.);
        let all_time_dt = mlts.most_recent_time - t0;
        assert_eq!(
            mlts.get_rate(2),
            (60 * 42 + 30 * 23) as f64 / all_time_dt.as_secs_f64()
        );

        assert_eq!(mlts.get_avg(0), (6 * 23) as f64 / 6.); // 60sec win. 6 entries
        assert_eq!(mlts.get_avg(1), (30 * 23 + 30 * 42) as f64 / 60.); // 600sec win. 60 entries
        assert_eq!(mlts.get_avg(2), (60 * 42 + 30 * 23) as f64 / 90.);

        assert_eq!(mlts.get_max(0), 23);
        assert_eq!(mlts.get_max(1), 42);
        assert_eq!(mlts.get_max(2), 42);

        // advance buckets. 60sec win will be empty, 600sec window will have just a single entry
        mlts.update_buckets(mlts.most_recent_time + Duration::from_secs(599));
        assert_eq!(mlts.get_sum(0), 0);
        assert_eq!(mlts.get_sum(1), 23);
        assert_eq!(mlts.get_sum(2), 60 * 42 + 30 * 23);

        assert_eq!(mlts.get_max(0), 0);
        assert_eq!(mlts.get_max(1), 23);
        assert_eq!(mlts.get_max(2), 42);

        assert_eq!(mlts.get_num_entries(0), 0);
        assert_eq!(mlts.get_num_entries(1), 1);
        assert_eq!(mlts.get_num_entries(2), 90);
    }
}
