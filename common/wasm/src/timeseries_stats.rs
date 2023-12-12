use chrono::{DateTime, Utc};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::Display,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use typescript_type_def::TypeDef;

/// Helper trait for TimeSources (e.g., `Instant` or `DataTime`) that can be used as
/// the internal clock for BucketedTimeSeries.
pub trait TimeSource {
    /// Calculate `a - b` as a `std::time::Duration`. Return 0 if the duration would
    /// be negative
    fn sub(a: Self, b: Self) -> std::time::Duration;

    /// Return the current time
    fn now() -> Self;
}

impl TimeSource for Instant {
    fn sub(a: Instant, b: Instant) -> std::time::Duration {
        a - b
    }

    fn now() -> Instant {
        Instant::now()
    }
}

impl TimeSource for DateTime<Utc> {
    fn sub(a: DateTime<Utc>, b: DateTime<Utc>) -> std::time::Duration {
        // we replicate the logic for `std::time::Instant`: if the difference would be
        // negative, we return 0.
        (a - b).to_std().unwrap_or_default()
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
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
 * `BucketedTimeSeries`
 */

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketedTimeSeries<TS>
where
    TS: TimeSource + Clone + Copy,
{
    pub created_time: TS,
    pub bucket_time_window: Duration,
    pub buckets: Vec<CounterBucket>,
    pub num_buckets: BucketIndex,
    pub last_used_bucket: usize,
    /// Identifies the time range of the buckets so two updates from different times that map to the
    /// same bucket don't get confused
    pub last_num_wraps: BucketIndex, // the number of times the counter has wrapped
}

impl<TS> BucketedTimeSeries<TS>
where
    TS: TimeSource + Clone + Copy,
{
    /**
     * Create a new BucketedTimeSeries
     */
    pub fn new(bucket_time_window: Duration, num_buckets: usize) -> BucketedTimeSeries<TS> {
        BucketedTimeSeries::new_with_create_time(TS::now(), bucket_time_window, num_buckets)
    }

    /**
     * Like `BucketedTimeSeries::new()` but we can specify the start time; useful for deterministic testing
     */
    pub fn new_with_create_time(
        created_time: TS,
        bucket_time_window: Duration,
        num_buckets: usize,
    ) -> BucketedTimeSeries<TS> {
        BucketedTimeSeries {
            created_time,
            // store Duration in Micros for faster calcs
            bucket_time_window,
            buckets: vec![CounterBucket::new(); num_buckets],
            num_buckets,
            last_used_bucket: 0,
            last_num_wraps: 0,
        }
    }

    pub fn add_value(&mut self, value: u64, now: TS) {
        let idx = self.update_buckets(now);
        self.buckets[idx].add(value);
    }

    /// Update and rotate the buckets up to `now`. Return the bucket index that
    /// `now` points tp
    pub fn update_buckets(&mut self, now: TS) -> usize {
        // how much time from system start?
        let offset_time = TS::sub(now, self.created_time).as_micros();
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
            // panic!("Time went backward for our monotonic clock!?");
            // This is no longer a monotonic clock all of the time!
            // FOR NOW, NO-OP/drop the data, but ideally we would store the data if it was still in
            // the window
            // tracking as https://github.com/netdebug-com/netdebug/issues/248
        } else if num_wraps == self.last_num_wraps {
            match bucket_index.cmp(&self.last_used_bucket) {
                Ordering::Greater => {
                    // zero everything from just after the last bucket used to the new bucket (inclusive)
                    for b in (self.last_used_bucket + 1)..=bucket_index {
                        self.buckets[b].clear();
                    }
                }
                Ordering::Less => {
                    // recently old data, could happen if the caller was delayed; just allow it without updating
                    // anything else
                }
                Ordering::Equal => {
                    // if bucket_index == self.last_bucket_used, then NOOP
                }
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

    /// Check if we've seen at least one full window (i.e., `num_bucket * time_per_bucket`) of
    /// data-points.
    pub fn full_window_seen(&self) -> bool {
        self.last_num_wraps != 0
    }

    fn bucket_iter(&self) -> BucketIterator {
        BucketIterator {
            buckets: &self.buckets,
            returned_cnt: 0,
            idx: self.last_used_bucket + 1,
        }
    }

    pub fn export_sum_buckets(&self) -> ExportedBuckets {
        ExportedBuckets {
            bucket_time_window: self.bucket_time_window,
            buckets: self.bucket_iter().map(|bucket| bucket.sum).collect_vec(),
        }
    }

    pub fn export_cnt_buckets(&self) -> ExportedBuckets {
        ExportedBuckets {
            bucket_time_window: self.bucket_time_window,
            buckets: self
                .bucket_iter()
                .map(|bucket| bucket.num_entries)
                .collect_vec(),
        }
    }

    pub fn total_duration(&self) -> Duration {
        self.bucket_time_window * self.num_buckets as u32
    }
}

struct BucketIterator<'a> {
    buckets: &'a Vec<CounterBucket>,
    returned_cnt: usize,
    idx: usize,
}

impl<'a> Iterator for BucketIterator<'a> {
    type Item = CounterBucket;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx == self.buckets.len() {
            self.idx = 0;
        }
        if self.returned_cnt == self.buckets.len() {
            None
        } else {
            self.idx += 1;
            self.returned_cnt += 1;
            Some(self.buckets[self.idx - 1])
        }
    }
}

/// A small helper struct that represents an exported (i.e., serde serialized)
/// `BucketedTimeSeries`. One instance of this will represent either the `max`, `sum`,
/// or `num_entries` values.
/// The buckets will be in-order. I.e., `buckets[0]` is the oldest bucket, and
/// `buckets[buckets.len()-1]` is the newest.
#[serde_as]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TypeDef)]
pub struct ExportedBuckets {
    #[type_def(type_of = "u64")]
    #[serde_as(as = "serde_with::DurationMicroSeconds<u64>")]
    #[serde(rename = "bucket_time_window_us")]
    pub bucket_time_window: Duration,
    pub buckets: Vec<u64>,
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
    levels: Vec<BucketedTimeSeries<Instant>>,
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

/// The different statistic types `ExportedStats` can export
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StatType {
    /// The maximum over the given time windows
    MAX,
    /// The sum of values over the given time windows
    SUM,
    /// The average (mean) of values over the given time windows
    AVG,
    /// The count, i.e., number of entries over the given time windows
    COUNT,
    /// The per-second rate over the given time window (i.e., sum / window_duration_in_seconds)
    RATE,
}

/// Represents the unit of what ExportedStats is tracking
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Units {
    Packets,
    Bytes,
    Milliseconds,
    Microseconds,
    None,
}

impl Units {
    /// Converts this unit to a string to use in the counter name
    pub fn to_counter_name_part(&self) -> &'static str {
        match self {
            Units::Packets => ".pkts",
            Units::Bytes => ".bytes",
            Units::Milliseconds => ".ms",
            Units::Microseconds => ".us",
            Units::None => "",
        }
    }
}

/// An exported statistics for a given "item". E.g., packets received. The ExportedStats
/// can track different stats type (max, sum, avg, etc. see `StatType`) over different time
/// windows (cf. `MultilevelTimeseries`). ExportetStats have a base name.
///
/// E.g., lets assume we want to track `bytes_received` over 60sec and 600sec time windows,
/// and export the `sum` and `avg`. Exported stats will the export the following named counters:
///    `received.bytes.SUM.60`    <- sum over last 60sec<br>
///    `received.bytes.SUM.600`   <- sum over last 600sec<br>
///    `received.bytes.SUM`    <- sum since the stat was created ("all time")<br>
///    `received.bytes.AVG.60`    <- avg over last 60sec<br>
///    `received.bytes.AVG.600`   <- avg over last 600sec<br>
///    `received.bytes.AVG`    <- avg since the stat was created ("all time")<br>
///
/// Example:
/// ```
/// # use common_wasm::timeseries_stats::*;
/// let mut rx_bytes = ExportedStat::new("received", Units::Bytes, [StatType::SUM, StatType::AVG]);
/// // Add data to rx_bytes. E.g., in a receive loop.
/// rx_bytes.add_value(42);
/// rx_bytes.add_value(23);
/// // Lets retrieve the counters
/// let map = rx_bytes.get_counter_map();
/// assert_eq!(map.get("received.bytes.SUM.60").unwrap(), &65);  // sum of rx bytes over the last min
/// assert_eq!(map.get("received.bytes.SUM.600").unwrap(), &65); // sum of rx bytes over the last 10 min
/// assert_eq!(map.get("received.bytes.AVG.60").unwrap(), &33);  // avg of rx bytes over the last
/// ```
///
/// When tracking time-units / duration, we can directly add duration values:
/// ```
/// # use common_wasm::timeseries_stats::*;
/// let mut proc_time = ExportedStat::new("processing_time", Units::Microseconds, [StatType::MAX]);
/// proc_time.add_duration_value(std::time::Duration::from_micros(123));
#[derive(Debug)]
pub struct ExportedStat {
    /// The (base-)name of the stat / item we want to track. E.g., `bytes_received`
    name: String,
    /// The actual MultilevelTimeseries that does all the tracking work.
    data: MultilevelTimeseries,
    /// The statistic types we are interested in exporting.
    stat_types: Vec<StatType>,
    /// The suffix to use for counternames for different time-window levels. E.g.,
    /// `.600` for the 10min window, `.60` for the 1min window, etc.
    /// The index corresponds to the level index of MultilevelTimeseries. Note that
    /// the last entry is the empty string (for the all-time stats)
    level_suffixes: Vec<String>,
    unit: Units,
}

impl ExportedStat {
    pub fn new<I: IntoIterator<Item = StatType>>(
        name: &str,
        unit: Units,
        stat_types: I,
    ) -> ExportedStat {
        ExportedStat::new_with_create_time(name, unit, stat_types, Instant::now())
    }

    pub fn new_with_create_time<I: IntoIterator<Item = StatType>>(
        name: &str,
        unit: Units,
        stat_types: I,
        now: Instant,
    ) -> ExportedStat {
        let mut stat_type_vec = Vec::from_iter(stat_types);
        stat_type_vec.sort();
        stat_type_vec.dedup();
        let window_sizes_sec = vec![60, 600, 3600];
        let mut level_suffixes: Vec<String> = window_sizes_sec
            .iter()
            .map(|sz| ".".to_string() + &sz.to_string())
            .collect();
        level_suffixes.push("".to_string()); // for all-time

        ExportedStat {
            name: name.to_string(),
            data: MultilevelTimeseries::new_with_create_time(
                window_sizes_sec
                    .into_iter()
                    .map(Duration::from_secs)
                    .collect_vec(),
                60, // num_buckets
                now,
            ),
            stat_types: stat_type_vec,
            level_suffixes,
            unit,
        }
    }

    /// Add the given value at time `now`, rotating buckets as necessary to move time
    /// forward to `now`
    pub fn add_value_with_time(&mut self, value: u64, now: Instant) {
        self.data.add_value(value, now);
    }

    /// Add the given value at time `now`, rotating buckets as necessary to move time
    /// forward to `now`
    pub fn add_value(&mut self, value: u64) {
        self.data.add_value(value, Instant::now());
    }

    /// If the unit we are tracking is a time duration (ms, us). Then add the given duration
    /// at time `now`, rotating buckets as necessary to move time
    /// forward to `now`
    /// Panics if the tracked unit is not time based
    pub fn add_duration_value_with_time(&mut self, dur: Duration, now: Instant) {
        let val = match self.unit {
            // TODO: we might want to do a clamping conversion here instead of just `as`.
            // Then again. If we have more than 2^64 mircoseconds, something is off already...
            Units::Milliseconds => dur.as_millis() as u64,
            Units::Microseconds => dur.as_micros() as u64,
            _ => panic!(
                "`{:?}` is not a duration unit for ExportedStat `{}`",
                self.unit, self.name
            ),
        };
        self.add_value_with_time(val, now);
    }

    /// If the unit we are tracking is a time duration (ms, us). Then add the given duration
    /// at time `Instant::now()`, rotating buckets as necessary to move time forward
    /// Panics if the tracked unit is not time based
    pub fn add_duration_value(&mut self, dur: Duration) {
        self.add_duration_value_with_time(dur, Instant::now());
    }

    /// Rotate buckets as necessary to move time forward to `now`. This method
    /// should be called before querying the counters/
    fn update_time_to(&mut self, now: Instant) {
        self.data.update_buckets(now);
    }
}

impl Display for ExportedStat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: Ideally, we'd call `update_buckets()` here but we can't since we
        // only got a shared reference.
        for (name, val) in self.get_counter_map() {
            writeln!(f, "{}={}", name, val)?;
        }
        Ok(())
    }
}

/// A trait that provides counters as key-value pairs.
pub trait CounterProvider {
    /// Append all the counter name, value pairs from this exporter to the given
    /// collection/map. Note that `HashMap<String, u64>`, `Vec<(String,u64)>` all implement
    /// the `Extend` trait.
    /// The method will append `self.num_counters()` entries to the collection/map.
    fn append_counters<M: Extend<(String, u64)>>(&self, map: &mut M);

    /// The number of counters tracked/exported by this instances. Can be used to reserve space in a collection
    /// or map before calling `append_counters`.
    fn num_counters(&self) -> usize;

    /// Return a map of `counter_name, value` pairs for all the stats/counters tracked by
    /// this instance.
    fn get_counter_map(&self) -> HashMap<String, u64> {
        let mut ret = HashMap::with_capacity(self.num_counters());
        self.append_counters(&mut ret);
        ret
    }

    /// Return a vector of `counter_name, value` pairs tuples for all the stats/counters
    /// tracked by this instance. The order of the counter names that this method produces
    /// is "nice" so it's quite handy for printing :-)
    fn get_counter_vec(&self) -> Vec<(String, u64)> {
        let mut ret = Vec::with_capacity(self.num_counters());
        self.append_counters(&mut ret);
        ret
    }
}

pub trait CounterProviderWithTimeUpdate: CounterProvider {
    /// Rotate buckets as necessary to move time forward to `now`. This method
    /// should be called before querying the counters/
    /// NOTE that we require update_time_to to only take a const reference.
    fn update_time_to(&self, now: Instant);

    fn update_time(&self) {
        self.update_time_to(Instant::now());
    }
}

impl CounterProvider for ExportedStat {
    fn num_counters(&self) -> usize {
        self.stat_types.len() * self.level_suffixes.len()
    }

    fn append_counters<M>(&self, map: &mut M)
    where
        M: Extend<(String, u64)>,
    {
        use std::iter::once;

        for stat_type in &self.stat_types {
            for (idx, suffix) in self.level_suffixes.iter().enumerate() {
                let counter_name = format!(
                    "{}{}.{:?}{}",
                    self.name,
                    self.unit.to_counter_name_part(),
                    stat_type,
                    suffix
                );
                // We are converting the floating point values (avg, rate) into u64. That's fb303
                // does as well and probably makes sense here too to keep a single datatype for
                // values
                let value = match stat_type {
                    StatType::MAX => self.data.get_max(idx),
                    StatType::SUM => self.data.get_sum(idx),
                    StatType::AVG => self.data.get_avg(idx).round() as u64,
                    StatType::COUNT => self.data.get_num_entries(idx),
                    StatType::RATE => self.data.get_rate(idx).round() as u64,
                };
                map.extend(once((counter_name, value)));
            }
        }
    }
}

/// A thread safe-registry for ExportedStats. The registry can be used to create
/// new ExportedStat instances (represented via a `StatHandle`). The registry will
/// keep track of all stats created from it and it implemented `CounterProvider` to
/// query the counters from all contained `ExportedStats`.
///
/// ExportedStatRegistry internally uses `Arc` so it's safe and easy to clone the
/// registry. The cloned registry will contain the same set of counters.
///
/// Note that the locking granularity is for the whole `ExportedStatRegistry`. I.e.,
/// best practice is to use a separate registry for each thread or tokio task and then
/// keep a top-level collection of all registries.
///
/// # Example
///  
///  ```
/// # use common_wasm::timeseries_stats::*;
/// use std::thread::spawn;
///
/// let system_epoch = std::time::Instant::now();
/// let mut registry1 = ExportedStatRegistry::new("t1", system_epoch);
/// let mut registry2 = ExportedStatRegistry::new("t2", system_epoch);
/// let mut registry3 = ExportedStatRegistry::new("t3", system_epoch);
/// let my_registries = vec![registry1.clone(), registry2.clone(), registry3.clone()];
///
/// let join_handle1 = spawn(move || {
///     let mut stat_foo = registry1.add_stat("thread1_foo", Units::Packets, [StatType::SUM]);
///     stat_foo.add_value(42);
/// });
///
/// let join_handle2 = spawn(move || {
///     let mut stat_foo = registry2.add_stat("thread2_bar", Units::Packets, [StatType::SUM]);
///     let mut another_stat = registry2.add_duration_stat("other_stat", Units::Milliseconds, [StatType::AVG]);
///     stat_foo.add_value(23);
///     another_stat.add_duration_value(std::time::Duration::from_millis(10));
/// });
///
///  //  Alternatively, we can also just move (or clone) the individual StatHandle into the thread
/// let mut thread3_stat = registry3.add_stat("thread3_foobar", Units::Packets, [StatType::SUM]);
/// let join_handle3 = spawn(move || {
///     thread3_stat.add_value(2342);
/// });
/// join_handle1.join();
/// join_handle2.join();
/// join_handle3.join();
/// let all_counters_map = my_registries.get_counter_map();
/// println!("{:#?}", all_counters_map);
/// assert_eq!(*all_counters_map.get("t1.thread1_foo.pkts.SUM.60").unwrap(), 42);
/// assert_eq!(*all_counters_map.get("t2.thread2_bar.pkts.SUM.60").unwrap(), 23);
/// assert_eq!(*all_counters_map.get("t2.other_stat.ms.AVG.60").unwrap(), 10);
/// assert_eq!(*all_counters_map.get("t3.thread3_foobar.pkts.SUM.60").unwrap(), 2342);
///
/// assert_eq!(all_counters_map.len(), my_registries.num_counters());
///
/// ```
#[derive(Clone, Debug)]
pub struct ExportedStatRegistry {
    stats: Arc<Mutex<Vec<ExportedStat>>>,
    prefix: String,
    created_time: Instant,
}

impl ExportedStatRegistry {
    /// Create a new registry with the given epoch time. All timeseries will use the same
    /// epoch.
    pub fn new(prefix: &str, created_time: Instant) -> Self {
        Self {
            stats: Arc::new(Mutex::new(Vec::new())),
            prefix: prefix.to_string(),
            created_time,
        }
    }

    /// Create a new ExportedStat in this registry and return a thread-safe
    /// `StatHandle`. The `StateHandle` can be used to add data points to the
    /// ExportedStat
    pub fn add_stat<I: IntoIterator<Item = StatType>>(
        &mut self,
        name: &str,
        unit: Units,
        stat_types: I,
    ) -> StatHandle {
        // TODO: make sure there are not name collisions.
        let fullname = if self.prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", self.prefix, name)
        };
        let idx = {
            let mut stats_vec_locked = self.stats.lock().unwrap();
            stats_vec_locked.push(ExportedStat::new_with_create_time(
                &fullname,
                unit,
                stat_types,
                self.created_time,
            ));
            stats_vec_locked.len() - 1
        };
        StatHandle {
            registry: self.clone(),
            idx,
        }
    }

    /// Create a new ExportedStat in this registry and return a thread-safe
    /// `StatHandle`. The `StateHandle` can be used to add data points to the
    /// ExportedStat
    pub fn add_duration_stat<I: IntoIterator<Item = StatType>>(
        &mut self,
        name: &str,
        unit: Units,
        stat_types: I,
    ) -> StatHandleDuration {
        assert!(unit == Units::Microseconds || unit == Units::Milliseconds);
        let raw_handle = self.add_stat(name, unit, stat_types);
        StatHandleDuration { raw_handle }
    }
}

impl CounterProviderWithTimeUpdate for ExportedStatRegistry {
    fn update_time_to(&self, now: Instant) {
        let mut stats_locked = self.stats.lock().unwrap();
        for stat in &mut *stats_locked {
            stat.update_time_to(now);
        }
    }
}

impl CounterProvider for ExportedStatRegistry {
    fn append_counters<M: Extend<(String, u64)>>(&self, map: &mut M) {
        let stats_locked = self.stats.lock().unwrap();
        for stat in &*stats_locked {
            stat.append_counters(map);
        }
    }

    fn num_counters(&self) -> usize {
        let mut cnt = 0;
        let stats_locked = self.stats.lock().unwrap();
        for stat in &*stats_locked {
            cnt += stat.num_counters();
        }
        cnt
    }
}

impl CounterProviderWithTimeUpdate for Vec<ExportedStatRegistry> {
    fn update_time_to(&self, now: Instant) {
        for registry in self.iter() {
            registry.update_time_to(now);
        }
    }
}

// TODO: is this really the best way to tackle this?
impl CounterProvider for Vec<ExportedStatRegistry> {
    fn append_counters<M: Extend<(String, u64)>>(&self, map: &mut M) {
        for registry in self.iter() {
            registry.append_counters(map);
        }
    }

    fn num_counters(&self) -> usize {
        let mut cnt = 0;
        for registry in self.iter() {
            cnt += registry.num_counters();
        }
        cnt
    }
}

/// A thread-safe representation of an ExportedStat. `StatHandles` are created by an
/// ExportedStatRegistry. A `StatHandle` can be safely cloned. The clone will still represent the
/// same ExportedStat. `StatHandle` implements `add_value()` and `add_value_with_time()` methods
///  that ExportedStat provides. See `StatHandleDuration` for a variant that supports time durations
#[derive(Clone, Debug)]
pub struct StatHandle {
    /// This is the registry used to create/register this handle
    registry: ExportedStatRegistry,
    idx: usize,
}

impl StatHandle {
    /// see ExportedStat::add_value_with_time()
    pub fn add_value_with_time(&self, value: u64, now: Instant) {
        self.registry.stats.lock().unwrap()[self.idx].add_value_with_time(value, now);
    }

    /// see ExportedStat::add_value()
    pub fn add_value(&self, value: u64) {
        self.add_value_with_time(value, Instant::now());
    }

    pub fn bump(&self) {
        self.add_value_with_time(1, Instant::now());
    }
}

/// A thread-safe representation of an ExportedStat to track time durations
/// See also `StatHandle`
#[derive(Clone, Debug)]
pub struct StatHandleDuration {
    raw_handle: StatHandle,
}

impl StatHandleDuration {
    /// see ExportedStat::add_duration_value_with_time()
    pub fn add_duration_value_with_time(&mut self, dur: Duration, now: Instant) {
        self.raw_handle.registry.stats.lock().unwrap()[self.raw_handle.idx]
            .add_duration_value_with_time(dur, now);
    }

    /// see ExportedStat::add_duration_value()
    pub fn add_duration_value(&mut self, dur: Duration) {
        self.add_duration_value_with_time(dur, Instant::now());
    }
}

/// A utility struct to make it easy to crate and keep track of created Registries.
#[derive(Clone)]
pub struct SuperRegistry {
    system_epoch: Instant,
    registries: Vec<ExportedStatRegistry>,
}

impl SuperRegistry {
    pub fn new(system_epoch: Instant) -> Self {
        Self {
            system_epoch,
            registries: Vec::new(),
        }
    }

    pub fn new_registry(&mut self, prefix: &str) -> ExportedStatRegistry {
        let registry = ExportedStatRegistry::new(prefix, self.system_epoch);
        self.registries.push(registry.clone());
        registry
    }

    pub fn registries(self) -> Vec<ExportedStatRegistry> {
        self.registries
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn time_series_basic_instant() {
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
    fn time_series_basic_utc() {
        let create_time = DateTime::<Utc>::now();
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
    fn time_series_harder_instant() {
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

    #[test]
    fn time_series_harder_utc() {
        // thanks to Gregor for showing this test fails
        let create_time = DateTime::<Utc>::now();
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

    fn get_bucket_values<TS: TimeSource + Copy + Clone>(ts: &BucketedTimeSeries<TS>) -> Vec<u64> {
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
        assert_eq!(ts.export_sum_buckets().buckets, &[1, 2, 3, 4]);
        ts.add_value(5, create_time + 4 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 2, 3, 4]);
        assert_eq!(ts.export_sum_buckets().buckets, &[2, 3, 4, 5]);
        ts.add_value(6, create_time + 5 * dt);
        assert_eq!(get_bucket_values(&ts), &[5, 6, 3, 4]);
        assert_eq!(ts.export_sum_buckets().buckets, &[3, 4, 5, 6]);
        assert_eq!(
            ts.export_sum_buckets().bucket_time_window,
            Duration::from_secs(1)
        );
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
        assert_eq!(ts.export_sum_buckets().buckets, &[4, 5, 6, 7]);

        ts.add_value(8, create_time + 8 * dt);
        assert_eq!(get_bucket_values(&ts), &[8, 6, 7, 0]);
        assert_eq!(ts.export_sum_buckets().buckets, &[6, 7, 0, 8]);
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

    fn mk_and_populate_exported_stat<I>(unit: Units, stat_types: I, now: Instant) -> ExportedStat
    where
        I: IntoIterator<Item = StatType>,
    {
        let add = |t0, dt| t0 + Duration::from_secs(dt);
        let mut es = ExportedStat::new_with_create_time("foobar", unit, stat_types, now);
        es.add_value_with_time(20_000, now); // only in all-time

        es.add_value_with_time(15_000, add(now, 500)); // in 3600sec+

        es.add_value_with_time(11_000, add(now, 3500)); // in 600sec+
        es.add_value_with_time(7_000, add(now, 3500)); // in 600sec+

        es.add_value_with_time(1_000, add(now, 4000));
        es.add_value_with_time(3_000, add(now, 4000));
        es.add_value_with_time(5_000, add(now, 4000));

        // sanity checks
        assert_eq!(es.data.get_num_entries(0), 3);
        assert_eq!(es.data.get_num_entries(1), 5);
        assert_eq!(es.data.get_num_entries(2), 6);
        assert_eq!(es.data.get_num_entries(3), 7);

        assert_eq!(es.data.get_sum(0), 9_000);
        assert_eq!(es.data.get_sum(1), 27_000);
        assert_eq!(es.data.get_sum(2), 42_000);
        assert_eq!(es.data.get_sum(3), 62_000);

        assert_eq!(es.data.get_max(0), 5_000);
        assert_eq!(es.data.get_max(1), 11_000);
        assert_eq!(es.data.get_max(2), 15_000);
        assert_eq!(es.data.get_max(3), 20_000);

        assert_eq!(es.data.get_avg(0), 9_000. / 3.); // 3_000
        assert_eq!(es.data.get_avg(1), 27_000. / 5.); // 5_400
        assert_eq!(es.data.get_avg(2), 42_000. / 6.); // 7_000
        assert_eq!(es.data.get_avg(3), 62_000. / 7.); // 8857.14

        assert_eq!(es.data.get_rate(0), 9_000. / 60.); // 150
        assert_eq!(es.data.get_rate(1), 27_000. / 600.); // 45
        assert_eq!(es.data.get_rate(2), 42_000. / 3600.); // 11.67
        assert_eq!(es.data.get_rate(3), 62_000. / 4000.); // 15.5
        es
    }

    #[test]
    fn test_exported_stats_1() {
        let now = Instant::now();
        let es = mk_and_populate_exported_stat(
            Units::Packets,
            [StatType::AVG, StatType::SUM, StatType::SUM],
            now,
        );
        let mut counters = es.get_counter_vec();
        assert_eq!(counters.len(), es.num_counters());
        counters.sort();

        let mut expected: Vec<(String, u64)> = [
            ("foobar.pkts.AVG.60", 3000),
            ("foobar.pkts.AVG.600", 5400),
            ("foobar.pkts.AVG.3600", 7000),
            ("foobar.pkts.AVG", 8857),
            ("foobar.pkts.SUM.60", 9_000),
            ("foobar.pkts.SUM.600", 27_000),
            ("foobar.pkts.SUM.3600", 42_000),
            ("foobar.pkts.SUM", 62_000),
        ]
        .iter()
        .map(|(name, val)| (name.to_string(), *val))
        .collect_vec();

        expected.sort();

        assert_eq!(counters, expected);

        let counters_map = es.get_counter_map();
        let expected_map = HashMap::from_iter(expected.clone());
        assert_eq!(counters_map, expected_map);

        // now test "append_counter" function
        counters.clear();
        es.append_counters(&mut counters);
        counters.sort();
        assert_eq!(counters, expected);
    }

    #[test]
    fn test_exported_stats_all_types() {
        let now = Instant::now();
        let es = mk_and_populate_exported_stat(
            Units::None,
            [
                StatType::AVG,
                StatType::SUM,
                StatType::COUNT,
                StatType::RATE,
                StatType::MAX,
            ],
            now,
        );
        let counters_map = es.get_counter_map();

        let expected: HashMap<String, u64> = [
            ("foobar.AVG.60", 3000),
            ("foobar.AVG.600", 5400),
            ("foobar.AVG.3600", 7000),
            ("foobar.AVG", 8857),
            //
            ("foobar.SUM.60", 9_000),
            ("foobar.SUM.600", 27_000),
            ("foobar.SUM.3600", 42_000),
            ("foobar.SUM", 62_000),
            //
            ("foobar.COUNT.60", 3),
            ("foobar.COUNT.600", 5),
            ("foobar.COUNT.3600", 6),
            ("foobar.COUNT", 7),
            //
            ("foobar.MAX.60", 5_000),
            ("foobar.MAX.600", 11_000),
            ("foobar.MAX.3600", 15_000),
            ("foobar.MAX", 20_000),
            //
            ("foobar.RATE.60", 150),
            ("foobar.RATE.600", 45),
            ("foobar.RATE.3600", 12), // rounded
            ("foobar.RATE", 16),      // rounded
        ]
        .iter()
        .fold(HashMap::new(), |mut m, (name, val)| {
            m.insert(name.to_string(), *val);
            m
        });

        assert_eq!(counters_map, expected);
    }

    #[test]
    fn test_exported_stats_duration_units_ms() {
        let mut es = ExportedStat::new("foo", Units::Milliseconds, [StatType::AVG]);
        es.add_duration_value(Duration::from_secs(2));
        es.add_duration_value(Duration::from_millis(42));
        let counters = es.get_counter_map();
        assert_eq!(counters.get("foo.ms.AVG.60"), Some(&1021));
    }

    #[test]
    fn test_exported_stats_duration_units_us() {
        let mut es = ExportedStat::new("foo", Units::Microseconds, [StatType::SUM]);
        es.add_duration_value(Duration::from_secs(1));
        es.add_duration_value(Duration::from_millis(42));
        es.add_duration_value(Duration::from_micros(23));
        let counters = es.get_counter_map();
        assert_eq!(counters.get("foo.us.SUM.60"), Some(&1_042_023));
    }

    #[test]
    #[should_panic(expected = "`Bytes` is not a duration unit for ExportedStat `foo`")]
    fn test_exported_stats_duration_panic() {
        let mut es = ExportedStat::new("foo", Units::Bytes, [StatType::SUM]);
        es.add_duration_value(Duration::from_secs(1));
    }
}
