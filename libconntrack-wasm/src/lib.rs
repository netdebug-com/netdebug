use std::fmt::Display;

use chrono::{DateTime, Utc};
use common_wasm::timeseries_stats::BucketedTimeSeries;
use serde::{Deserialize, Serialize};

pub mod connection_measurements;
pub use connection_measurements::*;
use typescript_type_def::TypeDef; // reshare these identifiers in this namespace
pub mod aggregate_counters;

/// When calculating the average rate, require at least this much time between
/// the first and the last packets.
pub const MIN_DURATION_FOR_AVG_RATE_MICROS: i64 = 10_000;

#[serde_with::serde_as]
#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq, TypeDef)]
pub struct DnsTrackerEntry {
    pub hostname: String,
    #[type_def(type_of = "String")]
    pub created: DateTime<Utc>,
    pub from_ptr_record: bool,
    #[serde(rename = "rtt_usec")]
    #[serde_as(as = "Option<serde_with::DurationMicroSeconds<i64>>")]
    #[type_def(type_of = "i64")]
    pub rtt: Option<chrono::Duration>,
    #[serde(rename = "ttl_sec")]
    #[serde_as(as = "Option<serde_with::DurationSeconds<i64>>")]
    #[type_def(type_of = "i64")]
    pub ttl: Option<chrono::Duration>,
}

/**
 * Try to print this duration in the most human natural way, e.g.,
 *  using the most relevant precision given the size. But show all of the
 * precision
 *
 * NOTE: particularly in WASM which is always 32bit, there's chance
 * that nanos and micros might exceed 2^32 so fall back to less precise
 * millis if necessary (which always works)
 */
pub fn pretty_print_duration(d: &chrono::Duration) -> String {
    // apparently this can overflow
    if let Some(mut nanos) = d.num_nanoseconds() {
        nanos = nanos % 1_000_000_000; // truncate off the seconds portion
        if d.num_seconds() > 0 {
            format!("{}.{:9} seconds", d.num_seconds(), nanos)
        } else if d.num_milliseconds() > 0 || d.num_microseconds().is_none() {
            format!("{}.{:6} milliseconds", d.num_milliseconds(), nanos / 1000)
        } else {
            // unwrap should be ok here b/c we won't reach here if it's None
            format!(
                "{}.{:3} microseconds",
                d.num_microseconds().unwrap(),
                nanos / 1000000
            )
        }
    } else {
        // nano seconds not available due to overflow, fall back to only showing millis
        // but make sure to not over represent sigfigs
        // https://docs.rs/chrono/latest/chrono/struct.Duration.html#method.num_microseconds
        let millis = d.num_milliseconds() % 1_000; // truncate off the seconds portion
        if d.num_seconds() > 0 {
            format!("{}.{:03} seconds*", d.num_seconds(), millis)
        } else if d.num_milliseconds() > 0 || d.num_microseconds().is_none() {
            format!("{} milliseconds*", millis)
        } else {
            // unwrap should be ok here b/c we won't reach here if it's None
            format!("{} microseconds*", d.num_microseconds().unwrap())
        }
    }
}

/**
 * Use the SI definitions of Mega (Mega = 1e6), not the compute binary
 * approximations (e.g., Mega = 2^20)
 */
pub fn pretty_print_si_units(x: Option<f64>, units: &str) -> String {
    match x {
        Some(x) if x > 1e9 => format!("{:.2} G{}", x / 1e9, units),
        Some(x) if x > 1e6 => format!("{:.2} M{}", x / 1e6, units),
        Some(x) if x > 1e3 => format!("{:.2} K{}", x / 1e3, units),
        Some(x) => format!("{:.2} {}", x, units),
        None => "None".to_string(),
    }
}

/**
 * A (hopefuly useful) subset of all of the possible IP Protocols
 * /// use IpProtocol::*;
 * ///  assert_eq!(TCP, IpProtocol::from_wire(TCP.to_wire()));
 */

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TypeDef)]
pub enum IpProtocol {
    ICMP,
    TCP,
    UDP,
    ICMP6,
    Other(u8),
}

impl Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use IpProtocol::*;
        match self {
            ICMP => write!(f, "ICMP"),
            TCP => write!(f, "TCP"),
            UDP => write!(f, "UDP"),
            ICMP6 => write!(f, "ICMP6"),
            Other(ip_proto) => write!(f, "ip_proto={}", ip_proto),
        }
    }
}

impl IpProtocol {
    pub fn to_wire(&self) -> u8 {
        use IpProtocol::*;
        let num = match self {
            ICMP => 1,
            TCP => 6,
            UDP => 17,
            ICMP6 => 58,
            Other(ip_proto) => *ip_proto,
        };
        num as u8
    }

    pub fn from_wire(ip_proto: u8) -> IpProtocol {
        use IpProtocol::*;
        match ip_proto {
            1 => ICMP,
            6 => TCP,
            17 => UDP,
            58 => ICMP6,
            _ => Other(ip_proto),
        }
    }
}

pub trait RateCalculator {
    fn add_packet_with_time(&mut self, bytes: u64, now: DateTime<Utc>);

    fn add_packet(&mut self, bytes: u64) {
        self.add_packet_with_time(bytes, Utc::now())
    }

    fn get_byte_rate(&self) -> Option<f64>;

    fn get_packet_rate(&self) -> Option<f64>;

    fn to_pretty_string(&self) -> String {
        format!(
            "{}, {}",
            pretty_print_si_units(self.get_byte_rate(), "Byte/s"),
            pretty_print_si_units(self.get_packet_rate(), "Pkts/s")
        )
    }
}

/// Compute the average byte and packet rate, using Utc as the time source.
/// Will only compute a rate if the time duration is at least
/// `MIN_DURATION_FOR_AVG_RATE_MICROS`
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AverageRate {
    first_time: Option<DateTime<Utc>>,
    last_time: Option<DateTime<Utc>>,
    bytes: u64,
    packets: u64,
}

impl AverageRate {
    pub fn new() -> AverageRate {
        Self::default()
    }

    fn calc_rate(&self, x: f64) -> Option<f64> {
        if self.first_time.is_none() {
            return None;
        }
        let dt = (self.last_time.unwrap() - self.first_time.unwrap())
            .num_microseconds()
            .unwrap();
        if dt <= MIN_DURATION_FOR_AVG_RATE_MICROS {
            None
        } else {
            Some(x / (dt as f64 / 1e6))
        }
    }
}

impl RateCalculator for AverageRate {
    fn add_packet_with_time(&mut self, bytes: u64, now: DateTime<Utc>) {
        if self.first_time.is_none() {
            self.first_time = Some(now);
        }
        self.last_time = Some(now);
        self.bytes += bytes;
        self.packets += 1;
    }

    fn get_byte_rate(&self) -> Option<f64> {
        self.calc_rate(self.bytes as f64)
    }

    fn get_packet_rate(&self) -> Option<f64> {
        self.calc_rate(self.packets as f64)
    }
}

impl Display for AverageRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_pretty_string())?;
        Ok(())
    }
}

/// Keeps track of the maximum observed burst rate (both bytes and packets) in a short
/// time interval (`time_window`). E.g., if `time_window == 10ms` then it will track
/// maximum rate for 10ms bursts.
/// Note that packet and byte rates are tracked independently
#[derive(Clone, Debug, PartialEq)]
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
}

impl RateCalculator for MaxBurstRate {
    fn add_packet_with_time(&mut self, bytes: u64, now: DateTime<Utc>) {
        if self.ts.is_none() {
            self.ts = Some(BucketedTimeSeries::new_with_create_time(
                now,
                self.time_window / Self::NUM_BUCKETS,
                Self::NUM_BUCKETS as usize,
            ));
        }
        let ts = self.ts.as_mut().unwrap();
        ts.add_value(bytes, now);
        self.max_bytes = self.max_bytes.max(ts.get_sum());
        self.max_pkts = self.max_pkts.max(ts.get_num_entries());
    }

    fn get_byte_rate(&self) -> Option<f64> {
        self.ts
            .as_ref()
            .map(|ts| {
                if ts.full_window_seen() {
                    Some(self.max_bytes as f64 / self.time_window.as_secs_f64())
                } else {
                    None
                }
            })
            .flatten()
    }

    fn get_packet_rate(&self) -> Option<f64> {
        self.ts
            .as_ref()
            .map(|ts| {
                if ts.full_window_seen() {
                    Some(self.max_pkts as f64 / self.time_window.as_secs_f64())
                } else {
                    None
                }
            })
            .flatten()
    }
}

impl Display for MaxBurstRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_pretty_string())?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, TypeDef)]
pub struct RateEstimator {
    alpha: f64,
    estimate_rate_per_ns: Option<f64>,
    #[serde(skip)] // Instant doesn't serde, so skip serializing the time
    last_sample: Option<std::time::Instant>,
}

// probably sane for most applications
const DEFAULT_ALPHA: f64 = 0.1;

impl RateEstimator {
    pub fn new() -> RateEstimator {
        RateEstimator::with_alpha(DEFAULT_ALPHA)
    }
    pub fn with_alpha(alpha: f64) -> RateEstimator {
        RateEstimator {
            alpha,
            estimate_rate_per_ns: None,
            last_sample: None,
        }
    }

    /**
     * Add a new sample to the estimate with the current time
     */
    pub fn new_sample(&mut self, count: usize) {
        self.new_sample_with_time(count, std::time::Instant::now())
    }

    /**
     * Add a new sample the estimate with a known time
     */
    pub fn new_sample_with_time(&mut self, count: usize, now: std::time::Instant) {
        if let Some(last_sample) = self.last_sample {
            // low pass filter; could keep this as a rational, but seems fine for now
            if now == last_sample {
                // warn!("Ignoring (effectively infinite) sample with zero duration (now == last_sample)");
                // silently ignore this as we don't know where to log to in the WASM shared code case :-(
                return;
            }
            let time_delta = now - last_sample;
            self.new_sample_with_duration(count, time_delta);
        } else {
            // ignore first sample, just store the time
            self.last_sample = Some(now);
        }
    }

    /**
     * Add a new sample to the estimate with a known duration
     *
     * Mostly used for testing, but use this when we've already calculated the duration
     * from the last event
     *
     * Will panic!() if called without a previous estimate
     */
    fn new_sample_with_duration(&mut self, count: usize, time_delta: std::time::Duration) {
        let instant_rate = count as f64 / (time_delta.as_nanos() as f64);
        if let Some(old_estimate) = self.estimate_rate_per_ns {
            self.estimate_rate_per_ns =
                Some(instant_rate * self.alpha + (1.0 - self.alpha) * old_estimate);
        } else {
            // the instant estimate becomes the full initial estimate
            self.estimate_rate_per_ns = Some(instant_rate);
        }
        if let Some(last_sample) = self.last_sample {
            self.last_sample = Some(last_sample + time_delta);
        } else {
            panic!("Can't call RateEstimator::new_sample_with_duration() as the first sample");
        }
    }

    pub fn has_estimate(&self) -> bool {
        self.estimate_rate_per_ns.is_some()
    }

    /**
     * Get the current rate estimate with best precision
     *
     * will return None if we don't have at least two samples
     */
    pub fn get_rate(&self) -> Option<(f64, std::time::Duration)> {
        if let Some(estimate) = self.estimate_rate_per_ns {
            Some((estimate, std::time::Duration::from_nanos(1)))
        } else {
            None
        }
    }

    /**
     * Get current rate estimate in "per seconds"
     */
    pub fn get_rate_per_second(&self) -> Option<f64> {
        match self.estimate_rate_per_ns {
            Some(estimate) => Some(estimate * 1e9),
            None => None,
        }
    }

    /**
     * Use the SI definitions of Mega (Mega = 1e6), not the compute binary
     * approximations (e.g., Mega = 2^20)
     */
    pub fn get_pretty_rate_per_second(&self, units: &str) -> String {
        pretty_print_si_units(self.get_rate_per_second(), units)
    }
}

impl Eq for RateEstimator {}

/**
 * Rust doesn't like to autoimplement Ord for anything with floats
 */
impl Ord for RateEstimator {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.partial_cmp(other) {
            Some(o) => o,
            None => {
                match (self.estimate_rate_per_ns, other.estimate_rate_per_ns) {
                    (None, None) => std::cmp::Ordering::Equal,
                    (None, Some(_)) => std::cmp::Ordering::Less,
                    (Some(_), None) => std::cmp::Ordering::Greater,
                    (Some(e1), Some(e2)) => {
                        if e1 > e2 {
                            std::cmp::Ordering::Greater
                        } else {
                            std::cmp::Ordering::Less // don't care about equals in this case
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;
    #[test]
    fn ip_protocol_wire() {
        // it seems you need a special crate ('strum') to be able to iterate over enums
        // don't worry about that for now and just test the four we've defined
        use IpProtocol::*;
        assert_eq!(TCP, IpProtocol::from_wire(TCP.to_wire()));
        assert_eq!(UDP, IpProtocol::from_wire(UDP.to_wire()));
        assert_eq!(ICMP, IpProtocol::from_wire(ICMP.to_wire()));
        assert_eq!(ICMP6, IpProtocol::from_wire(ICMP6.to_wire()));
    }

    #[test]
    fn test_average_rate() {
        let now = Utc::now();
        let mut avg_rate = AverageRate::new();
        assert_eq!(avg_rate.get_byte_rate(), None);
        assert_eq!(avg_rate.get_packet_rate(), None);

        // Duration is 0: no rate
        avg_rate.add_packet_with_time(100, now);
        assert_eq!(avg_rate.get_byte_rate(), None);
        assert_eq!(avg_rate.get_packet_rate(), None);

        // Duration is only 9ms ==> rate is still None
        avg_rate.add_packet_with_time(100, now + chrono::Duration::milliseconds(9));
        assert_eq!(avg_rate.get_byte_rate(), None);
        assert_eq!(avg_rate.get_packet_rate(), None);

        // Now we have enough time to get a rate
        avg_rate.add_packet_with_time(130, now + chrono::Duration::milliseconds(11));
        assert_eq!(avg_rate.get_byte_rate().unwrap(), 30000.0);
        assert_eq!(avg_rate.get_packet_rate().unwrap(), 3. / 0.011);

        assert_eq!(avg_rate.to_string(), "30.00 KByte/s, 272.73 Pkts/s");
    }

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
    fn rate_estimator() {
        let mut rate = RateEstimator::new();
        rate.new_sample(10); // this is ignored, only used to start the timer
        assert_eq!(rate.get_rate_per_second(), None);
        rate.new_sample_with_duration(10, Duration::from_secs(1));
        let (estimate, duration) = rate.get_rate().unwrap();
        assert_eq!(duration, Duration::from_nanos(1));
        let test_estimate = 10.0 / 1e9; // 1s == 1e9 ns
        let epsilon = 1e-9;
        // floating point math can only ever be 'close enough'
        assert!((test_estimate - estimate).abs() < epsilon);
        // now update the estimate one last time and make sure it tracks properly
        rate.new_sample_with_duration(50, Duration::from_secs(1));
        let (estimate, duration) = rate.get_rate().unwrap();
        assert_eq!(duration, Duration::from_nanos(1));
        assert!(estimate > test_estimate)
    }

    #[test]
    #[should_panic]
    fn rate_estimator_panic() {
        let mut rate = RateEstimator::new();
        rate.new_sample_with_duration(10, Duration::from_secs(1));
    }

    #[test]
    fn test_pretty_print_si_units() {
        assert_eq!(pretty_print_si_units(Some(23e9), "Foo/s"), "23.00 GFoo/s");
        assert_eq!(pretty_print_si_units(Some(42e6), "Foo/s"), "42.00 MFoo/s");
        assert_eq!(pretty_print_si_units(Some(1.1e3), "Foo/s"), "1.10 KFoo/s");
        assert_eq!(pretty_print_si_units(Some(789.0), "Foo/s"), "789.00 Foo/s");
        assert_eq!(pretty_print_si_units(None, "Foo/s"), "None");
    }

    #[test]
    fn rate_estimator_pretty() {
        for (time, test_str) in [
            (Duration::from_nanos(1), "2.00 GHz"),
            (Duration::from_micros(1), "2.00 MHz"),
            (Duration::from_millis(1), "2.00 KHz"),
            (Duration::from_secs(1), "2.00 Hz"),
        ] {
            let mut test_rate = RateEstimator::new();
            test_rate.new_sample(10); // this count will be ignored, just the time
                                      // a rate of 2 every nano second (1e-9) is 2GHz
            test_rate.new_sample_with_duration(2, time);
            assert_eq!(test_str, test_rate.get_pretty_rate_per_second("Hz"));
        }
    }
}
