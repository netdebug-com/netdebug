use std::fmt::Display;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod connection_measurements;
pub use connection_measurements::*; // reshare these identifiers in this namespace

#[serde_with::serde_as]
#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsTrackerEntry {
    pub hostname: String,
    pub created: DateTime<Utc>,
    pub from_ptr_record: bool,
    #[serde_as(as = "Option<serde_with::DurationMicroSeconds<i64>>")]
    pub rtt: Option<chrono::Duration>,
    #[serde_as(as = "Option<serde_with::DurationSeconds<i64>>")]
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
 * A (hopefuly useful) subset of all of the possible IP Protocols
 * /// use IpProtocol::*;
 * ///  assert_eq!(TCP, IpProtocol::from_wire(TCP.to_wire()));
 */

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd)]
pub struct RateEstimator {
    alpha: f64,
    estimate_rate_per_us: Option<f64>,
    #[serde(skip)]  // Instant doesn't serde, so skip serializing the time
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
            estimate_rate_per_us: None,
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
        let instant_rate = count as f64 / (time_delta.as_micros() as f64);
        if let Some(old_estimate) = self.estimate_rate_per_us {
            self.estimate_rate_per_us =
                Some(instant_rate * self.alpha + (1.0 - self.alpha) * old_estimate);
        } else {
            // the instant estimate becomes the full initial estimate
            self.estimate_rate_per_us = Some(instant_rate);
        }
        if let Some(last_sample) = self.last_sample {
            self.last_sample = Some(last_sample + time_delta);
        } else {
            panic!("Can't call RateEstimator::new_sample_with_duration() as the first sample");
        }
    }

    pub fn has_estimate(&self) -> bool {
        self.estimate_rate_per_us.is_some()
    }

    /**
     * Get the current rate estimate with best precision
     *
     * will return None if we don't have at least two samples
     */
    pub fn get_rate(&self) -> Option<(f64, std::time::Duration)> {
        if let Some(estimate) = self.estimate_rate_per_us {
            Some((estimate, std::time::Duration::from_micros(1)))
        } else {
            None
        }
    }

    /**
     * Get current rate estimate in "per seconds"
     */
    pub fn get_rate_per_second(&self) -> Option<f64> {
        match self.estimate_rate_per_us {
            Some(estimate) => Some(estimate * 1_000_000.0),
            None => None,
        }
    }
}

impl Eq for RateEstimator { }

/**
 * Rust doesn't like to autoimplement Ord for anything with floats
 */
impl Ord for RateEstimator {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.partial_cmp(other) {
            Some(o) => o,
            None => {
                match (self.estimate_rate_per_us, other.estimate_rate_per_us) {
                    (None, None) => std::cmp::Ordering::Equal,
                    (None, Some(_)) => std::cmp::Ordering::Less,
                    (Some(_), None) => std::cmp::Ordering::Greater,
                    (Some(e1), Some(e2)) => if e1 > e2 {
                        std::cmp::Ordering::Greater
                    } else {
                        std::cmp::Ordering::Less // don't care about equals in this case
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
    fn rate_estimator() {
        let mut rate = RateEstimator::new();
        rate.new_sample(10); // this is ignored, only used to start the timer
        assert_eq!(rate.get_rate_per_second(), None);
        rate.new_sample_with_duration(10, Duration::from_secs(1));
        let (estimate, duration) = rate.get_rate().unwrap();
        assert_eq!(duration, Duration::from_micros(1));
        let test_estimate = 10.0 / 1_000_000.0; // 1s == 1e7 us
        let epsilon = 1e-9;
        // floating point math can only ever be 'close enough'
        assert!((test_estimate - estimate).abs() < epsilon);
        // now update the estimate one last time and make sure it tracks properly
        rate.new_sample_with_duration(50, Duration::from_secs(1));
        let (estimate, duration) = rate.get_rate().unwrap();
        assert_eq!(duration, Duration::from_micros(1));
        assert!(estimate > test_estimate)
    }

    #[test]
    #[should_panic]
    fn rate_estimator_panic() {
        let mut rate = RateEstimator::new();
        rate.new_sample_with_duration(10, Duration::from_secs(1));
    }
}
