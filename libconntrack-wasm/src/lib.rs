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

#[cfg(test)]
mod test {
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
}
