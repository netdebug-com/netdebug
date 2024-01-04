pub mod connection_key;
pub mod connection_measurements;
pub mod traffic_stats;

pub use connection_key::*;
pub use connection_measurements::*;
pub use traffic_stats::*;

use std::{fmt::Display, net::IpAddr, num::ParseIntError, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef; // reshare these identifiers in this namespace
pub mod topology_server_messages;

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
        nanos %= 1_000_000_000; // truncate off the seconds portion
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

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TypeDef,
)]
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
        match self {
            ICMP => 1,
            TCP => 6,
            UDP => 17,
            ICMP6 => 58,
            Other(ip_proto) => *ip_proto,
        }
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

impl FromStr for IpProtocol {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip_proto = u8::from_str(s)?;
        // once we get here, we can convert anything
        Ok(IpProtocol::from_wire(ip_proto))
    }
}

// sigh... really wish pcap::Device implemented Serialize/Deserialize
#[derive(Clone, Debug, Default, Serialize, Deserialize, TypeDef)]
pub struct NetworkInterfaceState {
    /// The default gw IPs, if known/assigned.  Could be empty
    pub gateways: Vec<IpAddr>,
    /// The name the OS gave to the interface, if exists/active
    /// If this is None then there is no active network.
    pub interface_name: Option<String>,
    /// The list of IPs bound to the interface, if exists. Could be empty.
    pub interface_ips: Vec<IpAddr>,
    /// A comment for when/how we got this info
    pub comment: String,
    /// Does the Network interface have link and is admin UP?
    pub has_link: bool,
    /// Is this a wireless interface?
    pub is_wireless: bool,
    /// The first time this config was set.
    #[type_def(type_of = "String")]
    pub start_time: DateTime<Utc>,
    /// If this is no longer the current config, when did it stop?
    #[type_def(type_of = "Option<String>")]
    pub end_time: Option<DateTime<Utc>>,
}

impl NetworkInterfaceState {
    /**
     * Walk through the important variables between the two states and see if they are the same
     * or different.  This is similar to PartialEq or Eq but ignores the timestamps and comment
     */
    pub fn has_state_changed(&self, state_update: &NetworkInterfaceState) -> bool {
        self.gateways
            .cmp(&state_update.gateways)
            .then(self.interface_name.cmp(&state_update.interface_name))
            .then(self.interface_ips.cmp(&state_update.interface_ips))
            .then(self.has_link.cmp(&state_update.has_link))
            .then(self.is_wireless.cmp(&state_update.is_wireless))
            .is_ne()
    }

    pub fn is_network_configured(&self) -> bool {
        self.interface_name.is_some()
    }

    /**
     * Don't mark as #[cfg(test)] because we want to reference it from other crates
     */
    pub fn mk_mock(interface_name: String, start_time: DateTime<Utc>) -> NetworkInterfaceState {
        NetworkInterfaceState {
            gateways: Vec::new(),
            interface_name: Some(interface_name),
            interface_ips: Vec::new(),
            comment: "mock".to_string(),
            has_link: true,
            is_wireless: false,
            start_time,
            end_time: None,
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

    #[test]
    fn test_pretty_print_si_units() {
        assert_eq!(pretty_print_si_units(Some(23e9), "Foo/s"), "23.00 GFoo/s");
        assert_eq!(pretty_print_si_units(Some(42e6), "Foo/s"), "42.00 MFoo/s");
        assert_eq!(pretty_print_si_units(Some(1.1e3), "Foo/s"), "1.10 KFoo/s");
        assert_eq!(pretty_print_si_units(Some(789.0), "Foo/s"), "789.00 Foo/s");
        assert_eq!(pretty_print_si_units(None, "Foo/s"), "None");
    }
}
