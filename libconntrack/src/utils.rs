use std::net::IpAddr;

use chrono::{DateTime, Utc};
use etherparse::IpHeader;

pub fn etherparse_ipheaders2ipaddr(ip: &Option<IpHeader>) -> Result<(IpAddr, IpAddr), pcap::Error> {
    match ip {
        Some(IpHeader::Version4(ip4, _)) => {
            Ok((IpAddr::from(ip4.source), IpAddr::from(ip4.destination)))
        }
        Some(IpHeader::Version6(ip6, _)) => {
            Ok((IpAddr::from(ip6.source), IpAddr::from(ip6.destination)))
        }
        None => Err(pcap::Error::PcapError("No IP address to parse".to_string())),
    }
}

/***
 * Given a remote IP address, figure out which local ip the local host
 * stack would use to connect to it.
 *
 * NOTE: this doesn't actually put any packets on the network and should
 * be reasonably cheap to run - just a local route table lookup
 *
 * NOTE: At least on MacOs with SLAAC IPv6 config, the OS will prefer a
 * temporary v6 address as src address, which has a limited lifetime
 * (couple of days).
 */

pub fn remote_ip_to_local(remote_ip: IpAddr) -> std::io::Result<IpAddr> {
    let udp_sock = match remote_ip {
        IpAddr::V4(_) => std::net::UdpSocket::bind(("0.0.0.0", 0))?,
        IpAddr::V6(_) => std::net::UdpSocket::bind(("::", 0))?,
    };
    udp_sock.connect((remote_ip, 53))?;
    Ok(udp_sock.local_addr()?.ip())
}

/**
 * Calculate the time between when packet_before was sent and pkt_after was received
 */

pub fn calc_rtt_ms(pkt_after: DateTime<Utc>, pkt_before: DateTime<Utc>) -> f64 {
    let dt = pkt_after - pkt_before;
    (dt.num_microseconds().unwrap_or(i64::MAX) as f64) / 1000.
}

/**
 * Convert a DateTime<Utc> to an f64 in _milliseconds_ that can be compared to
 * the output of Javascript's performance::now()
 */

pub fn timestamp_to_ms(ts: DateTime<Utc>) -> f64 {
    ts.timestamp_micros() as f64 / 1000.
}

// really should exist in some library somewhere
pub fn ip_proto_to_string(ip_proto: u8) -> String {
    use etherparse::IpNumber::*;
    if ip_proto == Tcp as u8 {
        String::from("Tcp")
    } else if ip_proto == Udp as u8 {
        String::from("Udp")
    } else {
        format!("ip_proto={}", ip_proto)
    }
}

/**
 * Easy macro to validate that a section of code ran in the given time.
 * TODO: use features to turn this on/off
 * TODO: use features to log this data ... somewhere... for regression testing
 *
 * perf_check!(message, instant, duration)
 *
 * /// use std::time::Instant;
 * ///
 * /// let start = Instant::now();
 * /// // do_something();
 * /// let (next_time, passed) = perf_check!("do_something()", start, Duration::from_millis(10));
 * /// assert!(passed);
 */

#[macro_export]
macro_rules! perf_check {
    ($m:expr, $t:expr, $d:expr) => {
        (|| -> (std::time::Instant, bool) {
            let now = std::time::Instant::now();
            let passed = if (now - $t) > $d {
                log::warn!(
                    "PERF_CHECK {}:{} failed: {} - {:?} > SLA of {:?}",
                    file!(),
                    line!(),
                    $m,
                    now - $t,
                    $d
                );
                false
            } else {
                log::trace!(
                    "PERF_CHECK {}:{} passed: {} - {:?} <= SLA of {:?}",
                    file!(),
                    line!(),
                    $m,
                    now - $t,
                    $d
                );
                true
            };
            (now, passed)
        })()
    };
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    // so sad that I have to test this; maybe #[ignore] now that it works?
    fn verify_calc_rtt() {
        use chrono::TimeZone;
        let a = Utc.timestamp_opt(1, 0).unwrap();
        let b = Utc.timestamp_opt(0, 5_000_000).unwrap();
        let diff = calc_rtt_ms(a, b);
        assert_eq!(diff, 995.0);
    }

    #[test]
    fn perf_check_test() {
        let start = std::time::Instant::now();
        let (next_step, passed) =
            perf_check!("trivial", start, std::time::Duration::from_millis(100));
        assert!(passed);
        let (_end, passed) = perf_check!(
            "bound to fail",
            next_step,
            std::time::Duration::from_millis(0)
        );
        assert!(!passed);
    }
}
