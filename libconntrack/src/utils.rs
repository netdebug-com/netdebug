use std::net::IpAddr;

use chrono::Duration;
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
 *
 * NOTE: we do not encode the _milliseconds_ part of the reply into the type
 * (e.g., ala std::time::Duration) because we need to communicate this value over
 * JSON which could get messy
 */

pub fn calc_rtt_ms(pkt_after: pcap::PacketHeader, pkt_before: pcap::PacketHeader) -> f64 {
    // my kingdom for timesub(3) - it's not in libc because it's just a macro
    let mut secs = (pkt_after.ts.tv_sec - pkt_before.ts.tv_sec) as f64;
    let mut usecs = (pkt_after.ts.tv_usec - pkt_before.ts.tv_usec) as f64;
    if usecs < 0.0 {
        secs -= 1.0;
        usecs += 1_000_000.0;
    }
    secs * 1000.0 + usecs / 1000.0
}

/**
 * Convert a libc::timeval to an f64 in _milliseconds_ that can be compared to
 * the output of Javascript's performance::now()
 */

pub fn timeval_to_ms(tv: libc::timeval) -> f64 {
    (tv.tv_sec as f64 * 1000.0) + (tv.tv_usec as f64 / 1000.0)
}

pub fn timeval_to_duration(tv: libc::timeval) -> chrono::Duration {
    Duration::microseconds(tv.tv_sec as i64 * 1_000_000 + tv.tv_usec as i64)
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
    use super::calc_rtt_ms;

    #[test]
    // so sad that I have to test this; maybe #[ignore] now that it works?
    fn verify_calc_rtt() {
        let b = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        let a = libc::timeval {
            tv_sec: 0,
            tv_usec: 5_000,
        };
        let pkt_after = pcap::PacketHeader {
            ts: b,
            caplen: 0,
            len: 0,
        };
        let pkt_before = pcap::PacketHeader {
            ts: a,
            caplen: 0,
            len: 0,
        };
        let diff = calc_rtt_ms(pkt_after, pkt_before);
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
