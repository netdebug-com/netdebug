use std::net::IpAddr;

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
}
