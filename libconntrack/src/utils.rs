use std::net::IpAddr;

use chrono::{DateTime, Utc};
use common_wasm::timeseries_stats::{ExportedStatRegistry, StatHandleDuration};
use etherparse::IpHeader;

use crate::owned_packet::OwnedParsedPacket;

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

pub fn packet_is_tcp_rst(packet: &OwnedParsedPacket) -> bool {
    if let Some(rst) = &(packet.transport)
        .as_ref()
        .and_then(|th| th.clone().tcp().map(|tcph| tcph.rst))
    {
        *rst
    } else {
        false
    }
}

/// Easy macro to reduce code testing errors and updating stats around our common
///  try_send pattern
/// ```rust
/// use std::vec::Vec;
/// use tokio::sync::mpsc::{Sender, channel};
/// use common_wasm::timeseries_stats::{ExportedStatRegistry, StatType, Units};
/// use log::warn;
/// use libconntrack::{send_or_log_sync, utils::PerfMsgCheck};
///
/// let (tx, _rx) = channel::<PerfMsgCheck<Vec<u8>>>(128);
/// let mut stats_registry = ExportedStatRegistry::new("example", std::time::Instant::now());
/// let mut msg_errs_counter = stats_registry.add_stat("message_tx_errors", Units::None, [StatType::COUNT]);
///
/// let data = Vec::from([0;128]);
/// // Instead of this:
/// // if let Err(e) = tx.try_send(PerfMsgChk::new(data)) {
/// //   warn!("Failed to send data to process: {}", e);
/// //   msg_errs_counter.update(1);
/// // }
/// // Write this:
/// send_or_log_sync!(tx, "process", data.clone(), &mut msg_errs_counter);
/// // Or this to explicitly specificy the SLA
/// send_or_log_sync!(tx, "process", data, &mut msg_errs_counter, std::time::Duration::from_millis(15));
/// // Or try_send_async!() if in an async context
/// ```

#[macro_export]
macro_rules! send_or_log_sync {
    // no stats or SLA
    ($tx:expr, $msg:expr, $data:expr) => {{
        if let Err(e) = $tx.try_send(PerfMsgCheck::new($data)) {
            warn!("Failed to send data to {} :: err {}", $msg, e);
        }
    }};
    // stats, no SLA
    ($tx:expr, $msg:expr, $data:expr, $stats:expr) => {{
        if let Err(e) = $tx.try_send(PerfMsgCheck::new($data)) {
            warn!("Failed to send data to {} :: err {}", $msg, e);
        }
        $stats.add_value(1);
    }};
    // stats AND SLA
    ($tx:expr, $msg:expr, $data:expr, $stats:expr, $sla:expr) => {
        (|| {
            if let Err(e) = $tx.try_send($crate::utils::PerfMsgCheck::with_sla($data, $sla)) {
                warn!("Failed to send data to {} :: err {}", $msg, e);
                $stats.add_value(1);
            }
        })()
    };
}

/// Easy macro to reduce code testing errors and updating stats around our common
/// try_send pattern
///
/// ```rust
/// # tokio_test::block_on( async {
/// use std::vec::Vec;
/// use tokio::sync::mpsc::{Sender, channel};
/// use common_wasm::timeseries_stats::{ExportedStatRegistry, StatType, Units};
/// use log::warn;
/// use libconntrack::{send_or_log_async, utils::PerfMsgCheck};
///
/// let (tx, _rx) = channel::<PerfMsgCheck<Vec<u8>>>(128);
/// let mut stats_registry = ExportedStatRegistry::new("example", std::time::Instant::now());
/// let mut msg_errs_counter = stats_registry.add_stat("message_tx_errors", Units::None, [StatType::COUNT]);
///
/// let data = Vec::from([0;128]);
/// // Instead of this:
/// // if let Err(e) = tx.send(PerfMsgChk::new(data)).await {
/// //   warn!("Failed to send data to process: {}", e);
/// //   msg_errs_counter.update(1);
/// // }
/// // Write this:
/// send_or_log_async!(tx, "process", data.clone(), &mut msg_errs_counter).await;
/// // Or this to explicitly specificy the SLA
/// send_or_log_async!(tx, "process", data, &mut msg_errs_counter, std::time::Duration::from_millis(15)).await;
/// # });
/// ```
#[macro_export]
macro_rules! send_or_log_async {
    ($tx:expr, $msg:expr, $data:expr) => {
        async {
            if let Err(e) = $tx.send(PerfMsgCheck::new($data)).await {
                warn!("Failed to send data to {:?} :: err {}", $msg, e);
            }
        }
    };
    ($tx:expr, $msg:expr, $data:expr, $stat:expr) => {
        async {
            if let Err(e) = $tx.send(PerfMsgCheck::new($data)).await {
                warn!("Failed to send data to {:?} :: err {}", $msg, e);
            }
            $stat.add_value(1);
        }
    };
    ($tx:expr, $msg:expr, $data:expr, $stat:expr, $sla:expr) => {
        async {
            if let Err(e) = $tx.send(PerfMsgCheck::with_sla($data, $sla)).await {
                warn!("Failed to send data to {:?} :: err {}", $msg, e);
            }
            $stat.add_value(1);
        }
    };
}
/**
 * Easy macro to validate that a section of code ran in the given time.
 * TODO: use features to turn this on/off
 * TODO: use features to log this data ... somewhere... for regression testing
 *
 * perf_check!(message, instant, duration)
 * perf_check!(message, instant, duration, perf_check_stat)
 *
 * ```
 * use std::time::{Duration, Instant};
 *
 * use common_wasm::timeseries_stats::{CounterProvider, ExportedStatRegistry};
 * use libconntrack::perf_check;
 * use libconntrack::utils::make_perf_check_stats;
 *
 * let start = Instant::now();
 * // do_something();
 * let (next_time, passed) = perf_check!("do_something()", start, Duration::from_millis(10));
 * assert!(passed);
 *
 * let mut stat_registry = ExportedStatRegistry::new("example", Instant::now());
 * let mut perf_stats = make_perf_check_stats("foobar", &mut stat_registry);
 * perf_check!("foo bar baz", start, Duration::from_millis(10), perf_stats);
 * assert_eq!(*stat_registry.get_counter_map().get("example.perf.foobar.violations.us.COUNT.60").unwrap(), 0);
 * ```
 */

#[macro_export]
macro_rules! perf_check {
    ($m:expr, $t:expr, $d:expr) => {{
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
    }};
    ($m:expr, $t:expr, $d:expr, $s:expr) => {{
        let now = std::time::Instant::now();
        let elapsed = (now - $t);
        let passed = if elapsed > $d {
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
        $s.duration.add_duration_value(elapsed);
        if !passed {
            $s.violations.add_duration_value(elapsed);
        }
        (now, passed)
    }};
}

/// Wrapper around the two StatHandle we want to use for `perf_check!()`
/// This allows the `perf_check!()` macro to track duration, violations, etc. as
/// ExportedStat
#[derive(Clone)]
pub struct PerfCheckStats {
    /// Tracks the number of SLA violations (COUNT) as well as the AVG and
    /// MAX violation time
    pub violations: StatHandleDuration,
    /// Tracks the MAX and AVG of the duration, regardless of whether it violated the SLA or not
    pub duration: StatHandleDuration,
}

/// Create a PerfCheckStats instance using the given basename and registry
pub fn make_perf_check_stats(name: &str, registry: &mut ExportedStatRegistry) -> PerfCheckStats {
    use common_wasm::timeseries_stats::{StatType, Units};
    let violation_name = format!("perf.{}.violations", name);
    let duration_name = format!("perf.{}.duration", name);
    PerfCheckStats {
        violations: registry.add_duration_stat(
            &violation_name,
            Units::Microseconds,
            [StatType::COUNT, StatType::AVG, StatType::MAX],
        ),
        duration: registry.add_duration_stat(
            &duration_name,
            Units::Microseconds,
            [StatType::AVG, StatType::MAX],
        ),
    }
}

/**
 * Used to track enqueue/dequeue times to make sure queue depths don't get too long.
 * Wraps any Message and forces you to check the performance to get the message
 */

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfMsgCheck<T> {
    data: T,
    send_time: std::time::Instant,
    sla: std::time::Duration,
}

impl<T> PerfMsgCheck<T> {
    pub fn new(data: T) -> PerfMsgCheck<T> {
        PerfMsgCheck {
            data,
            send_time: std::time::Instant::now(),
            sla: std::time::Duration::from_millis(50), // default perf_check time
        }
    }

    pub fn with_sla(data: T, sla: std::time::Duration) -> PerfMsgCheck<T> {
        PerfMsgCheck {
            data,
            send_time: std::time::Instant::now(),
            sla,
        }
    }

    pub fn perf_check_get(self, msg: &str) -> T {
        perf_check!(msg, self.send_time, self.sla);
        self.data
    }

    /**
     * For testing, sometimes we want to skip the perf checks
     */
    #[cfg(test)]
    pub fn skip_perf_check(self) -> T {
        self.data
    }

    pub fn perf_check_get_with_stats(self, msg: &str, duration_stat: &mut StatHandleDuration) -> T {
        let delta = std::time::Instant::now() - self.send_time;
        perf_check!(msg, self.send_time, self.sla);
        duration_stat.add_duration_value(delta);
        self.data
    }
}

/**
 * Convert the hostname to the relevant part of the DNS domain using
 * the public suffix list.  Then apply a list of aliases to convert
 * related domains to their well-known equivalents, e.g., "1e100.net" --> "google.com"
 *
 * TODO: list of aliases should probably be more complete
 */

pub fn dns_to_cannonical_domain(hostname: &str) -> Result<String, String> {
    let hostname = hostname.to_lowercase();
    // use the 'psl' crate that uses the https://publicsuffix.org/ list to parse the domain
    // this is non-trivial so I'm glad someone else solved this for us!
    // Note that psl downloads a new copy of the list at it's publication time
    // so the list updates with each new release of psl - which should be fine for
    // our purposes (which are mostly cosmetic)
    let domain = match psl::domain(hostname.as_bytes()) {
        Some(domain) => domain,
        None => {
            return Err(format!(
                "public suffix list failed to parse domain {}",
                hostname
            ))
        }
    };
    // now apply aliases
    let cannonical_domain = match domain.as_bytes() {
        // TODO: this list is woefully inadequate
        b"googlecontent.com" | b"googleusercontent.com" | b"1e100.net" => b"google.com",
        _other => _other,
    };
    Ok(String::from_utf8_lossy(cannonical_domain).to_string())
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

    #[test]
    fn test_dns_cannonical_domain() {
        let test_pairs = [
            ("foo.bar.com", "bar.com"),
            ("foo.bar.co.uk", "bar.co.uk"),
            ("googlehosted.l.googleusercontent.com", "google.com"),
        ];

        for (test, valid) in test_pairs {
            assert_eq!(dns_to_cannonical_domain(test), Ok(valid.to_string()));
        }
    }
}
