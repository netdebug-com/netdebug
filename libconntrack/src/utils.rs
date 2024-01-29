use std::net::IpAddr;

use chrono::{DateTime, Utc};
use common_wasm::timeseries_stats::{ExportedStatRegistry, StatHandleDuration};
use log::warn;
use mac_address::MacAddress;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::timeout,
};

use crate::owned_packet::OwnedParsedPacket;

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

/// An IPv6 "link-local" address (e.g., starts with fe80::) actually
/// encodes the MacAddress of the target.  Unfortunately it encodes it
/// in an arcane EUI-64 mechanism which involves the bit manipulation
/// equivalents of snuff porn and for no clear reason.  But sometimes
/// you have to put on the leather and ride that walrus... sigh...
///
/// NOTE: rust unstable has a [`IPv6Address.is_unicast_link_local`] function
/// which would solve some of this for us, but not all of it...
/// But we're not running unstable anyway, so...
pub fn link_local_ipv6_to_mac_address(ip: IpAddr) -> Option<MacAddress> {
    match ip {
        IpAddr::V4(_) => None, // not v6
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            if octets[0] != 0xfe || octets[1] != 0x80 || octets[11] != 0xff || octets[12] != 0xfe {
                return None; // not link local
            }
            // is link, local; now decode as a MacAddress ala EUI-64
            // I'm not making this shit up, see:
            // https://en.wikipedia.org/wiki/MAC_address  and
            // https://support.lenovo.com/us/en/solutions/ht509925-how-to-convert-a-mac-address-into-an-ipv6-link-local-address-eui-64
            Some(MacAddress::from([
                // NOTE: (1 << 1) is the 7th bit... somehow...
                // check out : 'bc -l' with 'ibase=16' and 'obase=2' if you don't believe me
                octets[8] ^ (1 << 1), // flip the 7th bit, but only on Tuesday
                octets[9],
                octets[10],
                // skip bytes 11-12, because they must have a higher rate of bit flipping/morally suspect
                octets[13],
                octets[14],
                octets[15],
            ]))
        }
    }
}

/// A helper function that implements our RPC-over-channels
/// TODO: testme....
pub async fn channel_rpc_perf<M, RESP>(
    request_tx: Sender<PerfMsgCheck<M>>,
    request_msg: M,
    response_rx: &mut Receiver<RESP>,
    log_msg: &str,
    sla: Option<tokio::time::Duration>,
) -> Result<RESP, ()> {
    channel_rpc(
        request_tx,
        PerfMsgCheck::new(request_msg),
        response_rx,
        log_msg,
        sla,
    )
    .await
}

/// A helper function that implements our RPC-over-channels
/// TODO: testme....
pub async fn channel_rpc<M, RESP>(
    request_tx: Sender<M>,
    request_msg: M,
    response_rx: &mut Receiver<RESP>,
    log_msg: &str,
    sla: Option<tokio::time::Duration>,
) -> Result<RESP, ()> {
    use crate::perf_check;
    let func_start = std::time::Instant::now();
    if let Err(e) = request_tx.try_send(request_msg) {
        warn!("Failed to send {} :: err {}", log_msg, e);
        return Err(());
    }
    // TODO: maybe base the timeout on SLA. For now just use something so we get
    // feedback and don't wait forever.
    let max_wait_time = tokio::time::Duration::from_millis(15_000);
    match timeout(max_wait_time, response_rx.recv()).await {
        Ok(resp) => match resp {
            Some(resp) => {
                if let Some(sla) = sla {
                    perf_check!(log_msg, func_start, sla);
                }
                Ok(resp)
            }
            None => {
                warn!("Failed to receive {} response. Channel closed", log_msg);
                Err(())
            }
        },
        Err(_) => {
            warn!("Timed out waiting to receive {} response.", log_msg);
            Err(())
        }
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
    if hostname.ends_with("amazonaws.com") {
        // FIXME: PSL failes to parse (at least some) hostnames with this domain. Hardcode it for now.
        // https://github.com/netdebug-com/netdebug/issues/315
        return Ok("amazonaws.com".to_owned());
    }
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
    use std::str::FromStr;

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

    #[test]
    fn test_ipv6_link_local_to_mac() {
        // double checked with online calculator
        // https://ben.akrin.com/ipv6-link-local-address-to-mac-address-online-converter/
        let ip1 = IpAddr::from_str("fe80::e21f:2bff:fe32:6e52").unwrap();
        let mac1 = MacAddress::from([0xE0, 0x1F, 0x2B, 0x32, 0x6E, 0x52]);
        assert_eq!(link_local_ipv6_to_mac_address(ip1), Some(mac1));
        let ip2 = IpAddr::from_str("fe80::62b7:6eff:feba:5989").unwrap();
        let mac2 = MacAddress::from([0x60, 0xb7, 0x6e, 0xba, 0x59, 0x89]);
        assert_eq!(link_local_ipv6_to_mac_address(ip2), Some(mac2));
        let ip3 = IpAddr::from_str("2600:1700:5b20:4e1f:a93d:d726:acd0:c0a3").unwrap();
        assert_eq!(link_local_ipv6_to_mac_address(ip3), None);
    }
}
