use async_trait::async_trait;
use common_wasm::{
    timeseries_stats::{ExportedStatRegistry, StatHandle, StatType, Units},
    PingTreeIpReport, PingtreeUiResult, ProbeReportSummary,
};
use itertools::Itertools;
use libconntrack_wasm::{ConnectionKey, NetworkInterfaceState};
use mac_address::MacAddress;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::Arc,
};
use tokio::time::{sleep_until, Duration};
use tokio::{sync::RwLock, time::Instant};
use uuid::Uuid;

#[cfg(not(test))]
use log::{debug, info, warn};
#[cfg(test)]
use std::{println as debug, println as warn, println as info}; // Workaround to use prinltn! for logs.

use crate::{
    connection::ConnectionUpdateReceiver,
    connection_tracker::{ConnectionTrackerMsg, ConnectionTrackerSender},
    owned_packet::OwnedParsedPacket,
    prober::{ProbeMessage, ProberSender},
    send_or_log_sync,
    system_tracker::SystemTracker,
    utils::{remote_ip_to_local, PerfMsgCheck, GOOGLE_DNS_IPV6},
};

pub fn probe_summary_to_ip_map(
    report: &ProbeReportSummary,
) -> (HashSet<IpAddr>, BTreeMap<u8, Vec<IpAddr>>) {
    let mut ip_set = HashSet::new();
    let mut map: BTreeMap<u8, Vec<IpAddr>> = BTreeMap::new();
    // Hop distances in ascending order
    let dists = report.summary.keys().copied().sorted().collect_vec();
    // iterate through the per-hop reports in ascending hop distance order
    for distance in dists {
        // we know the key exists so unwrap is safe
        let nodes = report.summary.get(&distance).unwrap();
        for node in nodes {
            if let Some(ip) = node.ip {
                ip_set.insert(ip);
                map.entry(distance).or_default().push(ip)
            }
        }
    }
    (ip_set, map)
}

#[async_trait]
pub trait PingTreeManager {
    async fn run_pingtree_for_probe_nodes(
        &self,
        probe_report_summary: &ProbeReportSummary,
    ) -> PingtreeUiResult;
}

/// Utility for handling pingtree requests for the desktop process / from GUI
pub struct PingTreeManagerImpl {
    connection_tracker_tx: ConnectionTrackerSender,
    prober_tx: ProberSender,
    system_tracker: Arc<RwLock<SystemTracker>>,
    /// The `id` to put in the `id` field of the ICMP echo request. Usually the
    /// PID of the sending process.
    /// Note, since we have multiple senders of pings in the desktop process, we
    /// use a unique payload to disambiguate
    ping_id: u16,
    /// tracks the number of echo replies we see without the associated request.
    /// This indicates performance issues (with the pcap capture or connection tracker
    /// since we should observe every request.
    pingtree_no_request: StatHandle,
    pingtree_not_for_us: StatHandle,
}

impl PingTreeManagerImpl {
    pub fn new(
        connection_tracker_tx: ConnectionTrackerSender,
        prober_tx: ProberSender,
        system_tracker: Arc<RwLock<SystemTracker>>,
        stats_registry: ExportedStatRegistry,
    ) -> Self {
        Self {
            connection_tracker_tx,
            prober_tx,
            system_tracker,
            // system_tracker uses the same id. We disambiguate based on payload
            ping_id: std::process::id() as u16,
            pingtree_no_request: stats_registry.add_stat(
                "pingtree_no_request",
                Units::None,
                [StatType::COUNT],
            ),
            pingtree_not_for_us: stats_registry.add_stat(
                "pingtree_not_for_us",
                Units::None,
                [StatType::COUNT],
            ),
        }
    }
}

#[async_trait]
impl PingTreeManager for PingTreeManagerImpl {
    /// Probe the IPs from the given ProbeReportSummary using pingtree.
    /// TODO: The ProbeReportSummary currently DOES NOT contain an IP for the final endhost, so we
    /// are not including the endhost in the pingtree -- only the routers.
    async fn run_pingtree_for_probe_nodes(
        &self,
        probe_report_summary: &ProbeReportSummary,
    ) -> PingtreeUiResult {
        let (ip_set, hops_to_ips) = probe_summary_to_ip_map(probe_report_summary);
        let interface_state = self
            .system_tracker
            .read()
            .await
            .get_current_network_state_no_pings();
        // TODO: if looking up egress info on every pingtree becomes too expensive we can cache it
        let mut gw_lookup = GatewayLookup::new(self.connection_tracker_tx.clone(), interface_state);
        gw_lookup.do_lookup().await;
        let cfg = PingTreeConfig {
            ips: ip_set,
            v4_egress_info: gw_lookup.v4_egress_info,
            v6_egress_info: gw_lookup.v6_egress_info,
            num_rounds: 5,
            time_between_rounds: tokio::time::Duration::from_millis(500),
            final_probe_wait: tokio::time::Duration::from_millis(2000),
            connection_tracker_tx: self.connection_tracker_tx.clone(),
            prober_tx: self.prober_tx.clone(),
            ping_id: self.ping_id,
            pingtree_no_request: self.pingtree_no_request.clone(),
            pingtree_not_for_us: self.pingtree_not_for_us.clone(),
        };
        let ip_reports = pingtree_result_to_ip_reports(&run_pingtree(cfg).await);
        PingtreeUiResult {
            hops_to_ips,
            ip_reports,
        }
    }
}

pub fn pingtree_result_to_ip_reports(
    ping_res: &PingTreeResult,
) -> HashMap<IpAddr, PingTreeIpReport> {
    let mut reports = HashMap::new();
    for (ip, raw_rtts) in ping_res {
        let raw_rtts_micros = raw_rtts
            .iter()
            .map(|rtt_opt| rtt_opt.map(|rtt| rtt.as_micros() as u64))
            .collect_vec();
        let rtts_without_none = raw_rtts_micros.iter().copied().flatten().collect_vec();
        let mean = if !rtts_without_none.is_empty() {
            Some(rtts_without_none.iter().sum::<u64>() / (rtts_without_none.len() as u64))
        } else {
            None
        };
        reports.insert(
            *ip,
            PingTreeIpReport {
                ip: *ip,
                raw_rtts_micros,
                min_rtt_micros: rtts_without_none.iter().copied().min(),
                max_rtt_micros: rtts_without_none.iter().copied().max(),
                mean_rtt_micros: mean,
            },
        );
    }
    reports
}

/// Information required to send egress packets.
/// This represents a point-in-time information and does not take network changes into
/// account. E.g., it does not handle/care about temporary IPv6 address changes, egress
/// interface changes, new DHCP IPs, etc. So this information should only be used for a bounded
/// amount of time.
#[derive(Clone, Debug)]
pub struct EgressInfo {
    /// The IP address of the default gateways to use. Generally only FYI
    /// unless you want to talk to the gateway directly
    pub gateway_ip: IpAddr,
    /// The MAC address of the default gateway (or broadcast MAC). Use as dst_mac
    pub gateway_mac: MacAddress,
    /// The local IP address from which to send packets. Use a src_ip
    pub local_ip: IpAddr,
    /// The local MAC address from which to send packets. Use a src_mac
    pub local_mac: MacAddress,
}

impl Display for EgressInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Local IP {}, Local Mac: {}, Gateway IP: {}, Gateway Mac: {}",
            self.local_ip, self.local_mac, self.gateway_ip, self.gateway_mac
        )
    }
}

impl EgressInfo {
    pub fn new(gateway_ip: IpAddr, gateway_mac: MacAddress) -> Self {
        let local_ip = match gateway_ip {
            IpAddr::V4(_) => remote_ip_to_local(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            IpAddr::V6(_) => remote_ip_to_local(IpAddr::from_str(GOOGLE_DNS_IPV6).unwrap()),
        }
        .unwrap_or_else(|e| {
            panic!(
                "Failed to lookup local IP while processing gateway {}: {}",
                gateway_ip, e
            )
        });
        let local_mac = match mac_address::get_mac_address_by_ip(&local_ip) {
            Ok(Some(mac)) => mac,
            _ => {
                warn!(
                    "Failed to look up local interface Mac Address for IP {}. Using broadcast Mac",
                    local_ip
                );
                MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
            }
        };
        EgressInfo {
            gateway_ip,
            gateway_mac,
            local_ip,
            local_mac,
        }
    }
}

/// Helper struct with the logic to lookup the local IP and MAC to use for
/// egress as well as the MAC for the v6 and v4 default gateways. It takes
/// the default gateways from the given NetworkInterfaceState.
/// It uses ConnectionTracker to perform the ARP/NDP lookup for
/// If the gateway MAC(s) don't resolve, we use the broadcast MAC
///
/// The EgressInfo's represent point-in-time views. They are not updated if
/// the network state changes or if temporary IPv6 addresses are rotated.
///
/// TODO: fix the ugly API of this thing.
pub struct GatewayLookup {
    pub v4_egress_info: Option<EgressInfo>,
    pub v6_egress_info: Option<EgressInfo>,
    connection_tracker_tx: ConnectionTrackerSender,
    interface_state: NetworkInterfaceState,
}

impl GatewayLookup {
    /// Initialize the GatewayLookup struct
    pub fn new(
        connection_tracker_tx: ConnectionTrackerSender,
        interface_state: NetworkInterfaceState,
    ) -> Self {
        Self {
            v4_egress_info: None,
            v6_egress_info: None,
            interface_state,
            connection_tracker_tx,
        }
    }

    /// Perform the actual lookup
    pub async fn do_lookup(&mut self) {
        for gw in &self.interface_state.gateways {
            match gw {
                IpAddr::V4(ip) => {
                    if let Some(old_v4_egress_info) = self.v4_egress_info.as_ref() {
                        panic!(
                            "More than one IPv4 gateway IP: {} and {} -- giving up",
                            old_v4_egress_info.gateway_ip, ip
                        );
                    }
                    let (gw_ip, gw_mac) = self.lookup_mac_by_ip(*gw).await;
                    self.v4_egress_info = Some(EgressInfo::new(gw_ip, gw_mac));
                }
                IpAddr::V6(ip) => {
                    if let Some(old_v6_egress_info) = self.v6_egress_info.as_ref() {
                        panic!(
                            "More than one IPv6 gateway IP: {} and {} -- giving up",
                            old_v6_egress_info.gateway_ip, ip
                        );
                    }
                    let (gw_ip, gw_mac) = self.lookup_mac_by_ip(*gw).await;
                    self.v6_egress_info = Some(EgressInfo::new(gw_ip, gw_mac));
                }
            }
        }
    }

    // internal helper
    async fn lookup_mac_by_ip(&self, gateway_ip: IpAddr) -> (IpAddr, MacAddress) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        info!("Looking up Mac for IP: {}", gateway_ip);
        self.connection_tracker_tx
            .try_send(PerfMsgCheck::new(ConnectionTrackerMsg::LookupMacByIp {
                identifier: String::default(),
                ip: gateway_ip,
                tx,
            }))
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to send LookupMacByIp message to connectiont tracker: {}",
                    e
                )
            });
        rx.recv().await.unwrap()
    }
}

/// The configuration and other info needed to perform a pingtree run.
#[derive(Debug, Clone)]
pub struct PingTreeConfig {
    /// The Ips to probe
    pub ips: HashSet<IpAddr>,
    /// The egress info to send out IPv4 pings
    pub v4_egress_info: Option<EgressInfo>,
    /// The egress info to send out IPv6 pings
    pub v6_egress_info: Option<EgressInfo>,
    /// The number of probe rounds to send out. Each IP in the set will
    /// receive that many pings.
    pub num_rounds: u16,
    /// Time between sending probe rounds
    pub time_between_rounds: Duration,
    /// After sending the final probe round: how long to wait for respones to
    /// come back.
    pub final_probe_wait: Duration,
    pub connection_tracker_tx: ConnectionTrackerSender,
    pub prober_tx: ProberSender,
    /// The `id` to put in the `id` field of the ICMP echo request. Usually the
    /// PID of the sending process.
    /// Note, since we have multiple senders of pings in the desktop process, we
    /// use a unique payload to disambiguate
    pub ping_id: u16,
    /// tracks the number of echo replies we see without the associated request.
    /// This indicates performance issues (with the pcap capture or connection tracker
    /// since we should observe every request.
    pub pingtree_no_request: StatHandle,
    pub pingtree_not_for_us: StatHandle,
}

impl PingTreeConfig {
    /// Return the EgressInfo for the IP. We only check if the ip is v4 or v6.
    /// We don't do any additional egress info lookups
    pub fn get_egress_info_or_die(&self, ip: &IpAddr) -> &EgressInfo {
        match ip {
            IpAddr::V4(_) => self
                .v4_egress_info
                .as_ref()
                .expect("No IPv4 EgressInfo available"),
            IpAddr::V6(_) => self
                .v6_egress_info
                .as_ref()
                .expect("No IPv6 EgressInfo available"),
        }
    }
}

/// Actually run the pingtree and return the result.
pub async fn run_pingtree(cfg: PingTreeConfig) -> PingTreeResult {
    let mut pt = PingTreeImpl::new(cfg, Uuid::new_v4());

    pt.send_next_round();
    let mut next_wakeup_time = Some(Instant::now() + pt.cfg.time_between_rounds);
    while next_wakeup_time.is_some() {
        tokio::select! {
            Some((pkt, key)) = pt.pkt_rx.recv() => {
                pt.handle_response(pkt, &key);
            },
            _ = sleep_until(next_wakeup_time.unwrap()) => {
                next_wakeup_time = pt.handle_woken_up();
            }
        }
    }
    info!("Finished ping tree. Aggregating results");
    pt.aggregate_results()
}

/// The result of a PingTree run. One hashmap entry for each IP address we probed.
/// Each per-ip entry is a list of (optional) RTTs values. One list item per round.
/// (i.e., `x.get(ip).unwrap().len() == num_rounds`). The RTT is none if we didn't
/// get a response (or failed to capture the outgoing probe).
pub type PingTreeResult = HashMap<IpAddr, Vec<Option<Duration>>>;

/// The actual state and implementation of a single pingtree run. Don't use it directly
struct PingTreeImpl {
    cfg: PingTreeConfig,
    /// The rx on which we receive packets (from connection tracker)
    pkt_rx: ConnectionUpdateReceiver,
    /// The connection keys for which we add update listeners to connection_tracker.
    /// we store it for easier cleanup
    conn_keys_to_listen_to: Vec<ConnectionKey>,
    /// The description we use when adding listeners.
    /// FIXME: right now multiple pingtrees would share the same description and we
    /// could not run multiple pingtrees in parallel. Need to make it unique.
    /// (but before that we need to fix the ping_id in cfg too)
    conn_listener_desc: String,
    /// Map from (IP, ping_seq_no) to the time we sent the echo request
    /// (or rather we saw the echo request from connection tracker)
    echo_sent_times: HashMap<(IpAddr, u16), Instant>,
    /// Map from (IP, ping_seq_no) to the time we received the echo response
    echo_recv_times: HashMap<(IpAddr, u16), Instant>,
    /// The current probe round (i.e., ping_seq)
    cur_round: u16,
    /// The payload to send in the echo request. Used to make sure that received echo requests
    /// and replies are associated with this pingtree instance
    ping_payload: Vec<u8>,
}

impl PingTreeImpl {
    pub fn new(cfg: PingTreeConfig, uuid: Uuid) -> Self {
        // size the channel based on number of IPs. With 2x number of IPs
        // we have space for request + response per round. Add some additional
        // space since we might also get stray pings from system tracker.
        // so 3x number of IPs it is.
        let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel(3 * cfg.ips.len());
        let mut conn_keys_to_listen_to = Vec::new();
        let conn_listener_desc = format!("pingtree--{}", uuid.hyphenated());
        for ip in &cfg.ips {
            let egress_info = cfg.get_egress_info_or_die(ip);

            conn_keys_to_listen_to.push(ConnectionKey::make_icmp_echo_key(
                egress_info.local_ip,
                *ip,
                cfg.ping_id,
            ));
            let key = conn_keys_to_listen_to.last().unwrap();
            send_or_log_sync!(
                cfg.connection_tracker_tx,
                "PingTree -- add listeners",
                ConnectionTrackerMsg::AddConnectionUpdateListener {
                    desc: conn_listener_desc.clone(),
                    tx: pkt_tx.clone(),
                    key: key.clone(),
                }
            );
        }
        // NOTE: pcap.rs might truncate packets, so if the ping_payload is too long, it might get truncated
        // on received packets. So we don't pad the payload and keep it reasonable short
        let mut ping_payload = Vec::new();
        ping_payload.extend(b"PingTree-");
        ping_payload.extend(uuid.hyphenated().to_string().as_bytes());

        Self {
            cfg,
            pkt_rx,
            conn_keys_to_listen_to,
            conn_listener_desc,
            echo_sent_times: HashMap::new(),
            echo_recv_times: HashMap::new(),
            cur_round: 0,
            ping_payload,
        }
    }

    fn all_rounds_sent(&self) -> bool {
        self.cur_round >= self.cfg.num_rounds
    }

    fn handle_response(&mut self, pkt: Box<OwnedParsedPacket>, key: &ConnectionKey) {
        if let Some(info) = pkt.get_icmp_echo_info() {
            assert_eq!(info.id, self.cfg.ping_id);
            if info.payload != self.ping_payload {
                self.cfg.pingtree_not_for_us.bump();
                return;
            }
            if info.seq >= self.cfg.num_rounds {
                warn!(
                    "Received echo reply with seq_no {} that's larger than num_rounds ({})",
                    info.seq, self.cfg.num_rounds
                );
                return;
            }
            let prev = if info.is_reply {
                debug!("Received response from {} seq {}", key.remote_ip, info.seq);
                self.echo_recv_times
                    .insert((key.remote_ip, info.seq), Instant::now())
            } else {
                debug!("Received request to {} seq {}", key.remote_ip, info.seq);
                self.echo_sent_times
                    .insert((key.remote_ip, info.seq), Instant::now())
            };
            if prev.is_some() {
                warn!(
                    "Received duplicate echo {} for IP {}",
                    if info.is_reply { "response" } else { "request" },
                    key.remote_ip
                );
            }
        }
    }

    fn handle_woken_up(&mut self) -> Option<Instant> {
        if !self.all_rounds_sent() {
            self.send_next_round();
            if self.all_rounds_sent() {
                info!("Finished sending all rounds. Waiting for final responses");
                Some(Instant::now() + self.cfg.final_probe_wait)
            } else {
                Some(Instant::now() + self.cfg.time_between_rounds)
            }
        } else {
            None
        }
    }

    fn send_next_round(&mut self) {
        assert!(!self.all_rounds_sent());
        info!("Sending ping probes for round {}", self.cur_round);
        for dst_ip in &self.cfg.ips {
            let egress_info = self.cfg.get_egress_info_or_die(dst_ip);
            send_or_log_sync!(
                self.cfg.prober_tx,
                "pingtree -- send ping",
                ProbeMessage::SendPing {
                    local_mac: egress_info.local_mac.bytes(),
                    local_ip: egress_info.local_ip,
                    remote_mac: Some(egress_info.gateway_mac.bytes()),
                    remote_ip: *dst_ip,
                    id: self.cfg.ping_id,
                    seq: self.cur_round,
                    payload: Some(self.ping_payload.clone()),
                }
            );
        }
        self.cur_round += 1;
    }

    fn aggregate_results(self) -> PingTreeResult {
        let mut result: PingTreeResult = HashMap::new();
        for ip in &self.cfg.ips {
            let this_ip_results = result.entry(*ip).or_default();
            for round in 0..self.cfg.num_rounds {
                let t_sent = self.echo_sent_times.get(&(*ip, round));
                let t_recv = self.echo_recv_times.get(&(*ip, round));
                let rtt = match (t_sent, t_recv) {
                    (Some(t_sent), Some(t_recv)) => Some(*t_recv - *t_sent),
                    (None, _) => {
                        // No request seen.
                        self.cfg.pingtree_no_request.bump();
                        None
                    }
                    _ => None,
                };
                this_ip_results.push(rtt);
            }
        }
        result
    }
}

impl Drop for PingTreeImpl {
    fn drop(&mut self) {
        for key in &self.conn_keys_to_listen_to {
            send_or_log_sync!(
                self.cfg.connection_tracker_tx,
                "PingTreeImpl::drop",
                ConnectionTrackerMsg::DelConnectionUpdateListener {
                    desc: self.conn_listener_desc.clone(),
                    key: key.clone()
                }
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use common::test_utils::test_dir;
    use common_wasm::timeseries_stats::{StatType, SuperRegistry, Units};
    use tokio::sync::mpsc::error::TryRecvError;

    use crate::prober::{make_ping_icmp_echo_reply, make_ping_icmp_echo_request};

    fn mkip(ip_str: &str) -> IpAddr {
        IpAddr::from_str(ip_str).unwrap()
    }

    #[tokio::test]
    async fn test_pingtree_impl() {
        let v4_egress_info = EgressInfo {
            gateway_ip: mkip("10.0.0.1"),
            gateway_mac: MacAddress::new([1, 2, 3, 4, 5, 6]),
            local_ip: mkip("10.0.0.42"),
            local_mac: MacAddress::new([42, 42, 42, 0, 0, 0]),
        };
        let (conn_track_tx, mut conn_track_rx) = tokio::sync::mpsc::channel(100);
        let (prober_tx, mut prober_rx) = tokio::sync::mpsc::channel(100);
        let registry = SuperRegistry::new(std::time::Instant::now()).new_registry("test-pingtree");
        let pingtree_no_request =
            registry.add_stat("pingtree_no_request", Units::None, [StatType::COUNT]);
        let pingtree_not_for_us =
            registry.add_stat("pingtree_not_for_us", Units::None, [StatType::COUNT]);
        let cfg = PingTreeConfig {
            ips: [mkip("8.8.8.8"), mkip("7.7.7.7")].into_iter().collect(),
            v4_egress_info: Some(v4_egress_info.clone()),
            v6_egress_info: None,
            num_rounds: 2,
            time_between_rounds: Duration::from_millis(500),
            final_probe_wait: Duration::from_millis(2000),
            connection_tracker_tx: conn_track_tx,
            prober_tx,
            ping_id: 42,
            pingtree_no_request: pingtree_no_request.clone(),
            pingtree_not_for_us: pingtree_not_for_us.clone(),
        };

        let uuid_str = "42000000-0000-0000-0000-12340000abcd";
        let mut pt = PingTreeImpl::new(cfg, Uuid::from_str(uuid_str).unwrap());

        let key7 = ConnectionKey::make_icmp_echo_key(v4_egress_info.local_ip, mkip("7.7.7.7"), 42);
        let key8 = ConnectionKey::make_icmp_echo_key(v4_egress_info.local_ip, mkip("8.8.8.8"), 42);
        let expected_conn_keys: HashSet<ConnectionKey> =
            [key7.clone(), key8.clone()].into_iter().collect();
        let mut conn_keys = HashSet::new();
        for _ in 0..2 {
            let msg = conn_track_rx.try_recv().unwrap().skip_perf_check();
            match msg {
                ConnectionTrackerMsg::AddConnectionUpdateListener { desc, key, .. } => {
                    assert_eq!(desc, format!("pingtree--{}", uuid_str));
                    conn_keys.insert(key);
                }
                _ => panic!("Unexpected message"),
            }
        }
        assert_eq!(conn_track_rx.try_recv().unwrap_err(), TryRecvError::Empty);
        assert_eq!(conn_keys, expected_conn_keys);

        // run a round. Prober should get requests to send pings
        pt.send_next_round();
        let mut pinged_ips = HashSet::new();
        let mut echo_payload = Vec::new();
        for _ in 0..2 {
            let msg = prober_rx.try_recv().unwrap().skip_perf_check();
            match msg {
                ProbeMessage::SendPing {
                    local_mac,
                    local_ip,
                    remote_mac,
                    remote_ip,
                    id,
                    seq,
                    payload,
                } => {
                    assert_eq!(local_mac, v4_egress_info.local_mac.bytes());
                    assert_eq!(remote_mac, Some(v4_egress_info.gateway_mac.bytes()));
                    assert_eq!(local_ip, v4_egress_info.local_ip);
                    pinged_ips.insert(remote_ip);
                    assert_eq!(id, 42);
                    assert_eq!(seq, 0);
                    echo_payload = payload.unwrap();
                }
                _ => panic!("Unexpected message"),
            }
        }

        // Feed actual echo requests and recho replies into pingtree
        tokio::time::pause();
        let pkt = OwnedParsedPacket::try_from_fake_time(make_ping_icmp_echo_request(
            &v4_egress_info.local_ip,
            &mkip("7.7.7.7"),
            v4_egress_info.local_mac.bytes(),
            v4_egress_info.gateway_mac.bytes(),
            42,
            0,
            echo_payload.clone(),
        ))
        .unwrap();
        pt.handle_response(pkt, &key7);
        let pkt = OwnedParsedPacket::try_from_fake_time(make_ping_icmp_echo_request(
            &v4_egress_info.local_ip,
            &mkip("8.8.8.8"),
            v4_egress_info.local_mac.bytes(),
            v4_egress_info.gateway_mac.bytes(),
            42,
            0,
            echo_payload.clone(),
        ))
        .unwrap();
        pt.handle_response(pkt, &key8);

        tokio::time::advance(Duration::from_millis(123)).await;

        // Only 8.8.8.8 replies
        let pkt = OwnedParsedPacket::try_from_fake_time(make_ping_icmp_echo_reply(
            &v4_egress_info.local_ip,
            &mkip("8.8.8.8"),
            v4_egress_info.local_mac.bytes(),
            v4_egress_info.gateway_mac.bytes(),
            42,
            0,
            echo_payload.clone(),
        ))
        .unwrap();
        pt.handle_response(pkt, &key8);

        // send the next round.
        pt.send_next_round();
        // we don't check the prober_tx here but we could. Maybe we should
        // make pingtree see just the 7.7.7.7 request
        let pkt = OwnedParsedPacket::try_from_fake_time(make_ping_icmp_echo_request(
            &v4_egress_info.local_ip,
            &mkip("7.7.7.7"),
            v4_egress_info.local_mac.bytes(),
            v4_egress_info.gateway_mac.bytes(),
            42,
            1,
            echo_payload.clone(),
        ))
        .unwrap();

        pt.handle_response(pkt, &key7);
        // ... and the 8.8.8.8 reply
        let pkt = OwnedParsedPacket::try_from_fake_time(make_ping_icmp_echo_reply(
            &v4_egress_info.local_ip,
            &mkip("8.8.8.8"),
            v4_egress_info.local_mac.bytes(),
            v4_egress_info.gateway_mac.bytes(),
            42,
            1,
            echo_payload.clone(),
        ))
        .unwrap();
        pt.handle_response(pkt, &key8);

        // check the results we should have:
        // round 0: 7.7.7.7 and 8.8.8.8 had a request, 8.8.8.8 had a response 123ms later
        // round 1: 7.7.7.7 had a request, 8.8.8.8 had a response.
        assert!(pt.all_rounds_sent());
        let res = pt.aggregate_results();
        assert_eq!(pingtree_no_request.get_sum(), 1);
        assert_eq!(
            res.keys().cloned().collect::<HashSet<IpAddr>>(),
            HashSet::from([mkip("7.7.7.7"), mkip("8.8.8.8")])
        );
        assert_eq!(res.get(&mkip("7.7.7.7")).unwrap(), &[None, None]);
        assert_eq!(
            res.get(&mkip("8.8.8.8")).unwrap(),
            &[Some(Duration::from_millis(123)), None]
        );

        // the pt.aggregate() call will cause `pt` to get dropped, so we can now
        // check that it has unregistered itself from the connection updater
        conn_keys.clear();
        for _ in 0..2 {
            let msg = conn_track_rx.try_recv().unwrap().skip_perf_check();
            match msg {
                ConnectionTrackerMsg::DelConnectionUpdateListener { desc, key } => {
                    assert_eq!(desc, format!("pingtree--{}", uuid_str));
                    conn_keys.insert(key);
                }
                _ => panic!("Unexpected message"),
            }
        }
        assert!(conn_track_rx.try_recv().is_err());
        assert_eq!(conn_keys, expected_conn_keys);
    }

    #[test]
    fn test_probe_summary_to_ip_map() {
        let json = std::fs::read_to_string(test_dir(
            "libconntrack",
            "tests/logs/probe-report-summary.json",
        ))
        .unwrap();
        let probe_report_summary = serde_json::from_str::<ProbeReportSummary>(&json).unwrap();
        let (ip_set, hops_to_ips) = probe_summary_to_ip_map(&probe_report_summary);
        assert_eq!(
            ip_set,
            HashSet::from([
                mkip("192.168.1.1"),
                mkip("96.120.18.197"),
                mkip("96.108.129.85"),
                mkip("96.108.141.249"),
                mkip("96.110.42.133"),
                mkip("96.110.32.126"),
                mkip("62.115.51.193"),
                mkip("62.115.123.122"),
                mkip("62.115.138.71"),
                mkip("62.115.136.83"),
                mkip("62.115.176.219"),
            ])
        );
        assert_eq!(
            hops_to_ips.keys().copied().collect_vec(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13]
        );
        assert_eq!(
            hops_to_ips.get(&1).unwrap().clone(),
            vec![mkip("192.168.1.1")]
        );
        assert_eq!(
            hops_to_ips.get(&6).unwrap().clone(),
            vec![mkip("96.110.32.126")]
        );
    }

    #[test]
    fn test_pingtree_result_to_ip_reports() {
        let mut ping_res: PingTreeResult = HashMap::new();
        ping_res.insert(
            mkip("10.0.0.1"),
            vec![None, Some(Duration::from_millis(123)), None],
        );
        ping_res.insert(mkip("20.0.0.1"), vec![None, None, None]);
        ping_res.insert(
            mkip("30.0.0.1"),
            vec![
                Some(Duration::from_millis(42)),
                Some(Duration::from_millis(23)),
                None,
            ],
        );
        ping_res.insert(
            mkip("40.0.0.1"),
            vec![
                Some(Duration::from_millis(40)),
                Some(Duration::from_millis(80)),
                Some(Duration::from_millis(10)),
            ],
        );

        let ip_reports = pingtree_result_to_ip_reports(&ping_res);

        assert_eq!(
            ip_reports.get(&mkip("10.0.0.1")).unwrap(),
            &PingTreeIpReport {
                ip: mkip("10.0.0.1"),
                raw_rtts_micros: vec![None, Some(123_000), None],
                min_rtt_micros: Some(123_000),
                max_rtt_micros: Some(123_000),
                mean_rtt_micros: Some(123_000),
            }
        );
        assert_eq!(
            ip_reports.get(&mkip("20.0.0.1")).unwrap(),
            &PingTreeIpReport {
                ip: mkip("20.0.0.1"),
                raw_rtts_micros: vec![None, None, None],
                min_rtt_micros: None,
                max_rtt_micros: None,
                mean_rtt_micros: None,
            }
        );
        assert_eq!(
            ip_reports.get(&mkip("30.0.0.1")).unwrap(),
            &PingTreeIpReport {
                ip: mkip("30.0.0.1"),
                raw_rtts_micros: vec![Some(42_000), Some(23_000), None],
                min_rtt_micros: Some(23_000),
                max_rtt_micros: Some(42_000),
                mean_rtt_micros: Some(32_500),
            }
        );
        assert_eq!(
            ip_reports.get(&mkip("40.0.0.1")).unwrap(),
            &PingTreeIpReport {
                ip: mkip("40.0.0.1"),
                raw_rtts_micros: vec![Some(40_000), Some(80_000), Some(10_000)],
                min_rtt_micros: Some(10_000),
                max_rtt_micros: Some(80_000),
                mean_rtt_micros: Some(43_333),
            }
        );
    }
}
