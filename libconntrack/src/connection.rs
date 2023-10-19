use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    num::Wrapping,
    time::Instant,
};

use chrono::{DateTime, Duration, Utc};
use common_wasm::{
    analysis_messages::AnalysisInsights, evicting_hash_map::EvictingHashMap, ProbeId,
    ProbeReportEntry, ProbeReportSummary, ProbeRoundReport, PROBE_MAX_TTL,
};
use etherparse::{IpHeader, TcpHeader, TcpOptionElement, TransportHeader, UdpHeader};
use libconntrack_wasm::{
    aggregate_counters::{
        AggregateCounter, AggregateCounterConnectionTracker, AggregateCounterKind,
    },
    DnsTrackerEntry, IpProtocol, RateEstimator,
};
#[cfg(not(test))]
use log::{debug, info, warn};
use netstat2::ProtocolSocketInfo;
use pb_conntrack_types::ConnectionStorageEntry;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedSender};

#[cfg(test)]
use std::{println as debug, println as info, println as warn}; // Workaround to use prinltn! for logs.

use serde::{Deserialize, Serialize};

use crate::{
    analyze::analyze,
    dns_tracker::{DnsTrackerMessage, UDP_DNS_PORT},
    in_band_probe::ProbeMessage,
    owned_packet::OwnedParsedPacket,
    process_tracker::ProcessTrackerEntry,
    utils::{
        self, calc_rtt_ms, etherparse_ipheaders2ipaddr, packet_is_tcp_rst, timestamp_to_ms,
        PerfMsgCheck,
    },
};

/// When evicting stale/old connection entries: evict at most this many
/// connections at once
const MAX_ENTRIES_TO_EVICT: usize = 10;
/// If a connection has not seen any packets in this many milliseconds, the connection is
/// evicted. This is done regardless of the connection is open or closed.
const TIME_WAIT_MS: u64 = 60_000;

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ConnectionKey {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub local_l4_port: u16,
    pub remote_l4_port: u16,
    pub ip_proto: u8,
}

impl std::fmt::Display for ConnectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto_desc = utils::ip_proto_to_string(self.ip_proto);
        write!(
            f,
            "{} [{}]::{} --> [{}]::{} ",
            proto_desc, self.local_ip, self.local_l4_port, self.remote_ip, self.remote_l4_port,
        )
    }
}

impl ConnectionKey {
    /**
     * Create a ConnectionKey from a remote socket addr and the global context
     *
     * NOTE: this code will not work in WASM b/c of the udp call
     */
    pub async fn new(local_l4_port: u16, addr: &SocketAddr, ip_proto: u8) -> Self {
        // Annoying - it turns out it's hard in Warp to figure out which local IP a given
        // connection is talking to - this technique should be close, but might
        // have problems with funky routing tables, e.g., where the packets
        // are coming in one interface but going out another

        let remote_ip = addr.ip();
        let local_ip = crate::utils::remote_ip_to_local(remote_ip).unwrap();

        ConnectionKey {
            local_ip,
            remote_ip,
            local_l4_port,
            remote_l4_port: addr.port(),
            ip_proto,
        }
    }

    pub fn from_protocol_socket_info(proto_info: &ProtocolSocketInfo) -> Self {
        match proto_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                if tcp.local_addr != tcp.remote_addr {
                    ConnectionKey {
                        local_ip: tcp.local_addr,
                        remote_ip: tcp.remote_addr,
                        local_l4_port: tcp.local_port,
                        remote_l4_port: tcp.remote_port,
                        ip_proto: etherparse::IpNumber::Tcp as u8,
                    }
                } else {
                    // this is commonly local_ip=remote_ip=localhost
                    // so sort the ports to create a cannoical key
                    let local_port = std::cmp::min(tcp.local_port, tcp.remote_port);
                    let remote_port = std::cmp::max(tcp.local_port, tcp.remote_port);
                    ConnectionKey {
                        local_ip: tcp.local_addr,
                        remote_ip: tcp.remote_addr,
                        local_l4_port: local_port,
                        remote_l4_port: remote_port,
                        ip_proto: etherparse::IpNumber::Tcp as u8,
                    }
                }
            }
            ProtocolSocketInfo::Udp(_udp) => {
                panic!("Not supported for UDP yet - check out https://github.com/ohadravid/netstat2-rs/issues/11")
            }
        }
    }

    pub fn to_string_with_dns(&self, dns_cache: &HashMap<IpAddr, DnsTrackerEntry>) -> String {
        let local = if let Some(entry) = dns_cache.get(&self.local_ip) {
            entry.hostname.clone()
        } else {
            format!("[{}]", self.local_ip)
        };
        let remote = if let Some(entry) = dns_cache.get(&self.remote_ip) {
            entry.hostname.clone()
        } else {
            format!("[{}]", self.remote_ip)
        };
        let proto_desc = utils::ip_proto_to_string(self.ip_proto);
        format!(
            "{} {}::{} --> {}::{} ",
            proto_desc, local, self.local_l4_port, remote, self.remote_l4_port,
        )
    }
}

pub type ConnectionTrackerSender = Sender<PerfMsgCheck<ConnectionTrackerMsg>>;
pub type ConnectionTrackerReceiver = Receiver<PerfMsgCheck<ConnectionTrackerMsg>>;

/**
 * ConnectionTracker uses the Agent model :: https://en.wikipedia.org/wiki/Agent-oriented_programming
 * which simplifies multithreading and state management.
 *
 * When a piece of code wants to interact with a ConnectionTracker, get the sender from the
 * global context and send it an async message
 */
#[derive(Debug)]
pub enum ConnectionTrackerMsg {
    Pkt(Box<OwnedParsedPacket>), // send to the connection tracker to track
    ProbeReport {
        key: ConnectionKey,
        clear_state: bool,
        probe_round: u32,
        application_rtt: Option<f64>,
        tx: mpsc::Sender<ProbeRoundReport>,
    },
    SetUserAnnotation {
        annotation: String,
        key: ConnectionKey,
    },
    SetUserAgent {
        user_agent: String,
        key: ConnectionKey,
    },
    GetInsights {
        key: ConnectionKey,
        tx: mpsc::Sender<Vec<AnalysisInsights>>,
    },
    GetConnectionKeys {
        tx: mpsc::Sender<Vec<ConnectionKey>>,
    },
    GetConnections {
        tx: mpsc::UnboundedSender<Vec<Connection>>,
    },
    SetConnectionRemoteHostnameDns {
        key: ConnectionKey,
        remote_hostname: Option<String>, // will be None if lookup fails
    },
    GetAggregateCountersConnectionTracker {
        tx: mpsc::UnboundedSender<AggregateCounterConnectionTracker>,
    },
}

fn send_connection_storage_msg(
    storage_service_msg_tx: &Option<mpsc::Sender<ConnectionStorageEntry>>,
    mut c: Connection,
) {
    if c.probe_report_summary.raw_reports.is_empty() && !c.in_active_probe_session() {
        // This connection has not probes. Don't bother exporting it
        return;
    }
    if let Some(tx) = storage_service_msg_tx.as_ref() {
        if let Err(e) = tx.try_send(c.to_connection_storage_entry()) {
            // TODO: Should probably rate-limit the potential log message at some
            // point, but I think it's fine for now.
            warn!(
                "Could not send connection entry to storage handler: {:?}",
                e
            );
        }
    }
}

/***
 * Maintain the state for a bunch of connections.   Also, cache some information
 * that doesn't change often, e.g. ,the local IP addresses and listen port of
 * the webserver so we don't need to get the information from the WebServerContext every
 * packet.  The assumption is that if that information changes (e.g., new IP address),
 * then we would spin up new ConnectionTracker instances.
 */

pub struct ConnectionTracker<'a> {
    connections: EvictingHashMap<'a, ConnectionKey, Connection>,
    local_addrs: HashSet<IpAddr>,
    prober_tx: Sender<PerfMsgCheck<ProbeMessage>>,
    storage_service_msg_tx: Option<mpsc::Sender<ConnectionStorageEntry>>,
    dns_tx: Option<tokio::sync::mpsc::UnboundedSender<DnsTrackerMessage>>,
    tx: ConnectionTrackerSender, // so we can tell others how to send msgs to us
    rx: ConnectionTrackerReceiver, // to read messages sent to us
    // aggregate counters of everything that's gone through this connection manager
    tx_bytes: AggregateCounter,
    rx_bytes: AggregateCounter,
    dequeue_delay_stats_us: AggregateCounter,
}
impl<'a> ConnectionTracker<'a> {
    pub fn new(
        storage_service_msg_tx: Option<mpsc::Sender<ConnectionStorageEntry>>,
        max_connections_per_tracker: usize,
        local_addrs: HashSet<IpAddr>,
        prober_tx: Sender<PerfMsgCheck<ProbeMessage>>,
        max_queue_size: usize,
    ) -> ConnectionTracker<'a> {
        let (tx, rx) = tokio::sync::mpsc::channel(max_queue_size);
        let storage_service_msg_tx_clone = storage_service_msg_tx.clone();
        // for now, track these big counters by minute and second
        let tx_bytes = ConnectionTracker::create_aggregate_counter("tx_bytes");
        let rx_bytes = ConnectionTracker::create_aggregate_counter("rx_bytes");

        let mut dequeue_delay_stats_us = AggregateCounter::new(
            AggregateCounterKind::ConnectionTracker,
            "dequeue_delay stats".to_string(),
        );
        dequeue_delay_stats_us.add_time_series(
            "(us)".to_string(),
            std::time::Duration::from_millis(1),
            5000,
        );
        ConnectionTracker {
            connections: EvictingHashMap::new(
                max_connections_per_tracker,
                move |_k, v: Connection| {
                    debug!("Evicting connection");
                    send_connection_storage_msg(&storage_service_msg_tx_clone, v);
                },
            ),
            local_addrs,
            prober_tx,
            storage_service_msg_tx,
            dns_tx: None,
            tx,
            rx,
            tx_bytes,
            rx_bytes,
            dequeue_delay_stats_us,
        }
    }

    pub fn set_dns_tracker(&mut self, dns_tx: mpsc::UnboundedSender<DnsTrackerMessage>) {
        self.dns_tx = Some(dns_tx);
    }

    pub async fn rx_loop(&mut self) {
        let mut last_stats_update = std::time::Instant::now();
        while let Some(msg) = self.rx.recv().await {
            use ConnectionTrackerMsg::*;
            let msg = msg.perf_check_get_with_stats(
                "ConnectionTracker::rx_loop",
                &mut self.dequeue_delay_stats_us,
            );
            // TODO: fb303-style stats!!
            let now = Instant::now();
            if (now - last_stats_update) > std::time::Duration::from_secs(5) {
                last_stats_update = now;
                info!(
                    "ConnectionTracker dequeue delay stats: {}",
                    self.dequeue_delay_stats_us
                );
            }
            match msg {
                Pkt(pkt) => self.add(pkt),
                ProbeReport {
                    key,
                    clear_state,
                    tx,
                    probe_round,
                    application_rtt,
                } => {
                    self.generate_report(&key, probe_round, application_rtt, clear_state, tx)
                        .await
                }
                SetUserAnnotation { annotation, key } => {
                    self.set_user_annotation(&key, annotation).await;
                }
                GetInsights { key, tx } => self.get_insights(&key, tx).await,
                SetUserAgent { user_agent, key } => {
                    self.set_user_agent(&key, user_agent).await;
                }
                GetConnectionKeys { tx } => {
                    // so simple, no need for a dedicated function
                    let keys = self.connections.keys().map(|k| k.clone()).collect();
                    if let Err(e) = tx.send(keys).await {
                        warn!(
                            "Error sendings keys back to caller in GetConnectionKeys(): {}",
                            e
                        );
                    }
                }
                GetConnections { tx } => {
                    self.handle_get_connections(tx);
                }
                SetConnectionRemoteHostnameDns {
                    key,
                    remote_hostname,
                } => {
                    self.set_connection_remote_hostname_dns(&key, remote_hostname);
                }
                GetAggregateCountersConnectionTracker { tx } => {
                    self.get_aggregate_connection_tracker_counters(tx)
                }
            }
        }
        warn!("ConnectionTracker exiting rx_loop()");
    }

    pub fn add(&mut self, packet: Box<OwnedParsedPacket>) {
        let mut needs_dns_lookup = false;
        if let Some((key, src_is_local)) = packet.to_connection_key(&self.local_addrs) {
            if src_is_local {
                self.tx_bytes.update(packet.len as u64);
            } else {
                self.rx_bytes.update(packet.len as u64);
            }
            let connection = match self.connections.get_mut(&key) {
                Some(connection) => connection,
                None => {
                    if packet_is_tcp_rst(&packet) {
                        debug!("Not creating a new connection entry on RST");
                        return;
                    }
                    // else create the state and look it up again
                    self.new_connection(key.clone());
                    needs_dns_lookup = true;
                    self.connections.get_mut(&key).unwrap()
                }
            };
            connection.update(
                packet,
                &mut self.prober_tx,
                &key,
                src_is_local,
                &self.dns_tx,
            );
            if needs_dns_lookup {
                // only new connections that we don't immediately tear down need DNS lookups
                if let Some(dns_tx) = self.dns_tx.as_mut() {
                    // ask the DNS tracker to tell us the remote DNS name
                    if let Err(e) = dns_tx.send(DnsTrackerMessage::Lookup {
                        ip: key.remote_ip,
                        key: key.clone(),
                        tx: self.tx.clone(),
                    }) {
                        warn!("Failed to send a Lookup message to the DNS Tracker: {}", e);
                    }
                }
            }
            self.evict_old_connections();
        }
        // if we got here, the packet didn't have enough info to be called a 'connection'
        // just return and move on for now
    }

    /// Check the connections that haven't seen any updates the longest, and evict all that
    /// have been in-active for more than `TIME_WAIT_SECONDS`. Evict at most `MAX_ENTRIES_TO_EVICT`
    fn evict_old_connections(&mut self) {
        let mut eviction_cnt = 0;
        while let Some((_key, conn)) = self.connections.front() {
            let elapsed_ms = conn.last_packet_instant.elapsed().as_millis();
            if eviction_cnt < MAX_ENTRIES_TO_EVICT && elapsed_ms > TIME_WAIT_MS as u128 {
                let (_key, conn) = self.connections.pop_front().unwrap();
                send_connection_storage_msg(&self.storage_service_msg_tx, conn);
                eviction_cnt += 1;
            } else {
                break;
            }
        }
    }

    fn new_connection(&mut self, key: ConnectionKey) {
        let now = Utc::now();
        let connection = Connection {
            connection_key: key.clone(),
            local_syn: None,
            remote_syn: None,
            local_seq: None,
            local_ack: None,
            remote_ack: None,
            local_data: None,
            probe_round: None,
            local_fin_seq: None,
            remote_fin_seq: None,
            remote_rst: false,
            local_rst: false,
            probe_report_summary: ProbeReportSummary::new(),
            user_annotation: None,
            user_agent: None,
            associated_apps: None,
            start_tracking_time: now,
            last_packet_time: now,
            last_packet_instant: tokio::time::Instant::now(),
            remote_hostname: None,
            tx_byte_rate: RateEstimator::new(),
            rx_byte_rate: RateEstimator::new(),
            tx_packet_rate: RateEstimator::new(),
            rx_packet_rate: RateEstimator::new(),
        };
        debug!("Tracking new connection: {}", &key);

        self.connections.insert(key, connection);
    }

    /**
     * Generate a ProbeReport from the given connection/key
     *
     * If called with a bad key, caller will get back None from rx.recv() if we exit without
     */

    async fn generate_report(
        &mut self,
        key: &ConnectionKey,
        probe_round: u32,
        application_rtt: Option<f64>,
        clear_state: bool,
        tx: tokio::sync::mpsc::Sender<ProbeRoundReport>,
    ) {
        if let Some(connection) = self.connections.get_mut(key) {
            let report =
                connection.generate_probe_report(probe_round, application_rtt, clear_state);
            if let Err(e) = tx.send(report).await {
                warn!("Error sending back report: {}", e);
            }
        } else {
            warn!("Found no connection matching key {}", key);
            // sending nothing will close the connection and thus return None to the report receiver
        }
    }

    async fn set_user_annotation(&mut self, key: &ConnectionKey, annotation: String) {
        if let Some(connection) = self.connections.get_mut(key) {
            connection.user_annotation = Some(annotation);
        } else {
            warn!(
                "Tried to set_user_annotation for unknown connection {} -- {}",
                key, annotation
            );
        }
    }

    async fn set_user_agent(&mut self, key: &ConnectionKey, user_agent: String) {
        if let Some(connection) = self.connections.get_mut(key) {
            connection.user_agent = Some(user_agent);
        } else {
            warn!(
                "Tried to set_user_agent for unknown connection {} -- {}",
                key, user_agent
            );
        }
    }

    async fn get_insights(
        &mut self,
        key: &ConnectionKey,
        tx: tokio::sync::mpsc::Sender<Vec<AnalysisInsights>>,
    ) {
        if let Some(connection) = self.connections.get_mut(key) {
            let insights = analyze(connection);
            if let Err(e) = tx.send(insights).await {
                warn!("get_insights: {} :: {}", key, e);
            }
        } else {
            warn!("Tried to get_insights for unknown connection {}", key,);
        }
    }

    fn handle_get_connections(&self, tx: tokio::sync::mpsc::UnboundedSender<Vec<Connection>>) {
        let connections = self
            .connections
            .values()
            .cloned()
            .collect::<Vec<Connection>>();
        if let Err(e) = tx.send(connections) {
            warn!(
                "Tried to send the connections back to caller, but failed: {}",
                e
            );
        }
    }

    fn set_connection_remote_hostname_dns(
        &mut self,
        key: &ConnectionKey,
        remote_hostname: Option<String>,
    ) {
        if let Some(connection) = self.connections.get_mut(key) {
            connection.remote_hostname = remote_hostname;
        } else {
            // This can happen if the connection is torn down faster than we can get the DNS
            // name back from the DNS tracker; make it debug for now
            debug!(
                "Tried to lookup unknown key {} in the conneciton map trying to set DNS name {:?}",
                key, remote_hostname
            );
        }
    }

    pub fn set_tx_rx(&mut self, tx: ConnectionTrackerSender, rx: ConnectionTrackerReceiver) {
        self.tx = tx;
        self.rx = rx;
    }

    pub fn get_tx(&self) -> ConnectionTrackerSender {
        self.tx.clone()
    }

    /**
     * Create the aggregate counter for this connection tracker
     * Just do per second and per minute for now
     */
    fn create_aggregate_counter(counter_name: &str) -> AggregateCounter {
        let mut agg_counter = AggregateCounter::new(
            AggregateCounterKind::ConnectionTracker,
            counter_name.to_string(),
        );
        agg_counter.add_time_series(
            "Last 5 Seconds".to_string(),
            std::time::Duration::from_millis(10),
            500,
        );
        agg_counter.add_time_series(
            "Last Minute".to_string(),
            std::time::Duration::from_secs(1),
            60,
        );
        agg_counter.add_time_series(
            "Last Hour".to_string(),
            std::time::Duration::from_secs(60),
            60,
        );

        agg_counter
    }

    fn get_aggregate_connection_tracker_counters(
        &self,
        tx: UnboundedSender<AggregateCounterConnectionTracker>,
    ) {
        let counters = AggregateCounterConnectionTracker {
            send: self.tx_bytes.clone(),
            recv: self.rx_bytes.clone(),
        };
        if let Err(e) = tx.send(counters) {
            warn!(
                "Tried to send aggregate_counters back to caller but got {}",
                e
            );
        }
    }
}

/**
 * TODO: move Probe stuff to a separate file.
 *
 * There are 'ProbeRounds' which is the state for an active set ("round") of probes
 * while it's in process.  A "ProbeReport" which is a finished set of probes where
 * we match the incoming replies to the outgoing original packets ("probes").  There
 * is also a "ProbeReportSummary" which summarizes multiple probe reports.
 */

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeRound {
    pub round_number: usize,
    pub start_time: DateTime<Utc>,
    pub next_end_host_reply: ProbeId, // used for idle probes
    // current probes: outgoing probes and incoming replies
    pub outgoing_probe_timestamps: HashMap<ProbeId, HashSet<OwnedParsedPacket>>,
    pub incoming_reply_timestamps: HashMap<ProbeId, HashSet<OwnedParsedPacket>>,
}
impl ProbeRound {
    fn new(round_number: usize) -> ProbeRound {
        ProbeRound {
            round_number,
            start_time: Utc::now(),
            next_end_host_reply: PROBE_MAX_TTL - 1,
            outgoing_probe_timestamps: HashMap::new(),
            incoming_reply_timestamps: HashMap::new(),
        }
    }
}

/**
 * Main connection tracking structure - one per connection.
 *
 * NOTE: everything in this struct will get serialized to a logfile on the connection's close
 * for analysis, so be thoughtful what you add here.
 */
#[derive(Clone, Debug)]
pub struct Connection {
    pub connection_key: ConnectionKey,
    pub start_tracking_time: DateTime<Utc>,
    // Human readable time of the last packet for logging
    pub last_packet_time: DateTime<Utc>,
    // The time of the last packet used for evictions and statekeeping
    pub last_packet_instant: tokio::time::Instant,
    pub local_syn: Option<OwnedParsedPacket>,
    pub remote_syn: Option<OwnedParsedPacket>,
    pub local_seq: Option<Wrapping<u32>>, // the most recent seq seen from local INCLUDING the TCP payload
    pub local_ack: Option<Wrapping<u32>>,
    pub remote_ack: Option<Wrapping<u32>>,
    pub local_data: Option<OwnedParsedPacket>, // data sent for retransmits
    pub probe_round: Option<ProbeRound>,
    pub local_fin_seq: Option<Wrapping<u32>>, // used for tracking connection close
    pub remote_fin_seq: Option<Wrapping<u32>>,
    pub remote_rst: bool,
    pub local_rst: bool,
    pub probe_report_summary: ProbeReportSummary,
    pub user_annotation: Option<String>, // an human supplied comment on this connection
    pub user_agent: Option<String>, // when created via a web request, store the user-agent header
    pub associated_apps: Option<HashMap<u32, Option<String>>>, // PID --> ProcessName, if we know it
    pub remote_hostname: Option<String>, // the FQDN of the remote host, if we know it
    pub tx_byte_rate: RateEstimator,
    pub tx_packet_rate: RateEstimator,
    pub rx_byte_rate: RateEstimator,
    pub rx_packet_rate: RateEstimator,
}
impl Connection {
    fn update(
        &mut self,
        packet: Box<OwnedParsedPacket>,
        prober_tx: &mut Sender<PerfMsgCheck<ProbeMessage>>,
        key: &ConnectionKey,
        src_is_local: bool,
        dns_tx: &Option<mpsc::UnboundedSender<DnsTrackerMessage>>,
    ) {
        self.last_packet_time = Utc::now();
        if src_is_local {
            self.tx_byte_rate.new_sample(packet.len as usize);
            self.tx_packet_rate.new_sample(1);
        } else {
            self.rx_byte_rate.new_sample(packet.len as usize);
            self.rx_packet_rate.new_sample(1);
        }
        match &packet.transport {
            Some(TransportHeader::Tcp(tcp)) => {
                if src_is_local {
                    self.update_tcp_local(&packet, tcp, prober_tx);
                } else {
                    self.update_tcp_remote(&packet, tcp);
                }
            }
            Some(TransportHeader::Icmpv4(icmp4)) => {
                if src_is_local {
                    warn!(
                        "Ignoring weird ICMP4 from our selves but for this connection: {} : {:?}",
                        key, packet
                    );
                } else {
                    self.update_icmp4_remote(&packet, icmp4);
                }
            }
            Some(TransportHeader::Icmpv6(icmp6)) => {
                if src_is_local {
                    warn!(
                        "Ignoring ICMP6 from our selves but for this connection: {} : {:?}",
                        key, packet
                    );
                } else {
                    self.update_icmp6_remote(&packet, icmp6);
                }
            }
            Some(TransportHeader::Udp(udp)) => {
                // logic is for both src_is_local and not, for now
                self.update_udp(&key, &packet, udp, dns_tx, src_is_local);
            }
            None => {
                warn!(
                    "Ignoring unknown transport in IP protocol in packet {:?}",
                    packet
                );
            }
        }
    }

    /**
     * To avoid storing copies of all data, particularly in a high-speed connection,
     * we need a heuristic to separate outgoing probe packets and incoming incoming_reply_timestamps
     * from regular traffic...
     * .. but one that isn't obviously different enought to concern an IDS.
     *
     * It's performance issue if we mark too many packets as probes, so err on the
     * inclusive side and just say "any packet with a small payload" is a probe.
     *
     * Use the payload length to encode the probe ID/ttl
     */

    fn is_probe_heuristic(src_is_local: bool, packet: &OwnedParsedPacket) -> Option<ProbeId> {
        // any packet with a small payload is a probe
        if packet.payload.len() <= PROBE_MAX_TTL as usize {
            if src_is_local {
                // for outgoing packets, the TTL of the probe is the ttl of the outer packet
                let ttl = match &packet.ip {
                    None => None, // no IP header, not a probe
                    Some(IpHeader::Version4(ip4, _)) => Some(ip4.time_to_live),
                    Some(IpHeader::Version6(ip6, _)) => Some(ip6.hop_limit),
                };
                if let Some(t) = ttl {
                    if t > PROBE_MAX_TTL {
                        return None; // can't have a probe with a ttl larger than we would send
                    }
                }
                return ttl; // else assume the heuristicis correct
            }
        } else {
            // TODO: need to parse into the packet to extract the encapped payload and thus the probe ID
            return None;
        }
        None
    }

    fn update_tcp_local(
        &mut self,
        packet: &OwnedParsedPacket,
        tcp: &TcpHeader,
        prober_tx: &mut Sender<PerfMsgCheck<ProbeMessage>>,
    ) {
        // NOTE: we can't just use packet.payload.len() b/c we might have a partial capture
        let payload_len = match &packet.ip {
            None => 0,
            Some(IpHeader::Version4(ip4, _)) => {
                match ip4
                    .total_len()
                    .checked_sub(ip4.header_len() as u16 + tcp.header_len())
                {
                    Some(x) => x,
                    None => {
                        warn!(
                            "Malformed TCP packet with ip4.payload ({}) < ip4.header_len({}) + tcp.header_len ({}) :: {:?}",
                            ip4.total_len(),
                            ip4.header_len(),
                            tcp.header_len(),
                            &packet
                    );
                        0
                    }
                }
            }
            Some(IpHeader::Version6(ip6, _)) => {
                match ip6.payload_length.checked_sub(tcp.header_len()) {
                    Some(x) => x,
                    None => {
                        warn!(
                            "Malformed TCP packet with ip6.payload ({}) < tcp.header_len ({}) :: {:?}",
                            ip6.payload_length,
                            tcp.header_len(),
                            &packet
                        );
                        0
                    }
                }
            }
        };
        // every packet has a SEQ so just record the most recently one
        // we might thrash a bit if there's packet re-ordering but maybe that's OK?
        // currently this is only used for the self.is_idle_check()
        self.local_seq = Some(Wrapping(tcp.sequence_number) + Wrapping(payload_len as u32));
        // record the SYN to see which TCP options are negotiated
        if tcp.syn {
            self.local_syn = Some(packet.clone()); // memcpy() but doesn't happen that much or with much data
        }

        if tcp.rst {
            self.local_rst = true;
        }

        // record how far the local side has acknowledged
        if tcp.ack {
            self.local_ack = Some(Wrapping(tcp.acknowledgment_number));
        }

        // did we send some payload?
        if !packet.payload.is_empty() {
            let first_time = self.local_data.is_none();
            self.local_data = Some(packet.clone());
            // this is the first time in the connection lifetime we sent some payload
            // spawn an inband probe
            if first_time && !self.close_has_started() {
                // reset the probe state
                self.probe_round =
                    Some(ProbeRound::new(self.probe_report_summary.raw_reports.len()));
                // tcp_inband_probe(self.local_data.as_ref().unwrap(), raw_sock ).unwrap();
                if let Err(e) = prober_tx.try_send(PerfMsgCheck::new(ProbeMessage::SendProbe {
                    packet: packet.clone(),
                })) {
                    warn!("Problem sending to prober queue: {}", e);
                }
            }
        }
        if let Some(active_probe_round) = self.probe_round.as_mut() {
            if let Some(ttl) = Connection::is_probe_heuristic(true, packet) {
                // there's some super clean rust-ish way to compress this; don't care for now
                if let Some(probes) = active_probe_round.outgoing_probe_timestamps.get_mut(&ttl) {
                    probes.insert(packet.clone());
                } else {
                    let mut probes = HashSet::new();
                    probes.insert(packet.clone());
                    active_probe_round
                        .outgoing_probe_timestamps
                        .insert(ttl, probes);
                }
            }
        }
        if tcp.fin {
            // FIN's "use" a sequence number as if they sent a byte of data
            if let Some(fin_seq) = self.local_fin_seq {
                if fin_seq != Wrapping(tcp.sequence_number) {
                    warn!(
                        "Weird: got multiple local FIN seqnos: {} != {}",
                        fin_seq, tcp.sequence_number
                    );
                }
                // else it's just a duplicate packet
            }
            self.local_fin_seq = Some(Wrapping(tcp.sequence_number));
        }
        // TODO: look for outgoing selective acks (indicates packet loss)
    }

    fn update_tcp_remote(&mut self, packet: &OwnedParsedPacket, tcp: &TcpHeader) {
        if tcp.syn {
            if self.remote_syn.is_some() {
                warn!(
                    "Weird - multiple SYNs on the same connection: {}",
                    self.connection_key
                );
            }
            self.remote_syn = Some(packet.clone()); // memcpy() but doesn't happen that much or with much data
        }
        // record how far the remote side has acknowledged; check for old acks for outstanding probes
        if tcp.ack {
            // TODO: figure out if we need to implement Protection Against Wrapped Segments (PAWS) here
            // e.g., check to make sure that sequence space wraps are correctly handled
            // for now, wrapped segements show up as lost packets, so it's not the end of the world - I think
            // also make sure neither SYN or FIN are set as these can look like dupACKs if we're not careful
            if let Some(old_ack) = self.remote_ack {
                // Is this ACK a duplicate ACK?
                if old_ack == Wrapping(tcp.acknowledgment_number)
                    && packet.payload.len() == 0
                    && !tcp.syn
                    && !tcp.fin
                {
                    if let Some(Ok(selective_ack)) = tcp.options_iterator().find(|opt| {
                        matches!(&opt, Ok(TcpOptionElement::SelectiveAcknowledgement(_, _)))
                    }) {
                        // CRAZY: an out-of-sequence dupACK SHOULD contain a SACK option ala RFC2018, S4/page 5
                        // check whether the ACK sequence is ahead of the SACK range - that tells us it's a probe!
                        if let TcpOptionElement::SelectiveAcknowledgement((left, right), acks) =
                            selective_ack
                        {
                            if acks[0].is_some() || right > tcp.acknowledgment_number {
                                // this is not a dupACK/probe reply but a legit indication of a lost packet
                                // TODO: use selective ack params to estimate packets lost
                            } else {
                                // this is a dupACK/probe reply! the right - left indicates the probe id
                                let probe_id = if right >= left {
                                    // PAWS check
                                    right - left // NOTE: hand verified that this doesn't have off-by-one issues
                                } else {
                                    // SEQ wrapped!  (or maybe a malicious receiver?)
                                    (u32::MAX - left) + right
                                };
                                if let Some(active_probe_round) = self.probe_round.as_mut() {
                                    if probe_id <= PROBE_MAX_TTL as u32 {
                                        // record the reply
                                        let probe_id = probe_id as u8; // safe because we just checked
                                        if let Some(replies) = active_probe_round
                                            .incoming_reply_timestamps
                                            .get_mut(&probe_id)
                                        {
                                            replies.insert(packet.clone());
                                        } else {
                                            active_probe_round
                                                .incoming_reply_timestamps
                                                .insert(probe_id, HashSet::from([packet.clone()]));
                                        }
                                    } else {
                                        info!("Looks like we got a dupACK but the probe_id is too big {} :: {:?}", probe_id, packet);
                                    }
                                }
                            }
                        }
                    } else {
                        // Tested againstt all major stacks - everyone supports SACK so we
                        // don't need to handle the non-SACK case which can create noise
                        // the the code in place for now in case it's needed again (?)
                        //
                        // no SelectiveAck option, so asume this is a probe reply
                        // assume that inband ACK replies come from the highest TTL we sent
                        // and work backwards for each reply we received, e.g.,
                        // first reply is from TTL=max, second from TTL=max - 1, etc.
                        // this is a bit of a cheat as we really should try to match the
                        // reply to the actual outgoing probe that caused it, but there's not
                        // enough into the in ACK to infer the probe that caused it.  Working
                        // backwards adds some error to the RTT estimation, but it's on the
                        // order of the sent_time(probe_k) vs. sent_time(probe_n) which
                        // is extremely small (e.g., ~10 microseconds) because they are sent
                        // quickly back-to-back
                        /* if let Some(probe_id) = self.next_end_host_reply {
                            if let Some(replies) = self.incoming_reply_timestamps.get_mut(&probe_id)
                            {
                                replies.insert(packet.clone());
                            } else {
                                self.incoming_reply_timestamps
                                    .insert(probe_id, HashSet::from([packet.clone()]));
                            }
                            // make sure the next probe goes in the next nearer TTL's slot
                            if probe_id > 1 {
                                self.next_end_host_reply = Some(probe_id - 1);
                            }
                        } else {
                            warn!("Looks like we got a inband ACK reply without next_end_host_reply set!? : {:?}", self);
                        } */
                    }
                }
            }
            // what ever the case, update the ack for next time
            // NOTE: this could be a NOOP in the dup ack case
            self.remote_ack = Some(Wrapping(tcp.acknowledgment_number));
        }
        if tcp.fin {
            // FIN's "use" a sequence number as if they sent a byte of data
            if let Some(fin_seq) = self.remote_fin_seq {
                if fin_seq != Wrapping(tcp.sequence_number) {
                    warn!(
                        "Weird: got multiple remote FIN seqnos: {} != {}",
                        fin_seq, tcp.sequence_number
                    );
                }
                // else it's just a duplicate packet
            }
            self.remote_fin_seq = Some(Wrapping(tcp.sequence_number));
        }
        if tcp.rst {
            self.remote_rst = true;
        }
        // TODO: look for incoming selective acks (indicates packet loss)
    }

    // Check if the connection has started to be closed. I.e., we've received either a syn or a fin
    // from either side.
    pub fn close_has_started(&self) -> bool {
        self.local_rst
            || self.remote_rst
            || self.local_fin_seq.is_some()
            || self.remote_fin_seq.is_some()
    }

    /// is this the final ACK of the threeway close?
    /// Three-way close is:
    /// 1) Alice send FIN for Alice_seq+1
    /// 2) Bob sends FIN for Bob_seq+1 and ACK for Alice_seq+1
    /// 3) Alice sends ACK (no FIN) for Bob_seq+1
    ///
    /// NOTE: rust allows us to compare two Option<u32>'s directly,
    /// but the way None compares to Some(u32) breaks my brain so this is more
    /// typing but IMHO clearer
    fn is_four_way_close_done_or_rst(&self) -> bool {
        if self.local_rst || self.remote_rst {
            return true;
        }
        // has everyone sent their FIN's? (e.g. are we at least at step 3?)
        if self.local_fin_seq.is_some()
            && self.remote_fin_seq.is_some()
            && self.local_ack.is_some()
            && self.remote_ack.is_some()
        {
            // if we are at step 3, has everyone ACK'd everyone's FIN's?
            if self.remote_ack > self.local_fin_seq && self.local_ack > self.remote_fin_seq {
                // mark the connection closed
                return true;
            }
        }
        false
    }

    fn update_icmp6_remote(
        &mut self,
        packet: &OwnedParsedPacket,
        icmp6: &etherparse::Icmpv6Header,
    ) {
        match icmp6.icmp_type {
            etherparse::Icmpv6Type::Unknown { .. }
            | etherparse::Icmpv6Type::ParameterProblem(_)
            | etherparse::Icmpv6Type::EchoRequest(_)
            | etherparse::Icmpv6Type::EchoReply(_)
            | etherparse::Icmpv6Type::PacketTooBig { .. } => (),
            etherparse::Icmpv6Type::DestinationUnreachable(_)
            | etherparse::Icmpv6Type::TimeExceeded(_) => self.store_icmp_reply(packet),
        }
    }

    fn update_icmp4_remote(
        &mut self,
        packet: &OwnedParsedPacket,
        icmp4: &etherparse::Icmpv4Header,
    ) {
        match icmp4.icmp_type {
            etherparse::Icmpv4Type::Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            }
            | etherparse::Icmpv4Type::EchoRequest(_)
            | etherparse::Icmpv4Type::EchoReply(_)
            | etherparse::Icmpv4Type::TimestampRequest(_)
            | etherparse::Icmpv4Type::TimestampReply(_) => (),
            etherparse::Icmpv4Type::DestinationUnreachable(_)
            | etherparse::Icmpv4Type::Redirect(_)
            | etherparse::Icmpv4Type::TimeExceeded(_)
            | etherparse::Icmpv4Type::ParameterProblem(_) => self.store_icmp_reply(packet),
        }
    }

    fn store_icmp_reply(&mut self, packet: &OwnedParsedPacket) {
        // TODO figure out how to cache this from the connection_key() computation
        // if it's a perf problem - ignore for now
        // but right now we're creating this embedded packet twice!
        match OwnedParsedPacket::from_partial_embedded_ip_packet(
            &packet.payload,
            packet.timestamp,
            packet.len, // TODO: should we adjust the length here? But not clear to what w/o first parsing the pkt
        ) {
            Ok((pkt, _partial)) => {
                if let Some(probe_id) = self.is_reply_heuristic(&pkt) {
                    if let Some(active_probe_round) = self.probe_round.as_mut() {
                        if let Some(hash) = active_probe_round
                            .incoming_reply_timestamps
                            .get_mut(&probe_id)
                        {
                            hash.insert(pkt);
                        } else {
                            active_probe_round
                                .incoming_reply_timestamps
                                // careful to store the original packet and not the embedded one
                                .insert(probe_id, HashSet::from([packet.clone()]));
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to parsed update_icmp4_remote() {} for {:?}",
                    e, packet
                );
            }
        }
    }

    /**
     * Call on a packet which is potentially a reply to a probe and if it is,
     * extract the probe ID;  this should be called on the embedded packet
     * of an ICMP TTL exceeded
     *
     * Something is a probe is (1) it's old data and (2) if the payload
     * length (which we don't have but can reconstruct) is < PROBE_MAX_TTL
     *
     * This is a "heuristic" because there's possibly pathological behavior
     * in the network such that we falsely identify a regular packet as a reply
     */

    fn is_reply_heuristic(&self, pkt: &OwnedParsedPacket) -> Option<ProbeId> {
        match &pkt.transport {
            Some(TransportHeader::Tcp(_tcp)) => {
                // TODO: convert to SEQ-based probe-id encoding
                let (total_len, iph_len) = match &pkt.ip {
                    Some(IpHeader::Version4(ip4, _)) => {
                        // NOTE: etherparse "smartly" already returns hdr_len * 4
                        (ip4.total_len(), ip4.header_len() as u16)
                    }
                    Some(IpHeader::Version6(ip6, _)) => {
                        // NOTE: etherparse "smartly" already returns hdr_len * 4
                        // any icmp6 doesn't have ip6.total_len() so fake it
                        (
                            ip6.payload_length + ip6.header_len() as u16,
                            ip6.header_len() as u16,
                        )
                    }
                    None => {
                        warn!("No IP packet with a TCP packet!?");
                        return None;
                    }
                };
                // probe-Id = total_len - sizeof(iph) - sizeof(tcph)
                // but we don't have sizeof(tcph) here b/c it might be truncated
                // ASSUME Outgoing probes have no TCP options; so are exactly 20 bytes
                // which makes them look weird to an IDS and we lose precision
                let probe_id = total_len - iph_len - 20;

                if probe_id <= PROBE_MAX_TTL as u16 {
                    Some(probe_id as u8)
                } else {
                    None
                }
            }
            Some(_) | None => None,
        }
    }

    /**
     * Match up the outgoing probes vs. incoming replies and generate a
     * report.  If 'clear' is set, reset the connection's state so we can do a new set
     * of probes on the next data packet
     */
    fn generate_probe_report(
        &mut self,
        probe_round: u32,
        application_rtt: Option<f64>,
        clear: bool,
    ) -> ProbeRoundReport {
        let mut report = HashMap::new();
        if let Some(probe_round) = self.probe_round.as_mut() {
            if probe_round.outgoing_probe_timestamps.len() > PROBE_MAX_TTL as usize {
                warn!(
                    "Extra probes {} in {:?}",
                    probe_round.outgoing_probe_timestamps.len(),
                    self.connection_key,
                );
            }
            if probe_round.incoming_reply_timestamps.len() > PROBE_MAX_TTL as usize {
                warn!(
                    "Extra replies {} in {:?}",
                    probe_round.incoming_reply_timestamps.len(),
                    self.connection_key,
                );
            }
            for ttl in 1..=PROBE_MAX_TTL {
                let mut comment = String::new(); // no comment by default
                if let Some(probe_set) = probe_round.outgoing_probe_timestamps.get(&ttl) {
                    if probe_set.len() != 1 {
                        comment.push_str(
                            format!(
                                "Weird: {} probes found; guessing first one.",
                                probe_set.len()
                            )
                            .as_str(),
                        );
                    }
                    let probe = probe_set.iter().next().unwrap();
                    let out_timestamp_ms = timestamp_to_ms(probe.timestamp);
                    if let Some(reply_set) = probe_round.incoming_reply_timestamps.get(&ttl) {
                        if reply_set.len() != 1 {
                            comment.push_str(
                                format!(
                                    " Weird: {} replies found; guessing first one.",
                                    reply_set.len()
                                )
                                .as_str(),
                            );
                        }
                        // found a probe and a reply!
                        let reply = reply_set.iter().next().unwrap();
                        let rtt_ms = calc_rtt_ms(reply.timestamp, probe.timestamp);
                        if matches!(&reply.transport, Some(TransportHeader::Tcp(_tcph))) {
                            report.insert(
                                ttl,
                                ProbeReportEntry::EndHostReplyFound {
                                    ttl,
                                    out_timestamp_ms,
                                    rtt_ms,
                                    comment,
                                },
                            );
                        } else {
                            // else is an ICMP reply
                            // unwrap is ok here b/c we would have never stored a non-IP packet as a reply
                            let (src_ip, _dst_ip) = etherparse_ipheaders2ipaddr(&reply.ip).unwrap();
                            // NAT check - does the dst of the connection key == this src_ip?
                            if src_ip == self.connection_key.remote_ip {
                                report.insert(
                                    ttl,
                                    ProbeReportEntry::NatReplyFound {
                                        ttl,
                                        out_timestamp_ms,
                                        rtt_ms,
                                        src_ip,
                                        comment,
                                    },
                                );
                            } else {
                                report.insert(
                                    ttl,
                                    ProbeReportEntry::RouterReplyFound {
                                        ttl,
                                        out_timestamp_ms,
                                        rtt_ms,
                                        src_ip,
                                        comment,
                                    },
                                );
                            }
                        }
                    } else {
                        // missing reply - unfortunately common
                        report.insert(
                            ttl,
                            ProbeReportEntry::NoReply {
                                ttl,
                                out_timestamp_ms,
                                comment,
                            },
                        );
                    }
                } else {
                    // sigh, duplicate code
                    if let Some(reply_set) = probe_round.incoming_reply_timestamps.get(&ttl) {
                        if reply_set.len() != 1 {
                            comment.push_str(
                                format!(
                                    " Weird: {} replies found; guessing first one.",
                                    reply_set.len()
                                )
                                .as_str(),
                            );
                        }
                        // found a reply with out a probe (?) - can happen when pcap drops packets
                        let reply = reply_set.iter().next().unwrap();
                        // unwrap is ok here b/c we would have never stored a non-IP packet as a reply
                        let in_timestamp_ms = timestamp_to_ms(reply.timestamp);
                        if matches!(&reply.transport, Some(TransportHeader::Tcp(_tcp))) {
                            report.insert(
                                ttl,
                                ProbeReportEntry::EndHostNoProbe {
                                    ttl,
                                    in_timestamp_ms,
                                    comment,
                                },
                            );
                        } else {
                            // ICMP reply
                            let (src_ip, _dst_ip) = etherparse_ipheaders2ipaddr(&reply.ip).unwrap();
                            // NAT check - does the dst of the connection key == this src_ip?
                            if src_ip == self.connection_key.remote_ip {
                                report.insert(
                                    ttl,
                                    ProbeReportEntry::NatReplyNoProbe {
                                        ttl,
                                        in_timestamp_ms,
                                        src_ip,
                                        comment,
                                    },
                                );
                            } else {
                                report.insert(
                                    ttl,
                                    ProbeReportEntry::RouterReplyNoProbe {
                                        ttl,
                                        in_timestamp_ms,
                                        src_ip,
                                        comment,
                                    },
                                );
                            }
                        }
                    } else {
                        // missing both reply and probe - a bad day
                        report.insert(ttl, ProbeReportEntry::NoOutgoing { ttl, comment });
                    }
                }
            }
            if clear {
                self.clear_probe_data(true);
            }
        }
        let probe_report = ProbeRoundReport::new(report, probe_round, application_rtt);
        // one copy for us and one for the caller
        // the one for us will get logged to disk; the caller's will get sent to the remote client
        self.probe_report_summary.update(probe_report.clone());
        probe_report
    }

    /**
     * Reset the state around a set of probes.  If we clear the local_data,
     * then we're saying "when you next get a valid data packet, launch a probe
     * again".  
     */

    fn clear_probe_data(&mut self, flush_local_data: bool) {
        // clear any old probe data
        self.probe_round = None;
        if flush_local_data {
            self.local_data = None;
        }
    }

    fn in_active_probe_session(&self) -> bool {
        self.probe_round.is_some()
    }

    fn to_connection_storage_entry(&mut self) -> ConnectionStorageEntry {
        use pb_conntrack_types::MeasurementType;
        if self.in_active_probe_session() {
            let probe_round = self.probe_report_summary.raw_reports.len() as u32;
            self.generate_probe_report(probe_round, None, true);
        }
        ConnectionStorageEntry {
            measurement_type: MeasurementType::UnspecifiedMeasurementType as i32,
            local_hostname: None, // TODO
            local_ip: self.connection_key.local_ip.to_string(),
            local_port: self.connection_key.local_l4_port as u32,
            remote_hostname: self.remote_hostname.clone(),
            remote_ip: self.connection_key.remote_ip.to_string(),
            remote_port: self.connection_key.remote_l4_port as u32,
            ip_proto: self.connection_key.ip_proto as u32,
            probe_rounds: self
                .probe_report_summary
                .raw_reports
                .iter()
                .map(|report| report.to_protobuf())
                .collect(),
            user_annotation: self.user_annotation.clone(),
            user_agent: self.user_agent.clone(),
            // TODO: populate associated_apps. This is not a straight-forward as it might
            // appear. Connection::associated_apps is never populated. And in order to
            // retrieve it from the ProcessTracker, we need to send it a message and wait
            // for the response. Also the associated apps are not criticial at this stage since
            // we mostly need router IPs for now.
            associated_apps: Vec::new(),
        }
    }

    fn update_udp(
        &self,
        key: &ConnectionKey,
        packet: &OwnedParsedPacket,
        udp: &UdpHeader,
        dns_tx: &Option<mpsc::UnboundedSender<DnsTrackerMessage>>,
        src_is_local: bool,
    ) {
        if (src_is_local && udp.destination_port == UDP_DNS_PORT)
            || (!src_is_local && udp.source_port == UDP_DNS_PORT)
        {
            // are we tracking DNS?
            if let Some(dns_tx) = dns_tx {
                if let Err(e) = dns_tx.send(DnsTrackerMessage::NewEntry {
                    key: key.clone(),
                    data: packet.payload.clone(),
                    timestamp: packet.timestamp,
                    src_is_local,
                }) {
                    warn!("Error sending to DNS Tracker: {}", e);
                }
            }
        } else {
            // Noop - don't do anything special for other UDP connections -yet
            // TODO: handle QUIC connections - there are a lot of them
            debug!("Ignoring untracked UDP connection: {}", key);
        }
    }

    pub fn to_connection_measurements(
        &mut self,
        dns_cache: &HashMap<IpAddr, DnsTrackerEntry>,
        tcp_cache: &HashMap<ConnectionKey, ProcessTrackerEntry>,
        udp_cache: &HashMap<(IpAddr, u16), ProcessTrackerEntry>,
        probe_timeout: Option<Duration>,
    ) -> libconntrack_wasm::ConnectionMeasurements {
        // if there's an active probe round going, finish it/generate the report if it's been longer
        // then probe_timeout
        if let Some(probe_round) = self.probe_round.as_ref() {
            let now = Utc::now();
            let delta = now - self.start_tracking_time;
            let timeout = match probe_timeout {
                Some(timeout) => timeout,
                None => Duration::milliseconds(500),
            };
            if delta > timeout {
                self.generate_probe_report(probe_round.round_number as u32, None, false);
            }
        }
        let local_hostname = if let Some(entry) = dns_cache.get(&self.connection_key.local_ip) {
            Some(entry.hostname.clone())
        } else {
            None
        };
        let mut remote_hostname = self.remote_hostname.clone();
        let remote_hostname_dns_cache =
            if let Some(entry) = dns_cache.get(&self.connection_key.remote_ip) {
                Some(entry.hostname.clone())
            } else {
                None
            };
        // sanity check the two sources of remote_hostname
        match (&remote_hostname, &remote_hostname_dns_cache) {
            (None, None) | (Some(_), Some(_)) => (), // they're in sync
            (None, Some(_)) | (Some(_), None) => {
                debug!(
                    "DNS cache and stored hostname out of sync: stored {:?} cached {:?}",
                    &remote_hostname, &remote_hostname_dns_cache
                );
                // use which ever one we actually have
                if remote_hostname.is_none() {
                    // store it this way
                    self.remote_hostname = remote_hostname_dns_cache.clone();
                    remote_hostname = remote_hostname_dns_cache;
                }
            }
        }
        if remote_hostname.is_none() {
            // if we're STILL none, log it
            debug!(
                "UNABLE to find DNS lookup for {}",
                self.connection_key.remote_ip
            )
        }

        use IpProtocol::*;
        let ip_proto = IpProtocol::from_wire(self.connection_key.ip_proto);
        let inaddr_any = IpAddr::from([0, 0, 0, 0]);
        let associated_apps = match ip_proto {
            TCP => {
                if let Some(entry) = tcp_cache.get(&self.connection_key) {
                    entry.associated_apps.clone()
                } else {
                    HashMap::new()
                }
            }
            UDP => {
                /*
                 * UDP is a hard case to map, because depending on the application it may:
                 * 1) Bind INADDR_ANY (0.0.0.0) or the specific interface when it listens
                 * 2) May or may not connect(3) to the remote
                 *
                 * So we store the UDP data by (src_ip, port) pair and try both the interface
                 * address and the INADDR_ANY address types to find it
                 */
                let key = (
                    self.connection_key.local_ip,
                    self.connection_key.local_l4_port,
                );
                let key_in_addr_any = (inaddr_any.clone(), self.connection_key.local_l4_port);
                if let Some(entry) = udp_cache.get(&key) {
                    entry.associated_apps.clone()
                } else if let Some(entry) = udp_cache.get(&key_in_addr_any) {
                    entry.associated_apps.clone()
                } else {
                    HashMap::new()
                }
            }
            _ => HashMap::new(), // no info
        };
        libconntrack_wasm::ConnectionMeasurements {
            tx_byte_rate: self.tx_byte_rate.clone(),
            tx_packet_rate: self.tx_packet_rate.clone(),
            rx_byte_rate: self.rx_byte_rate.clone(),
            rx_packet_rate: self.rx_packet_rate.clone(),
            local_hostname,
            local_ip: self.connection_key.local_ip.clone(),
            local_l4_port: self.connection_key.local_l4_port,
            remote_hostname,
            remote_ip: self.connection_key.remote_ip.clone(),
            remote_l4_port: self.connection_key.remote_l4_port,
            ip_proto,
            probe_report_summary: self.probe_report_summary.clone(),
            user_annotation: self.user_annotation.clone(),
            user_agent: self.user_agent.clone(),
            associated_apps,
            start_tracking_time: self.start_tracking_time.clone(),
            last_packet_time: self.last_packet_time,
            close_has_started: self.close_has_started(),
            four_way_close_done: self.is_four_way_close_done_or_rst(),
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::env;
    use std::path::Path;
    use std::str::FromStr;

    use super::*;

    use crate::dns_tracker::DnsTracker;
    use crate::in_band_probe::test::test_tcp_packet_ports;
    use crate::owned_packet::OwnedParsedPacket;
    use crate::pcap::MockRawSocketProber;
    /**
     *  ConnectionKey should be a direction agnostic key for mapping packets
     * to a flow identifier.  but, the logic around "is the src of the packet"
     * from the "local process" is complicated - test all of the permutations
     */
    #[tokio::test]
    async fn src_is_local() {
        let local_ip = IpAddr::from_str("192.168.1.1").unwrap();
        let remote_ip = IpAddr::from_str("192.168.1.2").unwrap();
        let localhost_ip = IpAddr::from_str("127.0.0.1").unwrap();
        let mut local_addrs = HashSet::new();
        local_addrs.insert(local_ip);
        local_addrs.insert(localhost_ip); // both the local ip and the localhost ip are 'local'

        let local_pkt = test_tcp_packet_ports(local_ip, remote_ip, 21, 12345);
        let (l_key, src_is_local) = local_pkt.to_connection_key(&local_addrs).unwrap();
        assert!(src_is_local);

        let remote_pkt = test_tcp_packet_ports(remote_ip, local_ip, 12345, 21);
        let (r_key, src_is_local) = remote_pkt.to_connection_key(&local_addrs).unwrap();
        assert!(!src_is_local);

        assert_eq!(l_key, r_key);

        let local_localhost_pkt = test_tcp_packet_ports(localhost_ip, localhost_ip, 3030, 12345);
        let (ll_key, src_is_local) = local_localhost_pkt.to_connection_key(&local_addrs).unwrap();
        assert!(src_is_local);

        let remote_localhost_pkt = test_tcp_packet_ports(localhost_ip, localhost_ip, 12345, 3030);
        let (rl_key, src_is_local) = remote_localhost_pkt
            .to_connection_key(&local_addrs)
            .unwrap();
        assert!(!src_is_local);

        assert_eq!(ll_key, rl_key);
    }

    /**
     * Help tests find the testing directory - it's harder than it should be.
     *
     * If we invoke tests via 'cargo test', the base dir is netdebug/libconntrack
     * but if we start it from the vscode debug IDE, it's netdebug
     */

    pub fn test_dir(f: &str) -> String {
        use std::fs::metadata;
        if metadata(f).is_ok() {
            return f.to_string();
        }
        let p = Path::new("libconntrack").join(f);
        if metadata(&p).is_ok() {
            let p = p.into_os_string().to_str().unwrap().to_string();
            return p;
        } else {
            let cwd = env::current_dir().unwrap();
            panic!(
                "Couldn't find a test_dir for {} from cwd={}",
                f,
                cwd.display()
            );
        }
    }

    #[tokio::test]
    async fn connection_tracker_one_flow_outgoing() {
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let mock_prober = MockRawSocketProber::new();
        let mut local_addrs = HashSet::new();
        let localhost_ip = IpAddr::from_str("127.0.0.1").unwrap();
        local_addrs.insert(localhost_ip);
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs,
            mock_prober.tx.clone(),
            128,
        );

        let mut capture =
            // NOTE: this capture has no FINs so contracker will not remove it
            pcap::Capture::from_file(test_dir("tests/simple_websocket_cleartxt_out_probes.pcap"))
                .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            connection_tracker.add(owned_pkt);
        }
        assert_eq!(connection_tracker.connections.len(), 1);
        let connection = connection_tracker.connections.values().next().unwrap();
        // TODO; verify more about these pkts
        let _local_syn = connection.local_syn.as_ref().unwrap();
        let _remote_syn = connection.remote_syn.as_ref().unwrap();

        // verify we captured each of the outgoing probes
        let probe_round = connection.probe_round.as_ref().unwrap();
        assert_eq!(
            probe_round.outgoing_probe_timestamps.len(),
            16 as usize // NOTE: this should be the constant not PROBE_MAX_TTL because
                        // the ground truth is the packet capture, not the current const value
        );
        for probes in probe_round.outgoing_probe_timestamps.values() {
            assert_eq!(probes.len(), 1);
        }
    }

    const TEST_PROBE: [u8; 61] = [
        0x06, 0x25, 0x76, 0xbf, 0x7a, 0x4f, 0x06, 0x2e, 0x63, 0x19, 0xe4, 0xd3, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x2f, 0x00, 0x00, 0x40, 0x00, 0x07, 0x06, 0x70, 0xf6, 0xac, 0x1f, 0x02, 0x3d,
        0x4b, 0x0b, 0x09, 0x6c, 0x01, 0xbb, 0xa1, 0x0e, 0x13, 0x87, 0x86, 0x22, 0x00, 0x00, 0x00,
        0x00, 0x50, 0x00, 0x01, 0xe6, 0x74, 0xdb, 0x00, 0x00, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,
        0x2e,
    ];

    const TEST_REPLY: [u8; 70] = [
        0x06, 0x2e, 0x63, 0x19, 0xe4, 0xd3, 0x06, 0x25, 0x76, 0xbf, 0x7a, 0x4f, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0xf5, 0x01, 0x56, 0x0b, 0x34, 0x5d, 0x8d, 0x00,
        0xac, 0x1f, 0x02, 0x3d, 0x0b, 0x00, 0xb8, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00,
        0x2f, 0x00, 0x00, 0x40, 0x00, 0x01, 0x06, 0x76, 0xf6, 0xac, 0x1f, 0x02, 0x3d, 0x4b, 0x0b,
        0x09, 0x6c, 0x01, 0xbb, 0xa1, 0x0e, 0x13, 0x87, 0x86, 0x22,
    ];

    #[tokio::test]
    /**
     * Follow a TCP stream with outgoing probes and incoming replies and make sure
     * we can match them up to calculate RTTs, etc.
     */
    async fn connection_tracker_one_flow_out_and_in() {
        pretty_env_logger::init();
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let mock_prober = MockRawSocketProber::new();
        let mut local_addrs = HashSet::new();
        let local_ip = IpAddr::from_str("172.31.2.61").unwrap();
        local_addrs.insert(local_ip);
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs.clone(),
            mock_prober.tx.clone(),
            128,
        );

        let mut connection_key: Option<ConnectionKey> = None;
        let mut capture = pcap::Capture::from_file(test_dir(
            // NOTE: this capture has no FINs so contracker will not remove it
            "tests/simple_websocket_cleartext_remote_probe_replies.pcap",
        ))
        .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            let (key, _) = owned_pkt.to_connection_key(&local_addrs).unwrap();
            if let Some(prev_key) = connection_key {
                assert_eq!(prev_key, key);
            }
            connection_key = Some(key);
            connection_tracker.add(owned_pkt);
        }
        assert_eq!(connection_tracker.connections.len(), 1);
        // just grab the first connection .. the only connection
        let mut connection = connection_tracker
            .connections
            .values()
            .cloned()
            .into_iter()
            .next()
            .unwrap();
        // TODO; verify more about these pkts
        let _local_syn = connection.local_syn.as_ref().unwrap();
        let _remote_syn = connection.remote_syn.as_ref().unwrap();

        // verify we captured each of the outgoing probes
        let probe_round = connection.probe_round.as_ref().unwrap();
        assert_eq!(
            probe_round.outgoing_probe_timestamps.len(),
            16 as usize // this is hard coded by the pcap
        );
        // verify we captured each of the incoming replies - note that we only got six replies!
        assert_eq!(probe_round.incoming_reply_timestamps.len(), 6);
        for probes in probe_round.outgoing_probe_timestamps.values() {
            assert_eq!(probes.len(), 1);
        }

        // fake probe_report data; round=1, rtt=100ms
        let report = connection.generate_probe_report(1, Some(100.0), false);
        println!("Report:\n{}", report);
    }

    #[tokio::test]
    /**
     * Follow a TCP stream with outgoing probes and incoming replies and make sure
     * we can match them up to calculate RTTs, etc.
     */
    async fn connection_tracker_probe_and_reply() {
        let mock_prober = MockRawSocketProber::new();
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let mut local_addrs = HashSet::new();
        let local_ip = IpAddr::from_str("172.31.2.61").unwrap();
        local_addrs.insert(local_ip);
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs.clone(),
            mock_prober.tx.clone(),
            128,
        );

        let probe = OwnedParsedPacket::try_from_fake_time(TEST_PROBE.to_vec()).unwrap();

        let icmp_reply = OwnedParsedPacket::try_from_fake_time(TEST_REPLY.to_vec()).unwrap();

        connection_tracker.add(probe);
        connection_tracker.add(icmp_reply);

        assert_eq!(connection_tracker.connections.len(), 1);
        let connection = connection_tracker.connections.values().next().unwrap();
        let probe_round = connection.probe_round.as_ref().unwrap();
        assert_eq!(probe_round.outgoing_probe_timestamps.len(), 1);
        assert_eq!(probe_round.incoming_reply_timestamps.len(), 1);
        let probe_id = probe_round.outgoing_probe_timestamps.keys().next().unwrap();
        let reply_id = probe_round.incoming_reply_timestamps.keys().next().unwrap();
        // probe and reply match!
        assert_eq!(*probe_id, 7);
        assert_eq!(*reply_id, 7);
    }

    #[tokio::test]
    /**
     * Make sure a probe and the corresponding ICMPv4 reply map to the same
     * connection key and the src_is_local logic is correct for both
     *
     * TODO: add ICMPv6 version of this test
     */
    async fn icmp4_to_connection_key() {
        let mut local_addrs = HashSet::new();
        local_addrs.insert(IpAddr::from_str("172.31.2.61").unwrap());
        let probe = Box::new(OwnedParsedPacket::try_from_fake_time(TEST_PROBE.to_vec()).unwrap());

        let icmp_reply =
            Box::new(OwnedParsedPacket::try_from_fake_time(TEST_REPLY.to_vec()).unwrap());
        let (probe_key, src_is_local) = probe.to_connection_key(&local_addrs).unwrap();
        assert!(src_is_local);

        let (reply_key, src_is_local) = icmp_reply.to_connection_key(&local_addrs).unwrap();
        assert!(!src_is_local);

        assert_eq!(probe_key, reply_key);
    }

    #[test]
    fn options_cmp() {
        // it looks like you can compare inside options!?
        // some of the ack vs. seq comparisons assume this, so write a test just to make sure this
        // behavior doesn't change/go away
        //
        // https://doc.rust-lang.org/src/core/option.rs.html#560
        // apparently it's implemented by #[derive(Ord)] !?!
        let a = Some(10);
        let b = Some(20);
        let c: Option<i32> = None;

        assert!(a < b);
        assert!(b > a);
        assert!(a != c);
        assert!(a > c); // seems like None is less than everything!?
        assert!(b > c);
    }

    // as copied from the first few packets of 'aws-sjc-ist-one-stream.pcap'
    pub const TEST_1_LOCAL_SYN: [u8; 74] = [
        0xc8, 0x54, 0x4b, 0x43, 0xda, 0x3e, 0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x3c, 0xeb, 0x19, 0x40, 0x00, 0x40, 0x06, 0xbd, 0xf0, 0xc0, 0xa8, 0x01, 0x25,
        0x34, 0x35, 0x9b, 0xaf, 0x94, 0x62, 0x01, 0xbb, 0xd9, 0xe4, 0x72, 0xe2, 0x00, 0x00, 0x00,
        0x00, 0xa0, 0x02, 0xfa, 0xf0, 0x91, 0xe0, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02,
        0x08, 0x0a, 0x1a, 0xbf, 0x4f, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
    ];

    /**
     * Walk through a captured tcpdump of a single TCP stream, read all traffic
     * and make sure that we tear down the connection appropriately
     */
    #[tokio::test]
    async fn three_way_fin_teardown() {
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let mock_prober = MockRawSocketProber::new();
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.37").unwrap()]);
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs.clone(),
            mock_prober.tx.clone(),
            128,
        );

        let mut capture =
            pcap::Capture::from_file(test_dir("tests/simple_clear_text_with_fins.pcap")).unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        let mut conn_key = None;
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            conn_key = Some(owned_pkt.to_connection_key(&local_addrs).unwrap().0);
            connection_tracker.add(owned_pkt);
        }
        assert!(conn_key.is_some());
        assert_eq!(connection_tracker.connections.len(), 1);
        let conn = connection_tracker
            .connections
            .get_no_lru(&conn_key.unwrap())
            .unwrap();
        assert!(conn.is_four_way_close_done_or_rst());
        assert!(conn.close_has_started());
    }

    /**
     * Read a connection with full 3-way handshake, some data packets, and then a single
     * FIN. Make sure we `close_has_started()` is true
     */
    #[tokio::test]
    async fn connection_close_has_started_on_first_fin() {
        close_has_started_test_helper(
            &HashSet::from([IpAddr::from_str("192.168.1.238").unwrap()]),
            "tests/conn-syn-and-single-fin.pcap",
            false,
        );
        // now switch the direction of the connection to make sure it also
        // works for a FIN from the remote side.
        close_has_started_test_helper(
            &HashSet::from([IpAddr::from_str("34.121.150.27").unwrap()]),
            "tests/conn-syn-and-single-fin.pcap",
            false,
        );
    }

    /**
     * Read a connection with full 3-way handshake, some data packets, and then a single
     * RST. Make sure we `close_has_started()` is true
     */
    #[tokio::test]
    async fn connection_close_has_started_on_first_rst() {
        close_has_started_test_helper(
            &HashSet::from([IpAddr::from_str("192.168.1.238").unwrap()]),
            "tests/conn-syn-and-single-rst.pcap",
            true,
        );
        // now switch the direction of the connection to make sure it also
        // works for a FIN from the remote side.
        close_has_started_test_helper(
            &HashSet::from([IpAddr::from_str("34.121.150.27").unwrap()]),
            "tests/conn-syn-and-single-rst.pcap",
            true,
        );
    }

    fn close_has_started_test_helper(
        local_addrs: &HashSet<IpAddr>,
        pcap_file: &str,
        expected_four_way_close_done: bool,
    ) {
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let mock_prober = MockRawSocketProber::new();
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs.clone(),
            mock_prober.tx.clone(),
            128,
        );

        let mut capture = pcap::Capture::from_file(test_dir(pcap_file)).unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        let mut conn_key = None;
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            conn_key = Some(owned_pkt.to_connection_key(&local_addrs).unwrap().0);
            connection_tracker.add(owned_pkt);
        }
        assert!(conn_key.is_some());
        assert_eq!(connection_tracker.connections.len(), 1);
        let conn = connection_tracker
            .connections
            .get_no_lru(&conn_key.unwrap())
            .unwrap();
        assert_eq!(
            conn.is_four_way_close_done_or_rst(),
            expected_four_way_close_done
        );
        assert!(conn.close_has_started());
    }

    /**
     * Walk through a captured tcpdump of a single TCP stream, read all traffic
     * including the outgoing probes and incoming replies and make sure
     * that everything is read/processed correctly - including SACK from dup ACKs
     * to map replies back to probes
     */
    #[tokio::test]
    async fn full_probe_report() {
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let mock_prober = MockRawSocketProber::new();
        let local_addrs = HashSet::from([IpAddr::from_str("172.31.10.232").unwrap()]);
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs.clone(),
            mock_prober.tx.clone(),
            128,
        );

        let mut connection_key: Option<ConnectionKey> = None;
        let mut capture = pcap::Capture::from_file(test_dir(
            // NOTE: this capture has no FINs so contracker will not remove it
            "tests/aws-sfc-to-turkey-psh-dup-ack-sack-ones-stream.pcap",
        ))
        .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            let (key, _) = owned_pkt.to_connection_key(&local_addrs).unwrap();
            // make sure every packet in trace maps to same connection key
            if let Some(prev_key) = connection_key {
                assert_eq!(prev_key, key);
            }
            connection_key = Some(key);
            connection_tracker.add(owned_pkt);
        }
        let connection_key = connection_key.unwrap();
        assert_eq!(connection_tracker.connections.len(), 1);
        // do all of the connection work in a block so it will go away when we exit the block
        let connection = connection_tracker
            .connections
            .get_mut(&connection_key)
            .unwrap();
        let report = connection.generate_probe_report(1, Some(100.0), false);
        println!("{}", report); // useful for debugging

        // hand analysis via wireshark = which TTL's got which reply types?
        let no_replies: [u8; 6] = [1, 3, 5, 6, 9, 16];
        let router_icmp_replies: [u8; 10] = [2, 4, 7, 8, 10, 11, 12, 13, 14, 15];
        let nat_icmp_replies: [u8; 1] = [17];
        let endhost_replies: [u8; 15] =
            [18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];

        // sanity check to make sure we didn't miss something
        let mut all_probes = no_replies.clone().to_vec();
        all_probes.append(&mut router_icmp_replies.clone().to_vec());
        all_probes.append(&mut nat_icmp_replies.clone().to_vec());
        all_probes.append(&mut endhost_replies.clone().to_vec());

        // make sure all probes are accounted for
        for probe_id in 1..=PROBE_MAX_TTL {
            assert!(all_probes.iter().find(|x| **x == probe_id).is_some());
        }
        assert_eq!(report.probes.len(), all_probes.len());
        // now check that probes are correctly catergorized
        for ttl in no_replies {
            assert!(matches!(
                report.probes[&ttl],
                ProbeReportEntry::NoReply {
                    ttl: _,
                    out_timestamp_ms: _,
                    comment: _
                }
            ));
        }
        for ttl in router_icmp_replies {
            assert!(matches!(
                report.probes[&ttl],
                ProbeReportEntry::RouterReplyFound {
                    ttl: _,
                    out_timestamp_ms: _,
                    rtt_ms: _,
                    src_ip: _,
                    comment: _
                }
            ));
        }
        for ttl in nat_icmp_replies {
            assert!(matches!(
                report.probes[&ttl],
                ProbeReportEntry::NatReplyFound {
                    ttl: _,
                    out_timestamp_ms: _,
                    rtt_ms: _,
                    src_ip: _,
                    comment: _
                }
            ));
        }
        for ttl in endhost_replies {
            assert!(matches!(
                report.probes[&ttl],
                ProbeReportEntry::EndHostReplyFound {
                    ttl: _,
                    out_timestamp_ms: _,
                    rtt_ms: _,
                    comment: _
                }
            ));
        }
    }

    /**
     * Verify that we can extract the probe_id's from probes off of the wire correctly
     */
    #[tokio::test]
    async fn probe_id_off_by_one() {
        let ttl1_probe = [
            0x06, 0x50, 0x3e, 0xb8, 0xcf, 0xe9, 0x06, 0x95, 0x86, 0x20, 0x25, 0x41, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x29, 0x00, 0x00, 0x40, 0x00, 0x01, 0x06, 0x86, 0x69, 0xac, 0x1f,
            0x0a, 0xe8, 0x51, 0xd7, 0xea, 0x87, 0x01, 0xbb, 0x63, 0x7e, 0x0a, 0xf0, 0x8c, 0x3c,
            0x7d, 0x62, 0x09, 0xd2, 0x50, 0x18, 0x01, 0xfa, 0xee, 0xd0, 0x00, 0x00, 0x48,
        ];
        let probe1 = OwnedParsedPacket::try_from_fake_time(ttl1_probe.to_vec()).unwrap();

        let probe_id = Connection::is_probe_heuristic(true, &probe1).unwrap();
        assert_eq!(probe_id, 1);

        let ttl32_probe = [
            0x06, 0x50, 0x3e, 0xb8, 0xcf, 0xe9, 0x06, 0x95, 0x86, 0x20, 0x25, 0x41, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x48, 0x00, 0x00, 0x40, 0x00, 0x20, 0x06, 0x67, 0x4a, 0xac, 0x1f,
            0x0a, 0xe8, 0x51, 0xd7, 0xea, 0x87, 0x01, 0xbb, 0x63, 0x7e, 0x0a, 0xf0, 0x8c, 0x3c,
            0x7d, 0x62, 0x09, 0xd2, 0x50, 0x18, 0x01, 0xfa, 0xf7, 0xad, 0x00, 0x00, 0x48, 0x54,
            0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
            0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x3a,
            0x20, 0x74,
        ];
        let probe32 = OwnedParsedPacket::try_from_fake_time(ttl32_probe.to_vec()).unwrap();

        let probe_id = Connection::is_probe_heuristic(true, &probe32).unwrap();
        assert_eq!(probe_id, 32);
    }

    /***
     * If we get a RST from the remote side from a connection we're not tracking, then make sure
     * to not track that connection _based_ on the RST.
     */
    #[tokio::test]
    async fn dont_track_remote_rsts() {
        let remote_rst = [
            0x7c, 0x8a, 0xe1, 0x5a, 0xac, 0xc2, 0xf8, 0x0d, 0xac, 0xd4, 0x91, 0x89, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x28, 0xdb, 0x89, 0x00, 0x00, 0x40, 0x06, 0x1b, 0x45, 0xc0, 0xa8,
            0x01, 0x4a, 0xc0, 0xa8, 0x01, 0x67, 0x02, 0x77, 0xcd, 0x35, 0xde, 0xde, 0x42, 0xa5,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x04, 0x00, 0x00, 0x3a, 0xae, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let remote_rst = OwnedParsedPacket::try_from_fake_time(remote_rst.to_vec()).unwrap();
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.103").unwrap()]);
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let raw_sock = MockRawSocketProber::new();
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs,
            raw_sock.tx.clone(),
            128,
        );
        connection_tracker.add(remote_rst);
        assert_eq!(connection_tracker.connections.len(), 0);
    }

    /**
     * Make sure on new connection, we properly query the DNS tracker to store the hostname.
     * This is a 'higher' level test as it doesn't use (m)any of the internals of ConnectionTracker or
     * DnsTracker - just their public messaging interfaces
     */

    #[tokio::test]
    async fn test_dns_tracker_new_connection_lookup() {
        let mut dns_tracker = DnsTracker::new(20);
        let local_syn = OwnedParsedPacket::try_from_fake_time(TEST_1_LOCAL_SYN.to_vec()).unwrap();
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.37").unwrap()]);
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let mock_prober = MockRawSocketProber::new();
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs,
            mock_prober.tx.clone(),
            128,
        );
        let remote_ip = IpAddr::from_str("52.53.155.175").unwrap();
        let test_hostname = "test-hostname.example.com".to_string();
        // populate the dns_tracker with the DNS info
        dns_tracker.reverse_map.insert(
            remote_ip.clone(),
            DnsTrackerEntry {
                hostname: test_hostname.clone(),
                created: Utc::now(),
                from_ptr_record: false,
                rtt: None,
                ttl: None,
            },
        );
        // launch the dns_tracker in a task
        let (dns_tx, dns_rx) = tokio::sync::mpsc::unbounded_channel();
        connection_tracker.set_dns_tracker(dns_tx);
        tokio::spawn(async move {
            dns_tracker.do_async_loop(dns_rx).await;
        });
        let conn_track_tx = connection_tracker.get_tx();
        // launch the connection tracker in a task
        tokio::spawn(async move {
            connection_tracker.rx_loop().await;
        });
        // this call should trigger a call to the dns_tracker and a reply back to the connection tracker
        conn_track_tx
            .try_send(PerfMsgCheck::new(ConnectionTrackerMsg::Pkt(local_syn)))
            .unwrap();
        // this will get us a list of the active connections
        // there is some possibility for a race condition here as the message to the DnsTracker and back takes
        // some time; sleep for now but... sigh... 100 ms is more than enough
        tokio::time::sleep(Duration::milliseconds(100).to_std().unwrap()).await;
        let (connections_tx, mut connections_rx) = tokio::sync::mpsc::unbounded_channel();
        conn_track_tx
            .try_send(PerfMsgCheck::new(ConnectionTrackerMsg::GetConnections {
                tx: connections_tx,
            }))
            .unwrap();
        // make sure there's one and make sure remote_host is populated as expected
        let mut connections = connections_rx.recv().await.unwrap();
        assert_eq!(connections.len(), 1);
        let first_connection = connections.pop().unwrap();
        assert_eq!(first_connection.remote_hostname, Some(test_hostname));
    }

    #[test]
    fn connection_seq_wrap() {
        let builder = etherparse::PacketBuilder::ethernet2(
            [1, 2, 3, 4, 5, 6], //source mac
            [7, 8, 9, 10, 11, 12],
        ) //destionation mac
        .ipv4(
            [192, 168, 1, 1], //source ip
            [192, 168, 1, 2], //desitionation ip
            20,
        )
        // create the TCP header with MAX_INT as the seq to force a wrap
        .tcp_header(TcpHeader::new(1000, 2000, u32::MAX, 1000));
        //payload of the tcp packet, will push the ACK to wrap!
        let payload = [1, 2, 3, 4, 5, 6, 7, 8];

        // get some memory to store the result
        let mut pkt_buf = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut pkt_buf, &payload).unwrap();
        let wrapping_pkt = OwnedParsedPacket::try_from_fake_time(pkt_buf.to_vec()).unwrap();
        // make sure we set it up right
        match &wrapping_pkt.transport {
            Some(TransportHeader::Tcp(tcph)) => assert_eq!(tcph.sequence_number, u32::MAX),
            _ => panic!("Should be TCP"),
        }
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.1").unwrap()]);
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let mock_prober = MockRawSocketProber::new();
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs,
            mock_prober.tx.clone(),
            128,
        );
        connection_tracker.add(wrapping_pkt);
        assert_eq!(connection_tracker.connections.len(), 1);
        let conn = connection_tracker.connections.values().next().unwrap();
        assert_eq!(conn.local_seq.unwrap(), Wrapping(payload.len() as u32 - 1));
    }

    #[tokio::test]
    async fn test_time_wait_eviction() {
        let max_connections_per_tracker = 32;
        let mock_prober = MockRawSocketProber::new();
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.238").unwrap()]);
        let (evict_tx, mut evict_rx) = mpsc::channel(10);
        let mut connection_tracker = ConnectionTracker::new(
            Some(evict_tx),
            max_connections_per_tracker,
            local_addrs.clone(),
            mock_prober.tx.clone(),
            128,
        );

        let mut capture =
            pcap::Capture::from_file(test_dir("tests/normal-conn-syn-and-fin.pcap")).unwrap();
        let mut packets = Vec::new();
        while let Ok(pkt) = capture.next_packet() {
            packets.push(OwnedParsedPacket::try_from(pkt).unwrap());
        }
        // The trace has 11 packets total.
        // packets[7] is the first FIN
        // packets[9] is the 2nd FIN
        assert_eq!(packets.len(), 11);
        assert!(packets[7].clone().transport.unwrap().tcp().unwrap().fin);
        assert!(packets[9].clone().transport.unwrap().tcp().unwrap().fin);

        // Read the first couple of packets. Ensure connection is created.
        for i in 0..5 {
            connection_tracker.add(packets[i].clone());
        }
        assert_eq!(connection_tracker.connections.len(), 1);

        // pause() halt updating of the tokio Instant timer.
        tokio::time::pause();
        // But if there's no more work todo, the tokio runtime will
        // auto-advance any pending sleeps / timers, etc. So this sleep
        // call will not take any real wall-time
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_WAIT_MS + 10)).await;

        // Create a packet from a different connection.
        let mut pkt_unrelated_conn_raw: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2(
            [1, 2, 3, 4, 5, 6], //source mac
            [7, 8, 9, 10, 11, 12],
        ) //destionation mac
        .ipv4(
            [192, 168, 1, 238], //source ip
            [192, 168, 1, 2],   //desitionation ip
            20,
        )
        .tcp(12345, 80, 42, 1024)
        .write(&mut pkt_unrelated_conn_raw, &[])
        .unwrap();
        let pkt_unrelated_conn =
            OwnedParsedPacket::try_from_fake_time(pkt_unrelated_conn_raw).unwrap();
        let unrelated_conn_key = pkt_unrelated_conn
            .clone()
            .to_connection_key(&local_addrs)
            .unwrap()
            .0;

        // and put the packet into connection tracker. The previous connection should
        // be evicted
        connection_tracker.add(pkt_unrelated_conn);
        assert_eq!(connection_tracker.connections.len(), 1);
        let evicted = evict_rx.try_recv().unwrap();
        assert_eq!(evicted.local_ip, "192.168.1.238");
        assert_eq!(evicted.remote_ip, "34.121.150.27");
        assert_eq!(evicted.remote_port, 443);

        // make sure we have the "unrelated" connection in the tracker
        assert!(connection_tracker
            .connections
            .get_no_lru(&unrelated_conn_key)
            .is_some());

        tokio::time::resume();
    }

    /// Tests that when a connection gets evicted we only send it to the storage server
    /// if it has probe information in it.
    #[tokio::test]
    async fn test_send_only_conns_with_probe_to_storage() {
        let max_connections_per_tracker = 32;
        let mock_prober = MockRawSocketProber::new();
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.238").unwrap()]);
        let (evict_tx, mut evict_rx) = mpsc::channel(10);
        let mut connection_tracker = ConnectionTracker::new(
            Some(evict_tx),
            max_connections_per_tracker,
            local_addrs.clone(),
            mock_prober.tx.clone(),
            128,
        );

        // Read the first 3 packets from the trace. I.e., just the handshake but no data.
        // ==> No probes are sent.
        let mut capture =
            pcap::Capture::from_file(test_dir("tests/normal-conn-syn-and-fin.pcap")).unwrap();
        let mut num_pks = 0;
        while let Ok(pkt) = capture.next_packet() {
            if num_pks >= 3 {
                // just the 3-way handshake
                break;
            }
            connection_tracker.add(OwnedParsedPacket::try_from(pkt).unwrap());
            num_pks += 1;
        }

        assert_eq!(connection_tracker.connections.len(), 1);

        // pause() halt updating of the tokio Instant timer.
        tokio::time::pause();
        // this sleep won't actually sleep but just advande the Instant timer
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_WAIT_MS + 10)).await;

        // Create a packet from a different connection.
        let mut pkt_unrelated_conn_raw: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 238], [192, 168, 1, 2], 20)
            .tcp(12345, 80, 42, 1024)
            .write(&mut pkt_unrelated_conn_raw, &[])
            .unwrap();
        let pkt_unrelated_conn =
            OwnedParsedPacket::try_from_fake_time(pkt_unrelated_conn_raw).unwrap();
        let unrelated_conn_key = pkt_unrelated_conn
            .clone()
            .to_connection_key(&local_addrs)
            .unwrap()
            .0;

        // and put the packet into connection tracker. The previous connection should
        // be evicted, but since the previous connection doesn't have any probes, it
        // should not have been sent to the storage handler
        connection_tracker.add(pkt_unrelated_conn);
        assert_eq!(connection_tracker.connections.len(), 1);
        match evict_rx.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => (),
            x => panic!("Expected to get an empty from evict_rx, got {:?}", x),
        }

        // make sure we have the "unrelated" connection in the tracker
        assert!(connection_tracker
            .connections
            .get_no_lru(&unrelated_conn_key)
            .is_some());

        tokio::time::resume();
    }
}
