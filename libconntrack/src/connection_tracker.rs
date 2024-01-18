use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use chrono::{DateTime, Utc};
use common_wasm::{
    analysis_messages::AnalysisInsights,
    evicting_hash_map::EvictingHashMap,
    timeseries_stats::{ExportedStatRegistry, StatHandle, StatHandleDuration, StatType, Units},
    ProbeRoundReport,
};

use itertools::Itertools;
use libconntrack_wasm::{
    bidir_bandwidth_to_chartjs, traffic_stats::BidirectionalStats, AggregateStatEntry,
    AggregateStatKind, BidirBandwidthHistory, ConnectionKey, ConnectionMeasurements,
};
#[cfg(not(test))]
use log::{debug, warn};

use mac_address::MacAddress;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedSender};

#[cfg(test)]
use std::{println as debug, println as warn}; // Workaround to use prinltn! for logs.

use crate::{
    analyze::analyze,
    connection::{Connection, ConnectionUpdateListener, MAX_BURST_RATE_TIME_WINDOW_MILLIS},
    dns_tracker::DnsTrackerMessage,
    neighbor_cache::{LookupMacByIpResult, NeighborCache, NeighborCacheSender},
    owned_packet::{ConnectionKeyError, OwnedParsedPacket},
    prober::ProbeMessage,
    prober_helper::ProberHelper,
    process_tracker::{ProcessTrackerEntry, ProcessTrackerMessage, ProcessTrackerSender},
    send_or_log_sync,
    topology_client::{TopologyServerMessage, TopologyServerSender},
    utils::{self, packet_is_tcp_rst, PerfMsgCheck},
};

/// When evicting stale/old connection entries: evict at most this many
/// connections at once
const MAX_ENTRIES_TO_EVICT: usize = 10;
/// If a connection has not seen any packets in this many milliseconds, the connection is
/// evicted. This is done regardless of the connection is open or closed.
const TIME_WAIT_MS: i64 = 60_000;

pub type ConnectionTrackerSender = Sender<PerfMsgCheck<ConnectionTrackerMsg>>;
pub type ConnectionTrackerReceiver = Receiver<PerfMsgCheck<ConnectionTrackerMsg>>;

/// Certain query operations (e.g., dump flows, traffic stats, etc.) require us to update/
/// move forward the time. This enum specifies what time source should be used.
/// This will only make a material difference if (a) we are reading a previously captured
/// trace or (b) we are doing a live capture but the network has been idle for a while.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum TimeMode {
    /// Use the Wallclock time, i.e., Utc::now()
    Wallclock,
    /// Use the time as derived from received packet timestamps.
    PacketTime,
}

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
        should_probe_again: bool,
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
    GetConnectionMeasurements {
        tx: mpsc::UnboundedSender<Vec<ConnectionMeasurements>>,
        time_mode: TimeMode,
    },
    SetConnectionRemoteHostnameDns {
        keys: Vec<ConnectionKey>,
        remote_hostname: Option<String>, // will be None if lookup fails
    },
    SetConnectionApplication {
        key: ConnectionKey,
        application: Option<ProcessTrackerEntry>, // will be None if lookup fails, which we need for stats
    },
    GetTrafficCounters {
        tx: mpsc::UnboundedSender<BidirBandwidthHistory>,
        time_mode: TimeMode,
    },
    GetDnsTrafficCounters {
        tx: mpsc::Sender<Vec<AggregateStatEntry>>,
        time_mode: TimeMode,
    },
    AddConnectionUpdateListener {
        /// a description of what the listener is doing; must be unique across listeners
        desc: String,
        /// a tx queue to send updates to
        tx: ConnectionUpdateListener,
        /// a Connection identifier to listen to
        key: ConnectionKey,
    },
    DelConnectionUpdateListener {
        /// the desc string passed when adding it
        desc: String,
        /// the connection key to delete the update listener
        key: ConnectionKey,
    },
    /// Ask the neighbor cache if they've seen this IP
    /// If not, try to look it up
    LookupMacByIp {
        /// A human-readable unique across the program identifier for who is doing the lookup
        identifier: String,
        /// the IpAddr we're trying to resolve
        ip: IpAddr,
        /// a tx queue to send the reply
        tx: NeighborCacheSender,
    },
}

/**
 * Send a copy of the ConnectionMeasurements() struct associated with this connection
 * to the remote topology server for storage.
 */
// TODO: I'll move this down where the rest if the ConnectionTracker impl is in another
// diff. But doing it this way keeps the diff more readable
impl<'a> ConnectionTracker<'a> {
    fn send_connection_storage_msg(&mut self, c: &mut Connection, now: DateTime<Utc>) {
        if let Some(tx) = self.topology_client.as_ref() {
            let measurement = Box::new(c.to_connection_measurements(now, None));
            if !measurement.probe_report_summary.raw_reports.is_empty() {
                // only send the connection info if we have at least one successful probe round
                debug!(
                    "Sending connection measurements to topology server for {}",
                    c.connection_key()
                );
                send_or_log_sync!(
                    tx,
                    "send_connection_storage_msg()",
                    TopologyServerMessage::StoreConnectionMeasurements {
                        connection_measurements: measurement
                    }
                );
            } else {
                debug!(
                    "Not sending connection measurement to storage server: {} measurements {}",
                    measurement.probe_report_summary.raw_reports.len(),
                    c.connection_key()
                );
            }
        }
        if let Some(tx) = self.all_evicted_connections_listener.as_ref() {
            let measurement = Box::new(c.to_connection_measurements(now, None));
            if let Err(e) = tx.try_send(measurement) {
                warn!(
                    "Failed to send data to all_evicted_connections :: err {}",
                    e
                );
            }
        }
    }

    fn lookup_ip_by_mac(
        &mut self,
        identifier: String,
        target_ip: IpAddr,
        tx: Sender<(IpAddr, MacAddress)>,
    ) {
        if self
            .neighbor_cache
            .lookup_mac_by_ip_pending(identifier, &target_ip, tx)
            == LookupMacByIpResult::NotFound
        {
            // our lookup failed; let's source a Arp or Ndp lookup to the IP to force it
            // first, figure out a source IP and mac; just look through our local_addrs
            // and use the first one that's the same IP version as the target
            let local_ip = self
                .local_addrs
                .iter()
                .find(|a| a.is_ipv4() == target_ip.is_ipv4());
            if let Some(local_ip) = local_ip {
                /*
                 * Even if the external network is completely hosed, we should be able to see Arp/Ndp
                 * messages outgoing from our selves and thus have learned our own mac for the local_ip
                 *
                 * if this is a problem, just lookup manually with MacAddress:lookup_mac_by_ip(), but that's
                 * more complicated.
                 */
                if let Some(local_mac) = self.neighbor_cache.lookup_mac_by_ip(local_ip) {
                    if let Err(e) = self.prober_helper.tx().try_send(PerfMsgCheck::new(
                        ProbeMessage::SendIpLookup {
                            local_mac: local_mac.bytes(),
                            local_ip: *local_ip,
                            target_ip,
                        },
                    )) {
                        warn!(
                            "ConnectionTracker tried to send to the prober but got: {}",
                            e
                        );
                    }
                } else {
                    warn!(
                    "Tried to send a LookupIp message to the prober but couldn't find a mac for {}!?", local_ip
                );
                }
            } else {
                warn!(
                    "Tried to send a LookupIp message to the prober but couldn't find a local_ip!?"
                );
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionStatHandles {
    pub probe_rounds_sent: StatHandle,
    pub seq_out_of_window: StatHandle,
    pub ack_out_of_window: StatHandle,
    pub multiple_syns: StatHandle,
    pub multiple_fins_different_seqno: StatHandle,
    pub invalid_sack: StatHandle,
    pub sack_not_a_probe: StatHandle,
    pub outgoing_low_ttl_not_a_probe: StatHandle,
    pub probe_rounds_dst_ratelimit: StatHandle,
    pub weird_probes_found: StatHandle,
    pub weird_replies_found: StatHandle,
    pub packet_loss_event: StatHandle,
}

impl ConnectionStatHandles {
    pub fn new(registry: &ExportedStatRegistry) -> Self {
        let add_stat = |name: &str| registry.add_stat(name, Units::None, [StatType::COUNT]);
        ConnectionStatHandles {
            probe_rounds_sent: add_stat("probe_rounds_sent"),
            seq_out_of_window: add_stat("seq_out_of_window"),
            ack_out_of_window: add_stat("ack_out_of_window"),
            multiple_syns: add_stat("multiple_syns"),
            multiple_fins_different_seqno: add_stat("multiple_fins_different_seqno"),
            invalid_sack: add_stat("invalid_sack"),
            sack_not_a_probe: add_stat("sack_not_a_probe"),
            outgoing_low_ttl_not_a_probe: add_stat("outgoing_low_ttl_not_a_probe"),
            probe_rounds_dst_ratelimit: add_stat("probe_round_dst_ratelimit"),
            weird_probes_found: add_stat("weird_probes_found"),
            weird_replies_found: add_stat("weird_replies_found"),
            packet_loss_event: add_stat("packet_loss_event"),
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
    last_packet_time: DateTime<Utc>,
    max_connections: usize,
    local_addrs: HashSet<IpAddr>,
    prober_helper: ProberHelper,
    topology_client: Option<TopologyServerSender>,
    // If set, all evicted connections are send here. Mostly used for debugging/testing
    all_evicted_connections_listener: Option<Sender<Box<ConnectionMeasurements>>>,
    dns_tx: Option<tokio::sync::mpsc::UnboundedSender<DnsTrackerMessage>>,
    process_tx: Option<ProcessTrackerSender>,
    tx: ConnectionTrackerSender, // so we can tell others how to send msgs to us
    rx: ConnectionTrackerReceiver, // to read messages sent to us
    // used to track traffic grouped by, e.g., DNS destination
    aggregate_traffic_stats: HashMap<AggregateStatKind, BidirectionalStats>,
    stat_handles: ConnectionStatHandles,
    // TODO: merge the following StatHandles into the `stat_handle` field.
    /// Trackes number of successfully parsed packets. I.e., packets from
    /// which we could extract a ConnectionKey
    sucessfully_parsed_packets: StatHandle,
    /// Tracks packet that we ignored (couldn't extract connection key). Either didn't have
    /// L3 and/or L4 header or unhandled ICMP.
    no_conn_key_packets: StatHandle,
    /// Track that packets with ethertype of Arp
    arp_packets: StatHandle,
    /// Tracks ICMP packets (of type we handle) from which we failed to extract the inner
    /// packet's ConnectionKey
    icmp_extract_failed_packet: StatHandle,
    /// Number of parsed packets for which neither the src nor the dst IP was local. This
    /// could either by multicast traffic (Apple's mDNS/bonjour say hello). Or we got the wrong
    /// IPs from the interface or the IP of the interface changed.
    not_local_packets: StatHandle,
    /// The time difference between the packet timestamp (from libpcap) to the current wall
    /// time.
    pcap_to_wall_delay: StatHandleDuration,
    /// Tracks the time between enqueing and dequeing messages to the connection tracker
    dequeue_delay_stats: StatHandleDuration,
    /// Number of connections evicted due to us reaching the the max_connection limit
    evictions_due_to_size_limit: StatHandle,
    /// For each connection key, A (potentially empty) map of places to update if this connection gets an update
    /// The key is some sort of human read-able descriptor of what the caller is doing, e.g.,
    /// "Default Gw Ping Tracker" => tx
    /// NOTE: we put this here instead of in each connection so that the caller doesn't have to race
    /// with the packet handling code and risk trying to install a listener for a connection that doesn't
    /// exist yet.
    pub(crate) update_listeners: HashMap<ConnectionKey, HashMap<String, ConnectionUpdateListener>>,
    /// Keep a cache of Ipv4 Arp and (TODO) IPv6 ICMP neighbor solicition/advertisment messages
    pub(crate) neighbor_cache: NeighborCache<'a>,
}
impl<'a> ConnectionTracker<'a> {
    pub fn new(
        topology_client: Option<TopologyServerSender>,
        max_connections_per_tracker: usize,
        local_addrs: HashSet<IpAddr>,
        prober_tx: Sender<PerfMsgCheck<ProbeMessage>>,
        max_queue_size: usize,
        stats: ExportedStatRegistry,
        // do we ignore the rate limiter?
        // TODO: refactor this new() as a builder...
        unlimited_probes: bool,
    ) -> ConnectionTracker<'a> {
        let (tx, rx) = tokio::sync::mpsc::channel(max_queue_size);
        ConnectionTracker {
            connections: EvictingHashMap::new(
                // we are not actually using the EvictingHashmap's eviction. We manually handle evictions in
                // `Self::evict_connections()`. Why? We need the most recent time based on pkt timestamps
                // and we can't easily make that accessible from the callback (not without Arc<Mutex<DateTime<....>>>).
                // Also, we need to handle evictions based on TIME_WAIT anyways.
                // Why use `EvictingHashMap` and not `LinkedHashMap`? Cleaner API, IMHO. `LinkedHashMap::get()` does
                // not update the LRU, which can IMHO lead to subtle bugs.
                max_connections_per_tracker + 1,
                move |_k, mut _v| {
                    log::error!("The eviction callback got triggered. This should not happen. We expect to evict connections sooner");
                },
            ),
            last_packet_time: DateTime::<Utc>::UNIX_EPOCH,
            max_connections: max_connections_per_tracker,
            local_addrs,
            prober_helper: ProberHelper::new(prober_tx, unlimited_probes),
            topology_client,
            all_evicted_connections_listener: None,
            dns_tx: None,
            process_tx: None,
            tx,
            rx,
            // we always have at least the top-level ConnectionTracker traffic counters
            aggregate_traffic_stats: HashMap::from([(
                AggregateStatKind::ConnectionTracker,
                BidirectionalStats::new(std::time::Duration::from_millis(
                    MAX_BURST_RATE_TIME_WINDOW_MILLIS,
                )),
            )]),
            stat_handles: ConnectionStatHandles::new(&stats),
            sucessfully_parsed_packets: stats.add_stat(
                "succesfully_parsed",
                Units::Packets,
                [StatType::COUNT],
            ),
            no_conn_key_packets: stats.add_stat("no_conn_key", Units::Packets, [StatType::COUNT]),
            arp_packets: stats.add_stat("arp_packets", Units::Packets, [StatType::COUNT]),
            icmp_extract_failed_packet: stats.add_stat(
                "icmp_extract_failed",
                Units::Packets,
                [StatType::COUNT],
            ),
            not_local_packets: stats.add_stat("not_local", Units::Packets, [StatType::COUNT]),
            pcap_to_wall_delay: stats.add_duration_stat(
                "pcap_to_walltime_delay",
                Units::Microseconds,
                [StatType::AVG, StatType::MAX],
            ),
            dequeue_delay_stats: stats.add_duration_stat(
                "dequeue_delay",
                Units::Microseconds,
                [StatType::MAX, StatType::AVG, StatType::COUNT],
            ),
            evictions_due_to_size_limit: stats.add_stat(
                "evictions_due_to_size_limit",
                Units::None,
                [StatType::COUNT],
            ),
            update_listeners: HashMap::new(),
            // just re-use/abuse the max_connections_per_tracker for our max neighbors to remember, seems ok
            neighbor_cache: NeighborCache::new(max_connections_per_tracker),
        }
    }

    pub fn set_topology_client(&mut self, topology_client: Option<TopologyServerSender>) {
        self.topology_client = topology_client;
    }

    pub fn set_dns_tracker(&mut self, dns_tx: mpsc::UnboundedSender<DnsTrackerMessage>) {
        self.dns_tx = Some(dns_tx);
    }

    pub fn set_process_tracker(&mut self, process_tx: ProcessTrackerSender) {
        self.process_tx = Some(process_tx);
    }

    pub fn set_all_evicted_connections_listener(
        &mut self,
        all_evicted_connections: Sender<Box<ConnectionMeasurements>>,
    ) {
        self.all_evicted_connections_listener = Some(all_evicted_connections);
    }

    pub async fn rx_loop(&mut self) {
        while let Some(msg) = self.rx.recv().await {
            let msg = msg.perf_check_get_with_stats(
                "ConnectionTracker::rx_loop",
                &mut self.dequeue_delay_stats,
            );
            self.handle_one_msg(msg);
        }
        warn!("ConnectionTracker exiting rx_loop()");
    }

    /**
     * Used for testing; just one-shot process all of the queued messages and then return;
     * subtly different from rx_loop() in that it uses try_recv() which will never block
     */
    #[cfg(test)]
    pub async fn flush_rx_loop(&mut self) {
        // read only the queued messages, don't block
        while let Ok(msg) = self.rx.try_recv() {
            let msg = msg.perf_check_get_with_stats(
                "ConnectionTracker::rx_loop",
                &mut self.dequeue_delay_stats,
            );
            self.handle_one_msg(msg);
        }
        // return when done
    }

    pub fn handle_one_msg(&mut self, msg: ConnectionTrackerMsg) {
        use ConnectionTrackerMsg::*;
        match msg {
            Pkt(pkt) => self.add(pkt),
            ProbeReport {
                key,
                should_probe_again: clear_state,
                tx,
                probe_round,
                application_rtt,
            } => {
                self.generate_report(&key, probe_round, application_rtt, clear_state, tx);
            }
            SetUserAnnotation { annotation, key } => {
                self.set_user_annotation(&key, annotation);
            }
            GetInsights { key, tx } => self.get_insights(&key, tx),
            SetUserAgent { user_agent, key } => {
                self.set_user_agent(&key, user_agent);
            }
            GetConnectionKeys { tx } => {
                // so simple, no need for a dedicated function
                let keys = self.connections.keys().cloned().collect();
                if let Err(e) = tx.try_send(keys) {
                    warn!(
                        "Error sendings keys back to caller in GetConnectionKeys(): {}",
                        e
                    );
                }
            }
            GetConnectionMeasurements { tx, time_mode } => {
                self.handle_get_connection_measurements(tx, time_mode);
            }
            SetConnectionRemoteHostnameDns {
                keys,
                remote_hostname,
            } => {
                self.set_connection_remote_hostname_dns(&keys, remote_hostname);
            }
            GetTrafficCounters { tx, time_mode } => {
                self.get_conntrack_traffic_counters(tx, time_mode)
            }
            SetConnectionApplication { key, application } => {
                self.set_connection_application(key, application)
            }
            GetDnsTrafficCounters { tx, time_mode } => {
                self.get_aggregate_traffic_counters(
                    |kind| matches!(kind, AggregateStatKind::DnsDstDomain { .. }),
                    tx,
                    time_mode,
                );
            }
            AddConnectionUpdateListener { tx, key, desc } => {
                self.add_connection_update_listener(tx, key, desc)
            }
            DelConnectionUpdateListener { key, desc } => {
                self.del_connection_update_listener(desc, key)
            }
            LookupMacByIp { ip, tx, identifier } => self.lookup_ip_by_mac(identifier, ip, tx),
        }
    }

    pub fn add(&mut self, packet: Box<OwnedParsedPacket>) {
        let mut needs_dns_and_process_lookup = false;
        self.last_packet_time = packet.timestamp;
        // We do eviction handling before processing the new packet. All-in-all it doesn't really matter a
        // lot. However, it will likely make a difference when processing filtered traces in tests. Let's
        // assume we have a connection with a > TIME_WAIT gap in it. On a live capture, changes are very
        // high that some other packets arrived during this gap and that the connection gets evicted (and/or
        // that the first packet after the gap is from a different connection).
        //  But in a test, the first after-gap packet might be from the same connection and then if we evict
        // after handling the packet we would not evict that connection. Leading to test behavior that's
        // different from what one would normally see.
        self.evict_connections(packet.timestamp);
        match packet.to_connection_key(&self.local_addrs) {
            Ok((key, src_is_local)) => {
                self.sucessfully_parsed_packets.bump();
                let connection = match self.connections.get_mut(&key) {
                    Some(connection) => connection,
                    None => {
                        if packet_is_tcp_rst(&packet) {
                            debug!("Not creating a new connection entry on RST");
                            return;
                        }
                        // else create the state and look it up again
                        self.new_connection(key.clone(), packet.timestamp);
                        needs_dns_and_process_lookup = true;
                        self.connections.get_mut(&key).unwrap()
                    }
                };
                // NOTE: adding a listener to a connection is expensive as we copy every packet; use sparingly!
                if let Some(listeners_map) = self.update_listeners.get(&key) {
                    for (desc, tx) in listeners_map {
                        if let Err(e) = tx.try_send((packet.clone(), key.clone())) {
                            warn!("Update ConnectionListener {} failed: {}", desc, e);
                        }
                    }
                }
                let pkt_timestamp = packet.timestamp; // copy before we move packet into connection.update()
                let pkt_len = packet.len as u64; // copy before we move packet into connection.update()
                let conn_update_return = connection.update(
                    packet,
                    &mut self.prober_helper,
                    &key,
                    src_is_local,
                    &self.dns_tx,
                    self.pcap_to_wall_delay.clone(),
                );
                for group in connection.aggregate_groups() {
                    if let Some(traffic_stats) = self.aggregate_traffic_stats.get_mut(group) {
                        traffic_stats.add_packet_with_time(src_is_local, pkt_len, pkt_timestamp);
                        traffic_stats.add_new_lost_bytes(
                            !src_is_local, // The side that lost the bytes, is the opposite of the one sending ACKs
                            conn_update_return.new_lost_bytes,
                            pkt_timestamp,
                        );
                        // NOTE, tracking RTT for per-application, per-dns-domain, and conn-tracker aggregat_traffic_stats doesn't
                        // make sense (as there's no expectation that these RTTs should be similar). So we are not adding
                        // them.

                        // TODO: add aggregate_traffic_stats per destination IP
                    } else {
                        warn!(
                            "Group counters out of sync between connection {} and tracker: missing {:?}", 
                            connection.connection_key(),
                            group
                        );
                    }
                }
                if needs_dns_and_process_lookup {
                    // only new connections that we don't immediately tear down need DNS lookups
                    if let Some(dns_tx) = self.dns_tx.as_mut() {
                        // ask the DNS tracker to async message us the remote DNS name
                        if let Err(e) = dns_tx.send(DnsTrackerMessage::Lookup {
                            ip: key.remote_ip,
                            key: key.clone(),
                            tx: self.tx.clone(),
                        }) {
                            warn!("Failed to send a Lookup message to the DNS Tracker: {}", e);
                        }
                    }
                    if let Some(process_tx) = self.process_tx.as_mut() {
                        if let Err(e) = process_tx.try_send(PerfMsgCheck::new(
                            ProcessTrackerMessage::LookupOne {
                                key: key.clone(),
                                tx: self.tx.clone(),
                            },
                        )) {
                            warn!(
                                "Failed to send a Lookup message to the Process Tracker: {}",
                                e
                            );
                        }
                    }
                }
            }
            Err(ConnectionKeyError::IcmpInnerPacketError) => self.icmp_extract_failed_packet.bump(),
            Err(ConnectionKeyError::IgnoredPacket) => self.no_conn_key_packets.bump(),
            Err(ConnectionKeyError::NoLocalAddr) => self.not_local_packets.bump(),
            Err(ConnectionKeyError::Arp) => {
                self.arp_packets.bump();
                if let Err(e) = self.neighbor_cache.process_arp_packet(packet) {
                    warn!("Ignoring failed to parse Arp packet: {}", e);
                }
            }
        }
        // if we got here, the packet didn't have enough info to be called a 'connection'
        // just return and move on for now
    }

    /// Evict connections if
    /// a) We have more than `self.max_connections`
    /// or b) check the connections that haven't seen any updates the longest, and evict all that
    /// have been in-active for more than `TIME_WAIT_SECONDS`. Evict at most `MAX_ENTRIES_TO_EVICT` in
    /// this case
    fn evict_connections(&mut self, now: DateTime<Utc>) {
        // Size based eviction
        while self.connections.len() > self.max_connections {
            let (key, mut conn) = self.connections.pop_front().unwrap();
            self.evictions_due_to_size_limit.bump();
            debug!(
                "Evicting connection {} from connection_tracker due to size limit",
                key
            );
            self.send_connection_storage_msg(&mut conn, now);
        }
        // TIME_WAIT evictions
        let mut eviction_cnt = 0;
        while let Some((_key, conn)) = self.connections.front() {
            let elapsed_ms = (now - conn.last_packet_time()).num_milliseconds();
            if eviction_cnt < MAX_ENTRIES_TO_EVICT && elapsed_ms > TIME_WAIT_MS {
                let (key, mut conn) = self.connections.pop_front().unwrap();
                debug!(
                    "Evicting connection {} from connection_tracker due to idle",
                    key
                );
                self.send_connection_storage_msg(&mut conn, now);
                eviction_cnt += 1;
            } else {
                break;
            }
        }
    }

    fn new_connection(&mut self, key: ConnectionKey, pkt_timestamp: DateTime<Utc>) {
        debug!("Tracking new connection: {}", &key);
        let connection = Connection::new(key.clone(), pkt_timestamp, self.stat_handles.clone());

        self.connections.insert(key, connection);
    }

    /**
     * Generate a ProbeReport from the given connection/key
     *
     * If called with a bad key, caller will get back None from rx.recv() if we exit without
     */

    fn generate_report(
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
            if let Err(e) = tx.try_send(report) {
                warn!("Error sending back report: {}", e);
            }
        } else {
            warn!("Found no connection matching key {}", key);
            // sending nothing will close the connection and thus return None to the report receiver
        }
    }

    fn set_user_annotation(&mut self, key: &ConnectionKey, annotation: String) {
        if let Some(connection) = self.connections.get_mut(key) {
            connection.user_annotation = Some(annotation);
        } else {
            warn!(
                "Tried to set_user_annotation for unknown connection {} -- {}",
                key, annotation
            );
        }
    }

    fn set_user_agent(&mut self, key: &ConnectionKey, user_agent: String) {
        if let Some(connection) = self.connections.get_mut(key) {
            connection.user_agent = Some(user_agent);
        } else {
            warn!(
                "Tried to set_user_agent for unknown connection {} -- {}",
                key, user_agent
            );
        }
    }

    fn get_insights(
        &mut self,
        key: &ConnectionKey,
        tx: tokio::sync::mpsc::Sender<Vec<AnalysisInsights>>,
    ) {
        if let Some(connection) = self.connections.get_mut(key) {
            let insights = analyze(connection.probe_report_summary());
            if let Err(e) = tx.try_send(insights) {
                warn!("get_insights: {} :: {}", key, e);
            }
        } else {
            warn!("Tried to get_insights for unknown connection {}", key,);
        }
    }

    fn handle_get_connection_measurements(
        &mut self,
        tx: tokio::sync::mpsc::UnboundedSender<Vec<ConnectionMeasurements>>,
        time_mode: TimeMode,
    ) {
        let now = self.get_current_timestamp(time_mode);
        let connections = self
            .connections
            .iter_mut()
            .map(|(_key, c)| c.to_connection_measurements(now, None))
            .collect::<Vec<ConnectionMeasurements>>();
        if let Err(e) = tx.send(connections) {
            warn!(
                "Tried to send the connections back to caller, but failed: {}",
                e
            );
        }
    }

    pub fn set_connection_remote_hostname_dns(
        &mut self,
        keys: &Vec<ConnectionKey>,
        remote_hostname: Option<String>,
    ) {
        if let Some(remote_hostname) = remote_hostname {
            for key in keys {
                if let Some(connection) = self.connections.get_mut(key) {
                    connection.remote_hostname = Some(remote_hostname.clone());
                    match utils::dns_to_cannonical_domain(&remote_hostname) {
                        Ok(domain) => {
                            // add this group and make sure the connection tracker is tracking it
                            let group = AggregateStatKind::DnsDstDomain(domain);
                            connection.aggregate_groups.insert(group.clone());
                            self.aggregate_traffic_stats.entry(group).or_insert(
                                BidirectionalStats::new(std::time::Duration::from_millis(
                                    MAX_BURST_RATE_TIME_WINDOW_MILLIS,
                                )),
                            );
                        }
                        Err(e) => warn!("Unparsible DNS name: {} :: {}", &remote_hostname, e),
                    }
                }
            }
        } else {
            // This can happen if the connection is torn down faster than we can get the DNS
            // name back from the DNS tracker; make it debug for now
            debug!(
                "Tried to lookup unknown key(s) {:?} in the conneciton map trying to set DNS name {:?}",
                keys, remote_hostname
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

    fn get_conntrack_traffic_counters(
        &self,
        tx: UnboundedSender<BidirBandwidthHistory>,
        time_mode: TimeMode,
    ) {
        let mut traffic_stats = self
            .aggregate_traffic_stats
            .get(&AggregateStatKind::ConnectionTracker)
            .unwrap() // unwrap is ok b/c we should always have this counter
            .clone();
        // force send and recv counters to be up to date with now and time sync'd
        traffic_stats.advance_time(self.get_current_timestamp(time_mode));
        if let Err(e) =
            tx.send(traffic_stats.as_bidir_bandwidth_history(self.get_current_timestamp(time_mode)))
        {
            warn!(
                "Tried to send traffic_counters back to caller but got {}",
                e
            );
        }
    }

    fn set_connection_application(
        &mut self,
        key: ConnectionKey,
        application: Option<ProcessTrackerEntry>,
    ) {
        if let Some(application) = application {
            if let Some(connection) = self.connections.get_mut(&key) {
                connection.associated_apps = Some(application.associated_apps);
            } else {
                warn!(
                    "Tried to update application id for non-existent connection: {}",
                    key
                );
            }
        } else {
            // TODO: update a stats counter to count the number of non-identified connections
        }
    }

    /**
     * Walk the traffic counters list and return just the counters matching the
     * match_rule and their associated ConnectionMeasurements
     *
     * Used for generating the 'group by XXX' UI pages
     *
     * FYI: it is inefficient but likely still correct to call this for the
     * AggregateStatsKind::ConnectionTracker stats, but call get_conntrack_traffic_counters() for that.
     */

    fn get_aggregate_traffic_counters(
        &mut self,
        match_rule: impl Fn(&AggregateStatKind) -> bool,
        tx: Sender<Vec<AggregateStatEntry>>,
        time_mode: TimeMode,
    ) {
        let mut entries: HashMap<AggregateStatKind, AggregateStatEntry> = HashMap::new();
        let now = self.get_current_timestamp(time_mode);
        for (_key, connection) in self.connections.iter_mut() {
            // we clone aggregate_groups here. If we don't we borrow `connection` immutable, and
            // we can't call `to_connection_measurements()` later (since that requires a mut borrow)
            for kind in connection.aggregate_groups.clone() {
                if !match_rule(&kind) {
                    continue;
                }
                let m = connection.to_connection_measurements(now, None);
                // if we've already seen this kind before
                if let Some(entry) = entries.get_mut(&kind) {
                    // just add this connection to the list
                    entry.connections.push(m);
                } else {
                    // else look up the traffic counters and add this connection to the new list
                    if let Some(traffic_stats) = self.aggregate_traffic_stats.get_mut(&kind) {
                        entries.insert(
                            kind.clone(),
                            AggregateStatEntry {
                                kind: kind.clone(),
                                bandwidth: bidir_bandwidth_to_chartjs(
                                    traffic_stats.as_bidir_bandwidth_history(now),
                                ),
                                summary: traffic_stats.as_bidir_stats_summary(now),
                                connections: vec![m],
                            },
                        );
                    }
                }
            }
        }
        if let Err(e) = tx.try_send(entries.into_values().collect_vec()) {
            warn!(
                "Failed to return the aggregate counters to their caller!?: {}",
                e
            );
        }
    }

    pub fn get_current_timestamp(&self, time_mode: TimeMode) -> DateTime<Utc> {
        match time_mode {
            TimeMode::Wallclock => Utc::now(),
            TimeMode::PacketTime => self.last_packet_time,
        }
    }

    /**
     * Subscribe this tx to all packet updates for a given ConnectionKey.  The ConnectionKey
     * doesn't have to exist yet which avoids a nasty race condition.
     *
     * the 'desc' is a human readable id of who is listening, e.g., "Ping Updater" and needs to be unique
     */
    fn add_connection_update_listener(
        &mut self,
        tx: ConnectionUpdateListener,
        key: ConnectionKey,
        desc: String,
    ) {
        self.update_listeners
            .entry(key)
            .or_default()
            .insert(desc, tx);
    }

    /**
     * Unsubscribe from an `ConnectionTracker::add_connection_update_listener` call.  Pass the same
     * desc and ConnectionKey as when adding
     */
    fn del_connection_update_listener(&mut self, desc: String, key: ConnectionKey) {
        if let Some(listeners_map) = self.update_listeners.get_mut(&key) {
            if listeners_map.remove(&desc).is_none() {
                warn!(
                    "Tried to add a ConnectionUpdateListener ({}) for {} but desc not found",
                    desc, key
                );
            }
        } else {
            warn!(
                "Tried to add a ConnectionUpdateListener ({}) for {} but key not found",
                desc, key
            );
        }
    }
}

#[cfg(test)]
pub mod test {
    use core::panic;
    use std::str::FromStr;
    use std::time::Instant;

    use approx::assert_relative_eq;
    use chrono::Duration;
    use common::test_utils::test_dir;
    use common_wasm::{ProbeReportEntry, PROBE_MAX_TTL};
    use etherparse::{TcpHeader, TransportHeader};
    use libconntrack_wasm::DnsTrackerEntry;
    use tokio::sync::mpsc::channel;
    use tokio::sync::mpsc::error::TryRecvError;

    use super::*;

    use crate::dns_tracker::DnsTracker;
    use crate::owned_packet::OwnedParsedPacket;
    use crate::pcap::MockRawSocketProber;

    pub fn mk_mock_connection_tracker<'a>(local_addrs: HashSet<IpAddr>) -> ConnectionTracker<'a> {
        let mock_prober = MockRawSocketProber::new();
        mk_mock_connection_tracker_with_prober(local_addrs, mock_prober)
    }
    fn mk_mock_connection_tracker_with_prober<'a>(
        local_addrs: HashSet<IpAddr>,
        mock_prober: MockRawSocketProber,
    ) -> ConnectionTracker<'a> {
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs,
            mock_prober.tx.clone(),
            128,
            ExportedStatRegistry::new("test.conn_tracker", Instant::now()),
            true,
        )
    }

    #[tokio::test]
    async fn connection_tracker_one_flow_outgoing() {
        let mut local_addrs = HashSet::new();
        let localhost_ip = IpAddr::from_str("127.0.0.1").unwrap();
        local_addrs.insert(localhost_ip);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs);
        let mut capture =
            // NOTE: this capture has no FINs so contracker will not remove it
            pcap::Capture::from_file(test_dir("libconntack", "tests/simple_websocket_cleartxt_out_probes.pcap"))
                .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from_pcap(pkt).unwrap();
            connection_tracker.add(owned_pkt);
        }
        assert_eq!(connection_tracker.connections.len(), 1);
        let connection = connection_tracker.connections.values().next().unwrap();
        // TODO; verify more about these pkts
        let _local_syn = connection
            .local_tcp_state()
            .as_ref()
            .unwrap()
            .syn_pkt()
            .as_ref()
            .unwrap();
        let _remote_syn = connection
            .remote_tcp_state()
            .as_ref()
            .unwrap()
            .syn_pkt()
            .as_ref()
            .unwrap();

        // verify we captured each of the outgoing probes
        let probe_round = connection.probe_round().as_ref().unwrap();
        assert_eq!(
            probe_round.outgoing_probe_timestamps.len(),
            16 // NOTE: this should be the constant not PROBE_MAX_TTL because
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
        let local_addrs = HashSet::from([IpAddr::from_str("172.31.2.61").unwrap()]);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs.clone());

        let mut connection_key: Option<ConnectionKey> = None;
        let mut capture = pcap::Capture::from_file(test_dir(
            "libconntrack",
            // NOTE: this capture has no FINs so contracker will not remove it
            "tests/simple_websocket_cleartext_remote_probe_replies.pcap",
        ))
        .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from_pcap(pkt).unwrap();
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
            .next()
            .cloned()
            .unwrap();
        // TODO; verify more about these pkts
        let _local_syn = connection
            .local_tcp_state()
            .as_ref()
            .unwrap()
            .syn_pkt()
            .as_ref()
            .unwrap();
        let _remote_syn = connection
            .remote_tcp_state()
            .as_ref()
            .unwrap()
            .syn_pkt()
            .as_ref()
            .unwrap();

        // verify we captured each of the outgoing probes
        let probe_round = connection.probe_round().as_ref().unwrap();
        assert_eq!(
            probe_round.outgoing_probe_timestamps.len(),
            16 // this is hard coded by the pcap
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
        let local_addrs = HashSet::from([IpAddr::from_str("172.31.2.61").unwrap()]);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs);

        let probe = OwnedParsedPacket::try_from_fake_time(TEST_PROBE.to_vec()).unwrap();

        let icmp_reply = OwnedParsedPacket::try_from_fake_time(TEST_REPLY.to_vec()).unwrap();

        connection_tracker.add(probe);
        connection_tracker.add(icmp_reply);

        assert_eq!(connection_tracker.connections.len(), 1);
        let connection = connection_tracker.connections.values().next().unwrap();
        let probe_round = connection.probe_round().as_ref().unwrap();
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
     * Subscribe to the update_listener for a connection and make sure we get the updates
     */
    async fn connection_tracker_update_listener() {
        let local_addrs = HashSet::from([IpAddr::from_str("172.31.2.61").unwrap()]);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs.clone());

        let probe = OwnedParsedPacket::try_from_fake_time(TEST_PROBE.to_vec()).unwrap();

        let icmp_reply = OwnedParsedPacket::try_from_fake_time(TEST_REPLY.to_vec()).unwrap();

        let (tx, mut rx) = channel(10);
        let (key, _src_is_local) = probe.to_connection_key(&local_addrs).unwrap();
        let desc = "test listener".to_string();
        assert_eq!(connection_tracker.update_listeners.len(), 0);
        connection_tracker.add_connection_update_listener(tx, key.clone(), desc.clone());
        assert_eq!(connection_tracker.update_listeners.len(), 1);

        connection_tracker.add(probe.clone());
        connection_tracker.add(icmp_reply.clone());

        // get the first packet update
        let (test_probe, test_key) = rx.recv().await.unwrap();
        assert_eq!(test_probe, probe);
        assert_eq!(test_key, key);
        // get the second packet update
        let (test_reply, test_key) = rx.recv().await.unwrap();
        assert_eq!(test_reply, icmp_reply);
        assert_eq!(test_key, key);

        // now remove
        connection_tracker.del_connection_update_listener(desc, key.clone());
        assert_eq!(
            connection_tracker.update_listeners.get(&key).unwrap().len(),
            0
        );
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
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.37").unwrap()]);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs.clone());

        let mut capture = pcap::Capture::from_file(test_dir(
            "libconntrack",
            "tests/simple_clear_text_with_fins.pcap",
        ))
        .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        let mut conn_key = None;
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from_pcap(pkt).unwrap();
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
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs.clone());

        let mut capture = pcap::Capture::from_file(test_dir("libconntrack", pcap_file)).unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        let mut conn_key = None;
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from_pcap(pkt).unwrap();
            conn_key = Some(owned_pkt.to_connection_key(local_addrs).unwrap().0);
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
        let local_addrs = HashSet::from([IpAddr::from_str("172.31.10.232").unwrap()]);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs.clone());

        let mut connection_key: Option<ConnectionKey> = None;
        let mut capture = pcap::Capture::from_file(test_dir(
            "libconntrack",
            // NOTE: this capture has no FINs so contracker will not remove it
            "tests/aws-sfc-to-turkey-psh-dup-ack-sack-ones-stream.pcap",
        ))
        .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from_pcap(pkt).unwrap();
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
            assert!(all_probes.iter().any(|x| *x == probe_id));
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

    const REMOTE_RST: [u8; 60] = [
        0x7c, 0x8a, 0xe1, 0x5a, 0xac, 0xc2, 0xf8, 0x0d, 0xac, 0xd4, 0x91, 0x89, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x28, 0xdb, 0x89, 0x00, 0x00, 0x40, 0x06, 0x1b, 0x45, 0xc0, 0xa8, 0x01, 0x4a,
        0xc0, 0xa8, 0x01, 0x67, 0x02, 0x77, 0xcd, 0x35, 0xde, 0xde, 0x42, 0xa5, 0x00, 0x00, 0x00,
        0x00, 0x50, 0x04, 0x00, 0x00, 0x3a, 0xae, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /***
     * If we get a RST from the remote side from a connection we're not tracking, then make sure
     * to not track that connection _based_ on the RST.
     */
    #[tokio::test]
    async fn dont_track_remote_rsts() {
        let remote_rst = OwnedParsedPacket::try_from_fake_time(REMOTE_RST.to_vec()).unwrap();
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.103").unwrap()]);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs);
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
        let mut dns_tracker = DnsTracker::new(
            20,
            ExportedStatRegistry::new("testing_dns", std::time::Instant::now()),
        );
        let local_syn = OwnedParsedPacket::try_from_fake_time(TEST_1_LOCAL_SYN.to_vec()).unwrap();
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.37").unwrap()]);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs);
        let remote_ip = IpAddr::from_str("52.53.155.175").unwrap();
        let test_hostname = "test-hostname.example.com".to_string();
        // populate the dns_tracker with the DNS info
        dns_tracker.reverse_map.insert(
            remote_ip,
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
            .try_send(PerfMsgCheck::new(
                ConnectionTrackerMsg::GetConnectionMeasurements {
                    tx: connections_tx,
                    time_mode: TimeMode::PacketTime,
                },
            ))
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
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs);
        connection_tracker.add(wrapping_pkt);
        assert_eq!(connection_tracker.connections.len(), 1);
        let conn = connection_tracker.connections.values().next().unwrap();
        assert_eq!(
            conn.local_tcp_state()
                .as_ref()
                .unwrap()
                .sent_seq_no()
                .unwrap(),
            (1 << 32) + payload.len() as u64 - 1
        );
    }

    #[test]
    fn test_time_wait_eviction() {
        let mut mock_prober = MockRawSocketProber::new();
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.238").unwrap()]);
        let (evict_tx, mut evict_rx) = mpsc::channel(10);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs.clone());
        connection_tracker.set_topology_client(Some(evict_tx));

        let mut capture = pcap::Capture::from_file(test_dir(
            "libconntrack",
            "tests/normal-conn-syn-and-fin.pcap",
        ))
        .unwrap();
        let mut packets = Vec::new();
        while let Ok(pkt) = capture.next_packet() {
            packets.push(OwnedParsedPacket::try_from_pcap(pkt).unwrap());
        }
        // The trace has 11 packets total.
        // packets[7] is the first FIN
        // packets[9] is the 2nd FIN
        assert_eq!(packets.len(), 11);
        assert!(packets[7].clone().transport.unwrap().tcp().unwrap().fin);
        assert!(packets[9].clone().transport.unwrap().tcp().unwrap().fin);

        // Read the first couple of packets. Ensure connection is created.
        let mut last_packet_time = DateTime::<Utc>::UNIX_EPOCH;
        for pkt in packets.iter().take(5) {
            last_packet_time = pkt.timestamp;
            connection_tracker.add(pkt.clone());
        }
        assert_eq!(connection_tracker.connections.len(), 1);

        // feed the mock'd probes into the connection tracker so it thinks
        // it has a valid ProbeReport
        mock_prober.redirect_into_connection_tracker(&mut connection_tracker);

        // Create a packet from a different connection.
        let mut pkt_unrelated_conn_raw: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2(
            [1, 2, 3, 4, 5, 6], //source mac
            [7, 8, 9, 10, 11, 12],
        ) //destination mac
        .ipv4(
            [192, 168, 1, 238], //source ip
            [192, 168, 1, 2],   //destination ip
            20,
        )
        .tcp(12345, 80, 42, 1024)
        .write(&mut pkt_unrelated_conn_raw, &[])
        .unwrap();
        let pkt_unrelated_conn = OwnedParsedPacket::try_from_timestamp(
            pkt_unrelated_conn_raw,
            last_packet_time + Duration::milliseconds(TIME_WAIT_MS + 10),
        )
        .unwrap();
        let unrelated_conn_key = pkt_unrelated_conn
            .clone()
            .to_connection_key(&local_addrs)
            .unwrap()
            .0;

        // and put the packet into connection tracker. The previous connection should
        // be evicted
        connection_tracker.add(pkt_unrelated_conn);
        assert_eq!(connection_tracker.connections.len(), 1);
        let evicted = evict_rx.try_recv().unwrap().skip_perf_check();
        use TopologyServerMessage::*;
        match evicted {
            StoreConnectionMeasurements {
                connection_measurements: m,
            } => {
                assert_eq!(m.key.local_ip, IpAddr::from_str("192.168.1.238").unwrap());
                assert_eq!(m.key.remote_ip, IpAddr::from_str("34.121.150.27").unwrap());
                assert_eq!(m.key.remote_l4_port, 443);
            }
            _wut => panic!("Expected StoreConnectionMeasurements, got {:?}", _wut),
        }

        // make sure we have the "unrelated" connection in the tracker
        assert!(connection_tracker
            .connections
            .get_no_lru(&unrelated_conn_key)
            .is_some());
    }

    /// Tests that when a connection gets evicted we only send it to the storage server
    /// if it has probe information in it.
    #[test]
    fn test_send_only_conns_with_probe_to_storage() {
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.238").unwrap()]);
        let (evict_tx, mut evict_rx) = mpsc::channel(10);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs.clone());
        connection_tracker.set_topology_client(Some(evict_tx));

        // Read the first 3 packets from the trace. I.e., just the handshake but no data.
        // ==> No probes are sent.
        let mut capture = pcap::Capture::from_file(test_dir(
            "libconntrack",
            "tests/normal-conn-syn-and-fin.pcap",
        ))
        .unwrap();
        let mut num_pks = 0;
        let mut last_pkt_timne = DateTime::<Utc>::UNIX_EPOCH;
        while let Ok(pkt) = capture.next_packet() {
            if num_pks >= 3 {
                // just the 3-way handshake
                break;
            }
            let parsed_pkt = OwnedParsedPacket::try_from_pcap(pkt).unwrap();
            last_pkt_timne = parsed_pkt.timestamp;
            connection_tracker.add(parsed_pkt);
            num_pks += 1;
        }

        assert_eq!(connection_tracker.connections.len(), 1);

        let timestamp = last_pkt_timne + Duration::milliseconds(TIME_WAIT_MS + 10);

        // Create a packet from a different connection.
        let mut pkt_unrelated_conn_raw: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 238], [192, 168, 1, 2], 20)
            .tcp(12345, 80, 42, 1024)
            .write(&mut pkt_unrelated_conn_raw, &[])
            .unwrap();
        let pkt_unrelated_conn =
            OwnedParsedPacket::try_from_timestamp(pkt_unrelated_conn_raw, timestamp).unwrap();
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
    }

    /***
     * Verify that we send a lookup messasge to the ProcessTracker on new connections (not a rst)
     * and that we set them properly when we get the reply.
     */
    #[tokio::test]
    async fn connection_tracker_process_lookup() {
        let (process_tx, mut process_rx) = channel(128);
        let remote_rst = OwnedParsedPacket::try_from_fake_time(REMOTE_RST.to_vec()).unwrap();
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.103").unwrap()]);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs);
        connection_tracker.set_process_tracker(process_tx);
        connection_tracker.add(remote_rst);
        assert_eq!(connection_tracker.connections.len(), 0);
        // make sure we didn't get a message from the connection tracker
        // don't use assert_eq!() as it forces everything down a complex chain to
        // derive(PartialEq, Eq)
        match process_rx.try_recv() {
            Err(TryRecvError::Empty) => (),
            _e => panic!("Got a process message where none was expected: {:?}", _e),
        }
        // now try a real packet and make sure we get a message
        let local_syn = OwnedParsedPacket::try_from_fake_time(TEST_1_LOCAL_SYN.to_vec()).unwrap();
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.37").unwrap()]);
        connection_tracker.local_addrs = local_addrs; // new packet has a different local ip; hack it in
        connection_tracker.add(local_syn);
        // spawn the connection tracker to the background so it can start processing msgs
        let conntrack_tx = connection_tracker.get_tx();
        tokio::spawn(async move {
            connection_tracker.rx_loop().await;
        });
        let msg = process_rx.try_recv().unwrap().skip_perf_check();
        let my_app = "MyApp".to_string();
        let my_pid = 12345;
        let test_process_entry = ProcessTrackerEntry {
            associated_apps: HashMap::from([(my_pid, Some(my_app.clone()))]),
        };
        use ProcessTrackerMessage::*;
        match msg {
            LookupOne { key, tx } => {
                tx.send(PerfMsgCheck::new(
                    ConnectionTrackerMsg::SetConnectionApplication {
                        key,
                        application: Some(test_process_entry),
                    },
                ))
                .await
                .unwrap();
            }
            _wtf => panic!("Got unknown message: {:?}", _wtf),
        }
        // now verify that the ConnectionTracker correctly updated the state
        // use the tx/rx interface instead of the internals to ensure no race condition
        // because this message will be behind the SetApplication message
        let (conns_tx, mut conns_rx) = tokio::sync::mpsc::unbounded_channel();
        conntrack_tx
            .send(PerfMsgCheck::new(
                ConnectionTrackerMsg::GetConnectionMeasurements {
                    tx: conns_tx,
                    time_mode: TimeMode::PacketTime,
                },
            ))
            .await
            .unwrap();
        let mut connections = conns_rx.recv().await.unwrap();
        assert_eq!(connections.len(), 1);
        let connection = connections.pop().unwrap();
        let associated_apps = connection.associated_apps.unwrap();
        assert_eq!(associated_apps.len(), 1);
        let (test_pid, test_app) = associated_apps.iter().next().unwrap();
        assert_eq!(*test_pid, my_pid);
        assert_eq!(*test_app, Some(my_app));
    }

    #[test]
    fn test_tcp_rtt() {
        fn handle_dns_msg(
            dns_rx: &mut mpsc::UnboundedReceiver<DnsTrackerMessage>,
            conn_tracker: &mut ConnectionTracker,
        ) {
            if let Ok(DnsTrackerMessage::Lookup { key, .. }) = dns_rx.try_recv() {
                conn_tracker.handle_one_msg(ConnectionTrackerMsg::SetConnectionRemoteHostnameDns {
                    keys: vec![key],
                    remote_hostname: Some("somewhere.example.com".to_string()),
                });
            }
        }

        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.238").unwrap()]);
        let mut conn_track = mk_mock_connection_tracker(local_addrs);
        let mut capture = pcap::Capture::from_file(test_dir(
            "libconntrack",
            "tests/normal-conn-syn-and-fin.pcap",
        ))
        .unwrap();
        let (dns_tx, mut dns_rx) = mpsc::unbounded_channel();
        conn_track.set_dns_tracker(dns_tx);
        while let Ok(pkt) = capture.next_packet() {
            let parsed_pkt = OwnedParsedPacket::try_from_pcap(pkt).unwrap();
            conn_track.handle_one_msg(ConnectionTrackerMsg::Pkt(parsed_pkt));
            handle_dns_msg(&mut dns_rx, &mut conn_track);
        }
        // Query conn_tracker for connection measurements
        let (tx, mut rx) = mpsc::unbounded_channel();
        conn_track.handle_one_msg(ConnectionTrackerMsg::GetConnectionMeasurements {
            tx,
            time_mode: TimeMode::PacketTime,
        });
        let measurements = rx
            .try_recv()
            .clone()
            .expect("No response when getting connection measurements");
        let m = measurements
            .first()
            .expect("Expected one connection measurement");
        let tx_rtt_stat = m
            .tx_stats
            .rtt_stats_ms
            .clone()
            .expect("tx_rtt_stat should be Some(...)");
        // see connection::test::test_rtt_samples() for why we check these values
        assert_eq!(tx_rtt_stat.num_samples(), 4);
        assert_relative_eq!(tx_rtt_stat.mean(), 55.81775, epsilon = 1e-5);

        // see connection::test::test_rtt_samples() for why we check these values
        let rx_rtt_stat = m
            .rx_stats
            .rtt_stats_ms
            .clone()
            .expect("rx_rtt_stat should be Some(...)");
        assert_eq!(rx_rtt_stat.num_samples(), 2);
        assert_relative_eq!(rx_rtt_stat.mean(), 0.3605, epsilon = 1e-5);

        // Get DNS aggregate
        let (tx, mut rx) = mpsc::channel(1);
        conn_track.handle_one_msg(ConnectionTrackerMsg::GetDnsTrafficCounters {
            tx,
            time_mode: TimeMode::PacketTime,
        });
        let agg_stat_entry = rx
            .try_recv()
            .expect("No response for GetDnsTrafficCounters");
        assert_eq!(agg_stat_entry.len(), 1);
        assert_eq!(
            agg_stat_entry[0].kind,
            AggregateStatKind::DnsDstDomain("example.com".to_owned())
        );
        // Make sure that we actually tracked something for this domain
        assert!(agg_stat_entry[0].summary.tx.bytes > 0);
        assert!(agg_stat_entry[0].summary.rx.bytes > 0);
        // ... but we are not tracking RTT for dns domains
        assert_eq!(agg_stat_entry[0].summary.tx.rtt_stats_ms, None);
        assert_eq!(agg_stat_entry[0].summary.rx.rtt_stats_ms, None);
    }

    #[test]
    fn test_tcp_with_tx_loss_trace() {
        fn handle_dns_msg(
            dns_rx: &mut mpsc::UnboundedReceiver<DnsTrackerMessage>,
            conn_tracker: &mut ConnectionTracker,
        ) {
            if let Ok(DnsTrackerMessage::Lookup { key, .. }) = dns_rx.try_recv() {
                conn_tracker.handle_one_msg(ConnectionTrackerMsg::SetConnectionRemoteHostnameDns {
                    keys: vec![key],
                    remote_hostname: Some("topology.netdebug.com".to_string()),
                });
            }
        }

        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.238").unwrap()]);
        let mut conn_track = mk_mock_connection_tracker(local_addrs);
        let mut capture =
            pcap::Capture::from_file(test_dir("libconntrack", "tests/tcp-with-tx-loss.pcap"))
                .unwrap();
        let (all_conn_meas_tx, mut all_conn_meas_rx) = mpsc::channel(100);
        conn_track.set_all_evicted_connections_listener(all_conn_meas_tx);
        let (dns_tx, mut dns_rx) = mpsc::unbounded_channel();
        conn_track.set_dns_tracker(dns_tx);

        let mut tx_bytes = 0;
        let mut rx_bytes = 0;
        let mut tx_loss = 0;
        let mut rx_loss = 0;
        let mut tx_loss_per_conn = Vec::new();
        let mut connection_cnt = 0;
        let mut handle_conn_measurement = |measurement: &ConnectionMeasurements| {
            tx_bytes += measurement.tx_stats.bytes;
            rx_bytes += measurement.rx_stats.bytes;
            tx_loss += measurement.tx_stats.lost_bytes.unwrap_or_default();
            tx_loss_per_conn.push(measurement.tx_stats.lost_bytes.unwrap_or_default());
            rx_loss += measurement.rx_stats.lost_bytes.unwrap_or_default();
            connection_cnt += 1;
        };
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from_pcap(pkt).unwrap();
            conn_track.handle_one_msg(ConnectionTrackerMsg::Pkt(owned_pkt));
            handle_dns_msg(&mut dns_rx, &mut conn_track);
            if let Ok(measurement) = all_conn_meas_rx.try_recv() {
                handle_conn_measurement(&measurement);
            }
        }
        // Query conn_tracker for all remaining connections -- there should be one
        let (tx, mut rx) = mpsc::unbounded_channel();
        conn_track.handle_one_msg(ConnectionTrackerMsg::GetConnectionMeasurements {
            tx,
            time_mode: TimeMode::PacketTime,
        });
        if let Ok(measurements) = rx.try_recv() {
            for m in &measurements {
                handle_conn_measurement(m);
            }
        }

        // NOTE: this trace contains 3 or 4 connections depending on how you count. It has 3
        // distinct 5-tuples and 3 handshakes. But there is a ~2hr gap in the trace which causes
        // one of the connections to be evicted due to idle and then recreated.
        assert_eq!(tx_bytes, 699_668); // incl. L2. Manually computed with ipsumdump
        assert_eq!(rx_bytes, 41_033); // as above
        assert_eq!(tx_loss, 8688);
        assert_eq!(tx_loss_per_conn, vec![0, 7240, 0, 1448]);
        assert_eq!(rx_loss, 0);
        assert_eq!(connection_cnt, 4);

        // Query for per domain counters
        let (agg_counter_dns_tx, mut agg_counter_dns_rx) = mpsc::channel(100);
        conn_track.handle_one_msg(ConnectionTrackerMsg::GetDnsTrafficCounters {
            tx: agg_counter_dns_tx,
            time_mode: TimeMode::PacketTime,
        });
        let dns_agg_counters = agg_counter_dns_rx.try_recv().unwrap();
        assert_eq!(dns_agg_counters.len(), 1);
        let stat_entry = dns_agg_counters.first().unwrap();
        assert_eq!(
            stat_entry.kind,
            AggregateStatKind::DnsDstDomain("netdebug.com".to_owned())
        );
        // The way conntection_tracker handles DNS lookups: on the first packet of a connection,
        // it sends a lookup request to the DNS tracker. Once the DNS tracker responds, the conn
        // tracker will start tracking the domain name. Importantly, the DNS response is a conn
        // tracker message, so the at least the initial packet that triggered the lookup is
        // ignored. This trace has 4 "connections". Three start with a SYN (78 bytes on wire), the
        // final one starts with a full data packet (1514 bytes on the wire).
        // So we expect less bytes reported than the sum of all connections
        let expected_tx_dns_bytes = 699_668 - 3 * 78 - 1514;
        assert_eq!(stat_entry.summary.tx.bytes, expected_tx_dns_bytes);
        assert_eq!(stat_entry.summary.tx.lost_bytes, Some(8688)); // all SACKs were tracked

        // the first packet of every connection happens to be TX, so on RX we don't miss
        // anything due to the DNS lookup.
        assert_eq!(stat_entry.summary.rx.bytes, 41_033);
        assert_eq!(stat_entry.summary.rx.lost_bytes, None); // all SACKs were tracked
    }

    /**
     * Windows localhost traffic isn't ethernet, it's some custom encoding that wireshark
     * understands where the first 4 bytes are [0x18, 0, 0, 0] and then there's an IP packet.
     *
     * Let's make sure this works so we can debug the webserver on windows.
     *
     * DISABLE this test for now until we add support for this: track as #344
     */
    #[ignore]
    #[test]
    fn test_windows_localhost_encoding() {
        let local_addrs = HashSet::from([IpAddr::from_str("::1").unwrap()]);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs);
        let mut capture = pcap::Capture::from_file(test_dir(
            "libconntrack",
            "tests/windows_localhost_traffic.pcapng",
        ))
        .unwrap();
        while let Ok(pkt) = capture.next_packet() {
            connection_tracker.add(OwnedParsedPacket::try_from_pcap(pkt).unwrap());
        }
        assert_eq!(connection_tracker.connections.len(), 1);
        // assert_eq!(connection_tracker.no_conn_key_packets.get_sum()!?, 0);
    }

    /**
     * Make sure our neighbor lookup stuff works including:
     * 1) quick replies when we have the info cached
     * 2) handling pending replies when we do not
     */
    #[test]
    fn test_neighbor_cache_lookup() {
        // One ipv4 and one ipv6
        let local_ipv4 = IpAddr::from_str("192.168.1.34").unwrap();
        let local_ipv6 = IpAddr::from_str("1:2::333").unwrap();
        let local_mac = MacAddress::from([1, 2, 3, 4, 5, 6]);
        let local_addrs = HashSet::from([local_ipv4, local_ipv6]);
        let (prober_tx, mut prober_rx) = channel(10);
        let mut connection_tracker = mk_mock_connection_tracker(local_addrs);
        connection_tracker
            .neighbor_cache
            .ip2mac
            .insert(local_ipv4, local_mac);
        connection_tracker
            .neighbor_cache
            .ip2mac
            .insert(local_ipv6, local_mac);
        // override the default mock prober_helper so we can capture those messages
        connection_tracker.prober_helper = ProberHelper::new(prober_tx, true);

        // wrap all of the functionality into a helper function to run twice: once for v4 and once for v6
        fn check_lookup_for_ip(
            target_ip: IpAddr,
            target_mac: MacAddress,
            connection_tracker: &mut ConnectionTracker<'_>,
            prober_rx: &mut Receiver<PerfMsgCheck<ProbeMessage>>,
            local_mac: MacAddress,
            local_ip: IpAddr,
        ) {
            // first, lookup something that doesn't exist to verify we send a lookup for it
            let (lookup_tx, mut lookup_rx) = channel(10);
            connection_tracker.handle_one_msg(ConnectionTrackerMsg::LookupMacByIp {
                identifier: "test".to_string(),
                ip: target_ip,
                tx: lookup_tx,
            });
            let probe_msg = prober_rx.try_recv().unwrap().skip_perf_check();
            use ProbeMessage::*;
            match probe_msg {
                SendIpLookup {
                    local_mac: test_local_mac,
                    local_ip: test_local_ip,
                    target_ip: remote_ip,
                } => {
                    assert_eq!(test_local_mac, local_mac.bytes());
                    assert_eq!(test_local_ip, local_ip);
                    assert_eq!(remote_ip, target_ip);
                }
                _wut => panic!("Unexpected probe message {:?}", _wut),
            }

            // 2. Now 'learn' that IP to mac mapping so that we get our async notification
            connection_tracker
                .neighbor_cache
                .learn(&Some(target_ip), &Some(target_mac));

            // 3. Verify we got the reply
            let (lookup_ip, lookup_mac) = lookup_rx.try_recv().unwrap();
            assert_eq!(lookup_ip, target_ip);
            assert_eq!(lookup_mac, target_mac);
        }
        // check v4
        let target_ipv4 = IpAddr::from_str("192.168.1.1").unwrap();
        let target_mac = MacAddress::from([20, 21, 22, 23, 24, 25]);
        check_lookup_for_ip(
            target_ipv4,
            target_mac,
            &mut connection_tracker,
            &mut prober_rx,
            local_mac,
            local_ipv4,
        );
        // check v6; should work even though we don't yet parse v6 NDP
        let target_ipv6 = IpAddr::from_str("de:ad:be:ef::").unwrap();
        check_lookup_for_ip(
            target_ipv6,
            target_mac,
            &mut connection_tracker,
            &mut prober_rx,
            local_mac,
            local_ipv6,
        );
    }
}
