use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    num::Wrapping,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    owned_packet::IcmpEchoInfo,
    topology_client::{DataStorageMessage, DataStorageSender},
};

use chrono::Utc;
use common::os_abstraction::pcap_ifname_to_ifindex;
use common_wasm::{
    stats_helper::{NaiivePercentiles, SimpleStats},
    timeseries_stats::{ExportedStatRegistry, StatHandle, StatType, Units},
};
use itertools::Itertools;
use libconntrack_wasm::{
    AggregatedGatewayPingData, ConnectionKey, NetworkGatewayPingProbe, NetworkGatewayPingState,
    NetworkGatewayPingType, NetworkInterfaceState,
};

use mac_address::MacAddress;
use net_route::Route;
use pcap::{ConnectionStatus, IfFlags};

use tokio::sync::{mpsc::channel, RwLock};
use uuid::Uuid;

#[cfg(not(test))]
use log::{debug, warn};
#[cfg(test)]
// Workaround to use prinltn! for logs.
use std::{println as debug, println as warn};

use crate::{
    connection::ConnectionUpdateListener,
    connection_tracker::{ConnectionTrackerMsg, ConnectionTrackerSender},
    neighbor_cache::NeighborCacheSender,
    owned_packet::OwnedParsedPacket,
    pcap::lookup_egress_device,
    prober::{ProbeMessage, ProberSender},
    send_or_log_sync,
    utils::remote_ip_to_local,
};

pub const BROADCAST_MAC_ADDR: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
// How frequently ping data is sent to the topology server
pub const PING_DATA_EXPORT_INTERVAL_MS: u64 = 30_000;

pub const MIN_REASONABLE_PING_RTT_NS: i64 = 1000;

pub const PING_PAYLOAD_PREFIX: &[u8] = b"SystemTracker";

/**
 * The System Tracker tracks the state of the system, e.g., what is the current default Gateway, active network interface, cpu load, mem info etc.
 * It keeps historical information for comparisons over time.
 *
 * It uses one task to periodically probe the network state and during that task send a ping to the gateway if we know the gateway's Mac Address,
 *  and if we don't, then we request the info from the ConnectionTracker which will turn into an Arp/NDP lookup if we don't know the info
 *
 * TODO: collect mem and cpu info, particularly to understand if the desktop process is using too much mem/cpu
 */

/**
 * Convert a pcap Result to a new NetworkInferfaceState.
 * If we got an error (e.g., if no interfaces were up), that's still a new network state and report it as such.
 *
 * NOTE: this isn't a static member of the class because it references pcap::Device and thus can't
 * be part of the libconntrack_wasm crate.
 */
fn network_interface_state_from_pcap_device(
    pcap_dev: Result<pcap::Device, pcap::Error>,
    gateways: Vec<IpAddr>, // If known
    comment: String,
) -> NetworkInterfaceState {
    match pcap_dev {
        Ok(pcap_dev) => NetworkInterfaceState {
            uuid: Uuid::new_v4(),
            gateways,
            // NOTE: pcap puts a more human readable name in the description,
            // so use that if it exists, else fall back the device name
            interface_name: if let Some(desc) = pcap_dev.desc {
                Some(desc.clone())
            } else {
                Some(pcap_dev.name.clone())
            },
            interface_ips: pcap_dev
                .addresses
                .iter()
                .cloned()
                .map(|a| a.addr)
                .collect_vec(),
            comment,
            has_link: pcap_dev.flags.if_flags & (IfFlags::UP | IfFlags::RUNNING)
                == (IfFlags::UP | IfFlags::RUNNING)
                // NOTE: on windows, the UP and RUNNING flags stay the same when the intf goes down
                // but it's the ConnectionStatus that changes
                && pcap_dev.flags.connection_status == ConnectionStatus::Connected,
            is_wireless: pcap_dev.flags.if_flags & IfFlags::WIRELESS == IfFlags::WIRELESS,
            start_time: Utc::now(),
            end_time: None,
            gateways_ping: HashMap::new(),
        },
        // Failed to lookup the device - fill in as much as we can
        Err(e) => NetworkInterfaceState {
            uuid: Uuid::new_v4(),
            gateways: Vec::new(),
            interface_name: None,
            interface_ips: Vec::new(),
            comment: format!("No network {} : {}", comment, e),
            has_link: false,
            is_wireless: false,
            start_time: Utc::now(),
            end_time: None,
            gateways_ping: HashMap::new(),
        },
    }
}

#[derive(Clone, Debug)]
pub struct SystemTracker {
    /// A history of active network devices, ordered from oldest to newest
    /// network_history.last() is the current active device; but use helper function
    /// SystemTracker::current_network()
    network_history: VecDeque<NetworkInterfaceState>,
    /// Max number of histoical network states to keep
    max_histories: usize,
    /// Max number of ping's to remember for each gateway
    max_pings_per_gateway: usize,
    /// A tx handle for the ConnectionTracker so we can subscribe/unsubscribe to ping flows
    connection_tracker: ConnectionTrackerSender,
    /// The tx handle for listening to ConnectionTracker updates; it's None until the
    /// ```SystemTracker::ping_listener` task populates it
    ping_listener_tx: Option<ConnectionUpdateListener>,
    /// The tx handler for resolving IP to Mac bindings from the ConnectionTracker
    /// ```SystemTracker::ping_listener` task populates it
    neighbor_listener_tx: Option<NeighborCacheSender>,
    /// The ID we put into all of our ping packets to mark it from us, just our $PID
    ping_id: u16,
    /// The payload we add to echo requests. We use this to ensure that responses we receive are
    /// from the system tracker (and not pingtree for example).
    ping_payload: Vec<u8>,
    /// A pointer to our prober task that manages rate limiting, etc.
    prober_tx: ProberSender,
    /// counter for number of network device changes
    network_device_changes: StatHandle,
    /// counter for number of pings we get with a weird/delayed sequence number, shared across all gateways
    out_of_sequence_ping: StatHandle,
    /// counter for number of pings we get for an IP that's not a gateway we know, shared across all gateways
    unknown_gateway_ping: StatHandle,
    /// counter for number of duplicate pings, shared across all gateways
    duplicate_ping: StatHandle,
    /// Number of times the ping RTT was too short to be "real" or even negative
    /// e.g., due to clock skew or clock going backwards
    ping_rtt_too_low: StatHandle,
    /// Number of pings that weren't for us (i.e., payload didn't match what we expected)
    ping_not_for_us: StatHandle,
    /// Channel to send messages to the topology server
    data_storage_client: Option<DataStorageSender>,
    last_ping_data_sent_time: Instant,
}

impl SystemTracker {
    pub async fn new(
        stats_registry: ExportedStatRegistry,
        max_histories: usize,
        max_pings_per_gateway: usize,
        connection_tracker: ConnectionTrackerSender,
        prober_tx: ProberSender,
        data_storage_client: Option<DataStorageSender>,
    ) -> SystemTracker {
        let current_network = SystemTracker::snapshot_current_network_state().await;
        SystemTracker::new_with_network_state(
            stats_registry,
            max_histories,
            max_pings_per_gateway,
            current_network,
            connection_tracker,
            prober_tx,
            data_storage_client,
        )
    }
    pub fn new_with_network_state(
        stats_registry: ExportedStatRegistry,
        max_histories: usize,
        max_pings_per_gateway: usize,
        current_network: NetworkInterfaceState,
        connection_tracker: ConnectionTrackerSender,
        prober_tx: ProberSender,
        data_storage_client: Option<DataStorageSender>,
    ) -> SystemTracker {
        if let Some(data_storage_client) = &data_storage_client {
            let mut cloned_state = current_network.clone();
            cloned_state.gateways_ping.clear();
            send_or_log_sync!(
                data_storage_client,
                "SystemTracker::new_with_network_state()",
                DataStorageMessage::StoreNetworkInterfaceState {
                    network_interface_state: cloned_state,
                }
            );
        }
        let mut ping_payload = Vec::new();
        ping_payload.extend(PING_PAYLOAD_PREFIX);
        ping_payload.extend(vec![0u8; 128 - ping_payload.len()]);
        // sanity check
        assert_eq!(ping_payload.len(), 128);

        SystemTracker {
            network_history: VecDeque::from([current_network]),
            network_device_changes: stats_registry.add_stat(
                "network_device_changes",
                Units::None,
                [StatType::COUNT],
            ),
            max_histories,
            max_pings_per_gateway,
            connection_tracker,
            ping_listener_tx: None,
            neighbor_listener_tx: None,
            ping_id: std::process::id() as u16,
            prober_tx,
            out_of_sequence_ping: stats_registry.add_stat(
                "out_of_sequence_pings",
                Units::None,
                [StatType::COUNT],
            ),
            duplicate_ping: stats_registry.add_stat(
                "duplicate_pings",
                Units::None,
                [StatType::COUNT],
            ),
            unknown_gateway_ping: stats_registry.add_stat(
                "unknown_gateway_ping",
                Units::None,
                [StatType::COUNT],
            ),
            ping_rtt_too_low: stats_registry.add_stat(
                "ping_rtt_too_low",
                Units::None,
                [StatType::COUNT],
            ),
            ping_not_for_us: stats_registry.add_stat(
                "ping_not_for_us",
                Units::None,
                [StatType::COUNT],
            ),
            data_storage_client,
            last_ping_data_sent_time: Instant::now(),
            ping_payload,
        }
    }

    #[cfg(test)]
    fn mk_mock(network_device: NetworkInterfaceState) -> SystemTracker {
        // create throw-away connection tracker channel
        let (connection_tracker_tx, _rx) = channel(10);
        let (prober_tx, _rx) = channel(10);
        SystemTracker::new_with_network_state(
            ExportedStatRegistry::new("testing", std::time::Instant::now()),
            10,
            10,
            network_device,
            connection_tracker_tx,
            prober_tx,
            None,
        )
    }

    fn current_network(&self) -> &NetworkInterfaceState {
        // unwrap is ok b/c there will always be at least one
        self.network_history.iter().last().unwrap()
    }

    fn current_network_mut(&mut self) -> &mut NetworkInterfaceState {
        // unwrap is ok b/c there will always be at least one
        self.network_history.iter_mut().last().unwrap()
    }

    ///
    /// Handle a potential network state update.
    ///  
    /// Return true if state was updated, false if no update was needed
    ///  
    /// If the state has changed, send a msg to the connection tracker to delete the
    /// ConnectionUpdateListener that handles ping responses
    ///  
    /// Whether the state has changed or not, send a fresh round of pings to each gateway.
    ///  
    /// NOTE: this function is called every ```update_period``` from the [`SystemTracker::network_update_watcher`]
    /// task, e.g., every 500ms
    ///  
    pub async fn handle_update_network_state(
        &mut self,
        interface_state: NetworkInterfaceState,
    ) -> bool {
        let changed = if self.current_network().has_state_changed(&interface_state) {
            self.current_network_mut().end_time = Some(Utc::now());
            let old_state = self.current_network().clone();
            // for each old gateway, tell the connection tracker to stop listening to the ping updates
            for (gateway, ping_state) in &old_state.gateways_ping {
                send_or_log_sync!(
                    self.connection_tracker,
                    format!(
                        "unsubscribe from connection updates for gateway {}",
                        gateway
                    ),
                    ConnectionTrackerMsg::DelConnectionUpdateListener {
                        desc: PING_LISTENER_DESC.to_string(),
                        key: ping_state.key.clone(),
                    }
                );
            }
            self.network_history.push_back(interface_state.clone());
            while self.network_history.len() >= self.max_histories {
                self.network_history.pop_front();
            }
            self.network_device_changes.bump();
            warn!(
                "Network state change from '{}' to '{}'",
                old_state, interface_state
            );
            if let Some(data_storage_client) = &self.data_storage_client {
                self.export_gateway_ping_from_state(
                    &old_state,
                    "SystemTracker::handle_update_network_state() -- old ping data after change",
                );
                // We want to wait one interval before we export the first ping data for
                // the new interface. Otherwise we might end up with no or very few data
                // points and a potentially biased distribution.
                self.last_ping_data_sent_time = Instant::now();

                // Don't export the gateway ping data -- we export ping data
                // separately.
                let mut old_state = old_state.clone();
                old_state.gateways_ping.clear();
                let mut interface_state = interface_state.clone();
                interface_state.gateways_ping.clear();
                send_or_log_sync!(
                    data_storage_client,
                    "SystemTracker::handle_update_network_state() -- old_state",
                    DataStorageMessage::StoreNetworkInterfaceState {
                        network_interface_state: old_state
                    }
                );
                send_or_log_sync!(
                    data_storage_client,
                    "SystemTracker::handle_update_network_state() -- new_state",
                    DataStorageMessage::StoreNetworkInterfaceState {
                        network_interface_state: interface_state
                    }
                );
            }
            true
        } else {
            debug!(
                "Ignoring network state update - unchanged! {:?}",
                interface_state
            );
            false // no state update
        };
        // whether the state has changed or not, launch pings for each of the gateways
        for gateway in &self.current_network().gateways.clone() {
            self.send_next_ping(gateway);
        }
        if self.last_ping_data_sent_time.elapsed()
            > Duration::from_millis(PING_DATA_EXPORT_INTERVAL_MS)
        {
            self.export_gateway_ping_from_state(
                self.current_network(),
                "SystemTracker::handle_update_network_state() -- periodic ping data",
            );
            self.last_ping_data_sent_time = Instant::now();
        }
        changed
    }

    pub fn export_gateway_ping_from_state(
        &self,
        network_state: &NetworkInterfaceState,
        description: &'static str,
    ) {
        if let Some(data_storage_client) = &self.data_storage_client {
            let ping_data = aggregate_ping_state(network_state);
            if !ping_data.is_empty() {
                send_or_log_sync!(
                    data_storage_client,
                    description,
                    DataStorageMessage::StoreGatewayPingData { ping_data }
                );
                debug!("Sending aggregated ping data -- {}", description);
            } else {
                debug!(
                    "Aggregated ping data is empry -- Not sending -- {}",
                    description
                );
            }
        }
    }

    pub fn get_network_interface_histories(&self) -> Vec<NetworkInterfaceState> {
        Vec::from(self.network_history.clone())
    }

    /**
     * Spawn two tasks:
     *
     * Task #1:  periodically queries the network device state and sends an update message
     * to the SystemTracker.  Do this in a separate task in case it blocks/has random OS delays.  Who knows
     * how pcap implements this on all of the various platforms.  If we cared about super-precise periodicity,
     * we would track the time it took to process this and subtract it from the update_period on each run,
     * but that level of precision isn't needed.
     *
     * Ideally we could subscribe to OS-specific push updates rather than periodic pulls like this, but this
     * seems more portable.  TODO: investigate if there are other rust crate magics that solve this for us.
     *
     * Task #2: listen to the rx queue from the ConnectionTracker for ping information and record it into the NetworkInterfaceState
     *
     * NOTE: this is not spawned automatically on ```SystemTracker::new()``` and must be manually called
     */
    pub fn spawn_system_tracker_background_tasks(
        system_tracker: Arc<RwLock<SystemTracker>>,
        update_period: Duration,
    ) {
        let system_tracker_clone = system_tracker.clone();
        // task #2
        tokio::task::spawn(async move {
            SystemTracker::ping_and_neighbor_listener(system_tracker_clone).await;
        });
        // task #1
        tokio::task::spawn(async move {
            SystemTracker::network_change_watcher(system_tracker.clone(), update_period).await;
        });
    }

    pub async fn snapshot_current_network_state() -> NetworkInterfaceState {
        let device = lookup_egress_device();
        let device_hint = match &device {
            Ok(d) => Some(d.clone()),
            Err(_) => None,
        };
        let gateways = match SystemTracker::get_default_gateways_async(device_hint).await {
            Ok(g) => g,
            Err(e) => {
                warn!(
                    "Failed to collect the network route table !? :: {} - trying again later",
                    e
                );
                Vec::new()
            }
        };
        network_interface_state_from_pcap_device(device, gateways, "Update".to_string())
    }

    /// Get all of the default routes in the system in an OS-independent way
    /// In the cases where there are multiple gateway addresses, use the broadcast hints to
    /// prefer gateway IPs that match our egress interface
    /// * 'hints' - The Address information for the egress interface as copied from a  ['pcap::Device']
    ///     This will give us various hints about which gateway IPs to prefer in the
    ///     event that there are multiple conflicting options
    pub async fn get_default_gateways_async(
        hints: Option<pcap::Device>,
    ) -> std::io::Result<Vec<IpAddr>> {
        tokio::task::spawn_blocking(move || {
            // The net-route crate is async but we don't trust that it won't block on some OS calls,
            // so we spawn it with spawn_blocking() (a separate OS thread essentially), and then start a runtime
            // in this thread so we can call the async fn in net route

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            // this magic crate claims to list the routing table on MacOs/Linux/Windows... let's see
            // don't use the handle.default_route() function as it only returns the first route it finds where we
            // want all of them (v4 and v6) which oddly [`net_route::Handle::default_route`] only returns
            // one ... which one!?  Just do it ourselves...
            let routes = rt.block_on(async { net_route::Handle::new()?.list().await })?;
            // first, strip out the default routes, e.g., with prefix = 0
            let default_routes = routes
                .into_iter()
                // needs to have a prefix of 0 and a valid gateway to be considered a 'default' route
                .filter(|r| r.prefix == 0)
                .collect::<Vec<Route>>();
            // split into v4 and v6, and if there are multiple of one type, tie break by the hints
            // NOTE: multiple default routes with different metrics can happen, e.g., if there's a WiFI
            // and wired link at the same time, or a VPN (or probably in other cases)
            let (default_v4_routes, default_v6_routes): (Vec<Route>, Vec<Route>) = default_routes
                .iter()
                .cloned()
                .partition(|r| r.destination.is_ipv4());

            let mut gateways = Vec::new();
            SystemTracker::get_gateway_ip_by_all_hints(
                default_v4_routes,
                hints.clone(),
                &mut gateways,
            );
            SystemTracker::get_gateway_ip_by_all_hints(default_v6_routes, hints, &mut gateways);
            Ok(gateways)
        })
        .await?
    }

    /// helper function to best match the default gateways to the active egress interface
    /// This is a PITA because:
    /// 1) On Windows, when an interface goes down/becomes unavailable, it's routes are often
    ///     still in the routing table (!?)
    /// 2) A link-local IPv6 address has the same valid route on every interface
    /// 3) We can return gateways that we have no hope of pinging which confuses the UI/users
    ///
    /// So, use a sequence of heuristics to find only the gateway IPs that are directly reachable
    /// from the interface corresponding to the active default route
    /// * 'routes' - a list of all prefix=0 routes from ['get_default_gateways_async()']
    /// * 'hints' - The Address information for the egress interface as copied from a  ['pcap::Device']
    ///     This will give us various hints about which gateway IPs to prefer in the
    ///     event that there are multiple conflicting options
    ///
    fn get_gateway_ip_by_all_hints(
        routes: Vec<Route>,
        hints: Option<pcap::Device>,
        gateways: &mut Vec<IpAddr>,
    ) {
        // first try to see if we can find an ifindex-based hint
        if !SystemTracker::get_gateway_ip_by_ifindex_hints(&routes, hints, gateways) {
            // no valid hints; just return all the passed routes
            gateways.extend(
                routes
                    .iter()
                    .filter_map(|r| r.gateway)
                    .collect::<Vec<IpAddr>>(),
            );
        }
    }

    /// Filter the gateway IPs to match the ifindex of the egress interface (if we can get it)
    fn get_gateway_ip_by_ifindex_hints(
        routes: &[Route],
        hints: Option<pcap::Device>,
        gateways: &mut Vec<IpAddr>,
    ) -> bool {
        if let Some(dev) = hints {
            match pcap_ifname_to_ifindex(dev.name.clone()) {
                Ok(if_index) => {
                    let prefered_routes = routes
                        .iter()
                        .filter_map(|r| {
                            if r.ifindex == Some(if_index) {
                                r.gateway
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<IpAddr>>();
                    gateways.extend(prefered_routes);
                    return true;
                }
                Err(e) => {
                    warn!("Failed to lookup ifindex for {} -- {}", dev.name, e);
                    return false;
                }
            }
        }
        // we get here either on Err() from lookup or if there are no link_local addresses
        false
    }

    /// Persistent task that waits for various updates from the system and calls the relevant handlers
    async fn ping_and_neighbor_listener(system_tracker: Arc<RwLock<SystemTracker>>) -> ! {
        // create the tx/rx queues here so we can have them without locking the system tracker
        let (ping_listener_tx, mut ping_listener_rx) = channel(256);
        let (neighbor_listener_tx, mut neighbor_listener_rx) = channel(256);
        {
            // record them into the system_track so other parts can access
            let mut lock = system_tracker.write().await;
            lock.ping_listener_tx = Some(ping_listener_tx);
            lock.neighbor_listener_tx = Some(neighbor_listener_tx);
        }
        loop {
            tokio::select! {
                Some((pkt, key)) = ping_listener_rx.recv() =>  {
                    system_tracker.write().await.handle_ping_recv(pkt, key);
                },
                Some((ip, mac)) = neighbor_listener_rx.recv() => {
                    system_tracker.write().await.handle_neighbor_update(ip, mac);
                }
            }
        }
    }

    /// We got a ping (echo request or reply, v4 or v6) from the ConnectionTracker
    /// Parse it and update the relevant state
    /// NOTE: this function is typically called with a lock on the SystemTracker so
    /// be careful what you do here
    fn handle_ping_recv(&mut self, pkt: Box<OwnedParsedPacket>, key: ConnectionKey) {
        // extract the relevant info
        let IcmpEchoInfo {
            id,
            seq,
            is_reply,
            payload,
        } = match pkt.get_icmp_echo_info() {
            Some(info) => info,
            None => {
                warn!("Ignnoring weird non-echo request/reply pkt in handle_ping_recv()");
                return;
            }
        };

        // We truncate the payload during pcap handling, thus the payload we receive here might be
        // shorter than the payload we sent out. So we only compare the prefix
        assert_eq!(id, self.ping_id); // ConnectionTracker is broken if they sent us this with wrong ID
        if !payload.starts_with(PING_PAYLOAD_PREFIX) {
            // Not for us.
            self.ping_not_for_us.bump();
            return;
        }
        let gateway = key.remote_ip;
        let max_pings_per_gateway = self.max_pings_per_gateway;
        // now, lookup the ping state and update it
        if let Some(state) = self
            .network_history
            .iter_mut()
            .last()
            .unwrap()
            .gateways_ping
            .get_mut(&gateway)
        {
            let probe_complete = if let Some(current_probe) = &mut state.current_probe {
                if seq != current_probe.seqno {
                    warn!(
                        "Ignoring out-of-sequence ping for {} :: got seq {} != expected seq {}",
                        key, seq, current_probe.seqno
                    );
                    self.out_of_sequence_ping.bump();
                    return;
                }
                if is_reply {
                    if current_probe.recv_time.is_some() {
                        warn!("Duplicate ping reply for {} :: seq={}", key, seq);
                        self.duplicate_ping.bump();
                    }
                    current_probe.recv_time = Some(pkt.timestamp);
                } else {
                    if current_probe.sent_time.is_some() {
                        warn!("Duplicate ping request for {} :: seq={}", key, seq);
                        self.duplicate_ping.bump();
                    }
                    current_probe.sent_time = Some(pkt.timestamp);
                }
                current_probe.sent_time.is_some() && current_probe.recv_time.is_some()
            } else {
                warn!(
                    "Got a (duplicate?) ping when we weren't expecting it: key={} seq={}",
                    key, seq
                );
                self.duplicate_ping.bump();
                false
            };
            if probe_complete {
                // pull this out of the 'current_probe' state and push it into the histoical probe state
                // unwrap is ok b/c we only get here if it existed
                let probe = state.current_probe.take().unwrap();
                let rtt = probe.recv_time.unwrap() - probe.sent_time.unwrap();
                if rtt < chrono::Duration::nanoseconds(MIN_REASONABLE_PING_RTT_NS) {
                    // The RTT is unreasonable short or even negative. This can happen due to clock skew, etc. ignore.
                    debug!(
                        "Ping RTT to gateway {} is {}ns which is unreasonable short (or negative)",
                        gateway,
                        rtt.num_nanoseconds().unwrap()
                    );
                    self.ping_rtt_too_low.bump();
                }
                state.historical_probes.push_back(probe);
                // keep a max number of historical pings
                while state.historical_probes.len() > max_pings_per_gateway {
                    state.historical_probes.pop_front();
                }
            }
        } else {
            warn!(
                "Got ping for a gateway we're not tracking: {} - forgot to unsubscribe?",
                gateway
            );
            self.unknown_gateway_ping.bump();
        }
    }

    /// This is called from ping_and_neighbor_listener() task to
    /// tell us when the Connection Manager is able to resolve the Mac address of our
    /// target gateway
    fn handle_neighbor_update(&mut self, gateway: IpAddr, mac: MacAddress) {
        if let Some(state) = self
            .network_history
            .iter_mut()
            .last()
            .unwrap()
            .gateways_ping
            .get_mut(&gateway)
        {
            if state.gateway_mac.is_some() {
                warn!(
                    "Weird: got duplicate neighbor replies for gateway {} mac {}",
                    gateway, mac
                );
                // TODO: decide if we need to bump a counter here
            }
            // TODO: figure out how to handle pro-active Mac-to-IP binding changes, e.g., to support
            // any of the protocols listed https://en.wikipedia.org/wiki/First-hop_redundancy_protocol
            state.gateway_mac = Some(mac.bytes());
            if let Some(probe_state) = &state.current_probe {
                // we sent a lookup to the connection tracker and this message means we either
                // got a cached reply or sent an Arp/Ndp and got a reponse.
                //
                // From the API currently, we can't tell if it was cached or if we sent a request
                // and got a response, so just count this probe as 'not dropped' without any specific
                // timing information; don't add it to the history just because it's kinda garbage data
                //
                // TODO: figure out if we want to change the APIs and try to get real perf out of Arp/Ndp
                if probe_state.ping_type == NetworkGatewayPingType::ArpOrNdp {
                    state.next_seq = Wrapping(probe_state.seqno); // back up the seqno b/c it was unused
                    state.current_probe = None; // mark the probe as received
                }
            }
        } else {
            warn!(
                "Ignoring a neighbor update for an unknown (old?) gateway ip {} mac {}",
                gateway, mac
            );
            // TODO: decide if we need to bump a counter here
        }
    }

    /**
     * Watch for network changes and update the system_tracker
     */
    async fn network_change_watcher(
        system_tracker: Arc<RwLock<SystemTracker>>,
        update_period: Duration,
    ) {
        loop {
            tokio::time::sleep(update_period).await;
            let interface_state = SystemTracker::snapshot_current_network_state().await;
            system_tracker
                .write()
                .await
                .handle_update_network_state(interface_state)
                .await;
        }
    }

    /**
     * Check to see if we've pinged this IP before.
     *
     * If not, setup all of the state needed for it
     *
     * If yes, just update that state
     *
     * The System::ping_listener task will handle receiving the probe and reply; this is just
     * fire and forget
     */
    fn send_next_ping(&mut self, gateway: &IpAddr) {
        if !self.current_network().gateways_ping.contains_key(gateway) {
            if let Err(e) = self.make_new_ping_state(gateway) {
                warn!(
                    "Tried to figure out state for pinging {} - but got {} - will try again",
                    gateway, e
                );
            }
        }
        // outfox the borrow checker
        let max_pings = self.max_pings_per_gateway;
        // unwrap ok because of above clause
        let state = self
            .current_network_mut()
            .gateways_ping
            .get_mut(gateway)
            .unwrap();
        // if we still haven't gotten a reply to the previous probe, mark it as dropped and push it to history
        // NOTE: .take() marks it as None and gives us ownership
        if let Some(mut old_probe) = state.current_probe.take() {
            old_probe.dropped = true;
            state.historical_probes.push_back(old_probe);
            while state.historical_probes.len() > max_pings {
                state.historical_probes.pop_front();
            }
        }
        let seqno = state.next_seq.0;
        state.next_seq += 1;
        let ping_type = if state.gateway_mac.is_some() {
            NetworkGatewayPingType::IcmpEcho
        } else {
            NetworkGatewayPingType::ArpOrNdp
        };
        state.current_probe = Some(NetworkGatewayPingProbe::new(seqno, ping_type));
        let local_mac = state.local_mac;
        let key = state.key.clone();
        if let Some(gateway_mac) = state.gateway_mac {
            send_or_log_sync!(
                self.prober_tx,
                "send ping",
                ProbeMessage::SendPing {
                    local_mac,
                    local_ip: key.local_ip,
                    remote_mac: Some(gateway_mac),
                    remote_ip: key.remote_ip,
                    id: self.ping_id,
                    seq: seqno,
                    payload: Some(self.ping_payload.clone()),
                }
            );
        } else {
            // we don't know our gateway's mac yet - send a lookup message to the connection tracker
            // which will either get an immediate response if it's cached or trigger an Arp/NDP lookup
            // from the device
            // this is a bit subtle, b/c we could think of this like an ArpPing instead of an ICMP ping
            // this code will keep triggering everytime we go to ping until we resolve the Mac address
            if let Some(neighbor_listener_tx) = &self.neighbor_listener_tx {
                // TODO: add counter to track number of lookups
                send_or_log_sync!(
                    self.connection_tracker,
                    "lookup gateway mac",
                    ConnectionTrackerMsg::LookupMacByIp {
                        identifier: PING_LISTENER_DESC.to_string(),
                        ip: *gateway,
                        tx: neighbor_listener_tx.clone()
                    }
                );
            }
        }
    }

    /// Called for each new gateway to initialize the state needed to track pings
    fn make_new_ping_state(&mut self, gateway: &IpAddr) -> Result<(), pcap::Error> {
        // need to populate first time state and subscribe to ConnectionTracker updates
        let key = self.make_gateway_ping_key(gateway)?;
        // subscribe to ping flow from ConnectionTracker, if it's defined
        if let Some(ping_listener) = &self.ping_listener_tx {
            send_or_log_sync!(
                self.connection_tracker.clone(),
                "SystemTracker::make_new_ping_stat",
                ConnectionTrackerMsg::AddConnectionUpdateListener {
                    desc: PING_LISTENER_DESC.to_string(),
                    tx: ping_listener.clone(),
                    key: key.clone(),
                }
            );
        }
        let local_mac = mac_address::get_mac_address_by_ip(&key.local_ip)
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                warn!(
                    "Failed to lookup MacAddress for local IP {} (for gateway {}) - failing back to broadcast",
                    key.local_ip, gateway
                );
                mac_address::MacAddress::from(BROADCAST_MAC_ADDR)
            });
        let state = NetworkGatewayPingState {
            key,
            next_seq: Wrapping(0),
            current_probe: None,
            historical_probes: VecDeque::new(),
            local_mac: local_mac.bytes(),
            gateway_mac: None, // this will get filled in by the ConnectionTracker
        };
        self.current_network_mut()
            .gateways_ping
            .insert(*gateway, state);
        Ok(())
    }

    /**
     * For a given gateway IP, figure out what the corresponding ConnectionKey would be
     * based off of the local routing table ala remote_ip_to_local()
     */
    fn make_gateway_ping_key(&self, gateway: &IpAddr) -> Result<ConnectionKey, pcap::Error> {
        let source_ip = remote_ip_to_local(*gateway)?;
        Ok(ConnectionKey::make_icmp_echo_key(
            source_ip,
            *gateway,
            self.ping_id,
        ))
    }

    #[cfg(test)]
    fn make_gateway_ping_key_testing(&self, gateway: &IpAddr, local_ip: &IpAddr) -> ConnectionKey {
        ConnectionKey::make_icmp_echo_key(*local_ip, *gateway, self.ping_id)
    }
}
const PING_LISTENER_DESC: &str = "SystemTracker::ping_listener";

pub fn aggregate_ping_state(
    network_state: &NetworkInterfaceState,
) -> Vec<AggregatedGatewayPingData> {
    let mut ret = Vec::new();
    for (ip, ping_state) in &network_state.gateways_ping {
        let mut num_responses_recv = 0usize;
        let mut simple_stats = SimpleStats::new();
        let mut samples = Vec::new();
        for probe in &ping_state.historical_probes {
            if !probe.dropped && probe.sent_time.is_some() && probe.recv_time.is_some() {
                let rtt_ns = (probe.recv_time.unwrap() - probe.sent_time.unwrap())
                    .num_nanoseconds()
                    .unwrap();
                if rtt_ns < MIN_REASONABLE_PING_RTT_NS {
                    // this should never happen. We should never have added that probe.
                    // I guess we could panic!() but that seems excessive.
                    continue;
                }
                num_responses_recv += 1;
                simple_stats.add_sample(rtt_ns as f64);
                samples.push(rtt_ns as u64);
            }
        }
        if !samples.is_empty() {
            let percentiles = NaiivePercentiles::new(samples);
            ret.push(AggregatedGatewayPingData {
                network_interface_uuid: network_state.uuid,
                gateway_ip: *ip,
                num_probes_sent: ping_state.historical_probes.len(),
                num_responses_recv,
                // Note: we don't use simple_stats / ExportedSimpleStats directly here because they
                // use f64 internally and I don't want to mix u64 for the percentiles with f64 for the
                // mean...
                rtt_mean_ns: simple_stats.mean().round() as u64,
                rtt_variance_ns: simple_stats.variance().map(|v| v.round() as u64),
                rtt_min_ns: percentiles.percentile(0).unwrap(),
                rtt_p50_ns: percentiles.percentile(50).unwrap(),
                rtt_p75_ns: percentiles.percentile(75).unwrap(),
                rtt_p90_ns: percentiles.percentile(90).unwrap(),
                rtt_p99_ns: percentiles.percentile(99).unwrap(),
                rtt_max_ns: percentiles.percentile(100).unwrap(),
            });
        }
    }
    ret
}

#[cfg(test)]
mod test {
    use std::{collections::HashSet, net::Ipv4Addr, str::FromStr};

    use common::test_utils::test_dir;
    use etherparse::{Icmpv4Type, TransportHeader};
    use tokio::sync::mpsc::{channel, error::TryRecvError};

    use crate::{
        neighbor_cache::NeighborState,
        pcap::test::MockRawSocketProber,
        prober::{make_ping_icmp_echo_reply, make_ping_icmp_echo_request},
    };

    use super::*;

    #[tokio::test]
    async fn test_network_device_from_pcap() {
        // I don't think this needs super privs on any OS... let's see :-)
        let device = lookup_egress_device();
        // SUCCESS == no panic!()
        let _network_state =
            network_interface_state_from_pcap_device(device, Vec::new(), "test".to_string());
    }

    #[tokio::test]
    async fn test_network_device_update() {
        let now = Utc::now();
        let mut intf = NetworkInterfaceState::mk_mock("mock dev1".to_string(), now);
        let mut system_tracker = SystemTracker::mk_mock(intf.clone());
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        system_tracker.data_storage_client = Some(tx);
        // hacky: set the last_ping_data_sent_time to some time in the past, but not enough
        // in the past to trigger an export
        system_tracker.last_ping_data_sent_time = Instant::now() - Duration::from_secs(15);
        intf.start_time = now + Duration::from_secs(1);
        assert!(!system_tracker.handle_update_network_state(intf).await);
        let intf2 =
            NetworkInterfaceState::mk_mock("mock dev2".to_string(), now + Duration::from_secs(2));
        assert!(system_tracker.handle_update_network_state(intf2).await);
        assert_eq!(system_tracker.network_device_changes.get_sum(), 1);

        // last_ping_data_sent_time should have been reset by the update
        // we hackily check that it's only a little in the past
        assert!(system_tracker.last_ping_data_sent_time.elapsed() < Duration::from_secs(3));

        let mut recv_interface_states = HashMap::new();
        while let Ok(msg) = rx.try_recv() {
            match msg.skip_perf_check() {
                DataStorageMessage::StoreConnectionMeasurements { .. } => panic!(),
                DataStorageMessage::StoreNetworkInterfaceState {
                    network_interface_state,
                } => {
                    recv_interface_states.insert(
                        network_interface_state.interface_name.clone().unwrap(),
                        network_interface_state,
                    );
                }
                // No ping data so nothing is exported
                DataStorageMessage::StoreGatewayPingData { .. } => panic!(),
                DataStorageMessage::StoreDnsEntries { .. } => panic!(),
            }
        }
        assert_eq!(
            recv_interface_states.get("mock dev1").unwrap().start_time,
            now
        );
        assert!(recv_interface_states
            .get("mock dev1")
            .unwrap()
            .end_time
            .is_some());
        assert_eq!(
            recv_interface_states.get("mock dev2").unwrap().start_time,
            now + Duration::from_secs(2)
        );
        assert!(recv_interface_states
            .get("mock dev2")
            .unwrap()
            .end_time
            .is_none());
    }

    /**
     * Assume what ever system we're running the test on has a valid network with at least
     * one default route
     */
    #[tokio::test]
    async fn test_get_default_routes_async() {
        let gateways = SystemTracker::get_default_gateways_async(None)
            .await
            .unwrap();
        for gw in &gateways {
            println!("Found a default gw: {}", gw);
        }
        assert_ne!(gateways.len(), 0);
    }

    /****
     * Startup a Prober task and a SystemTracker and verify that we see outgoing pings and
     * that we get the right listener call backs
     *
     * This test is a bit of a beast, but there's a lot going on here
     */
    #[tokio::test]
    async fn test_system_tracker_outgoing_gateway_ping() {
        let mut mock_writer = MockRawSocketProber::default();
        let gateway = IpAddr::from_str("192.168.1.1").unwrap();
        let gateway_mac = [0, 1, 2, 3, 4, 5];
        // what IP would the test machine use to connect to this gateway?
        let local_ip = remote_ip_to_local(gateway).unwrap();
        let mut mock_connection_tracker =
            crate::connection_tracker::test::mk_mock_connection_tracker(HashSet::from([local_ip]));
        // pre-cache the gateway's Mac in the neighbor_cache
        mock_connection_tracker.neighbor_cache.ip2mac.insert(
            gateway,
            NeighborState {
                mac: MacAddress::from(gateway_mac),
                learn_time: Utc::now(),
            },
        );
        let mut mock_network_interface_state =
            NetworkInterfaceState::mk_mock("test".to_string(), Utc::now());
        let (ping_listener_tx, mut ping_listener_rx) = channel(10);
        let (neighbor_listener_tx, mut neighbor_listener_rx) = channel(10);
        let mut system_tracker = SystemTracker::mk_mock(mock_network_interface_state.clone());
        system_tracker.connection_tracker = mock_connection_tracker.get_tx();
        system_tracker.prober_tx = mock_writer.tx.clone(); // put the mock prober into place
        system_tracker.ping_listener_tx = Some(ping_listener_tx); // put the ping listener into place
        system_tracker.neighbor_listener_tx = Some(neighbor_listener_tx);

        // now make it appear like we found a new gateway
        mock_network_interface_state.gateways.push(gateway);
        // this should setup state for a ping including subscribing to the connection updates
        // and sending a lookup_mac_by_ip message to the connection tracker
        // it won't (yet) send the ping
        system_tracker
            .handle_update_network_state(mock_network_interface_state.clone())
            .await;
        // let the conntrack process the queued subscription msg and lookup msg
        mock_connection_tracker.flush_rx_loop().await;
        // verify the ping state; clone it to avoid holding a &mut on SystemTracker
        let ping_state = system_tracker
            .network_history
            .iter_mut()
            .last()
            .unwrap()
            .gateways_ping
            .get(&gateway)
            .unwrap()
            .clone();
        assert_ne!(ping_state.local_mac, BROADCAST_MAC_ADDR);
        assert!(mock_connection_tracker
            .update_listeners
            .get(&ping_state.key)
            .is_some());
        println!("Sent with local_mac {:X?}", ping_state.local_mac);
        let current_probe = ping_state.current_probe.as_ref().unwrap();
        assert_eq!(current_probe.seqno, 0);
        // make sure we got a neighbor update from the connection tracker...
        let (neighbor_update_ip, neighbor_update_mac) = neighbor_listener_rx.try_recv().unwrap();
        // ... and process it
        system_tracker.handle_neighbor_update(neighbor_update_ip, neighbor_update_mac);
        // now verify that we cleaned up the ping state
        // verify the ping state; clone it to avoid holding a &mut on SystemTracker
        assert!(system_tracker
            .network_history
            .iter_mut()
            .last()
            .unwrap()
            .gateways_ping
            .get(&gateway)
            .unwrap()
            .current_probe
            .is_none());
        assert_ne!(ping_state.local_mac, BROADCAST_MAC_ADDR);
        assert!(mock_connection_tracker
            .update_listeners
            .get(&ping_state.key)
            .is_some());
        println!("Sent with local_mac {:X?}", ping_state.local_mac);
        let current_probe = ping_state.current_probe.as_ref().unwrap();
        assert_eq!(current_probe.seqno, 0);

        // now re-call the handle_update_network_state() call which now that we
        // have a proper gateway_mac should actually send a ping!
        system_tracker
            .handle_update_network_state(mock_network_interface_state.clone())
            .await;
        // Take the SendPing message off the queue, turn it into bytes, and send
        // those bytes as a message to the ConnectionTracker as if we had pcap received it
        mock_writer.redirect_into_connection_tracker(&mut mock_connection_tracker);
        // Let the ConnectionTracker process those messages and trigger the update notification
        mock_connection_tracker.flush_rx_loop().await;
        // did the ping_listener get a message!? Is it a correctly formated ping?
        // NOTE: if we didn't pre-populate the gateway mac info, this would instead have generated an Arp lookup
        let (update_pkt, key) = ping_listener_rx.recv().await.unwrap();
        println!("Got ping reply from ping_listener!");
        assert_eq!(ping_state.key, key);
        let (ping_src_ip, ping_dst_ip) = update_pkt.get_src_dst_ips().unwrap();
        assert_eq!(ping_src_ip, local_ip);
        assert_eq!(ping_dst_ip, gateway);
        assert_eq!(
            update_pkt.link.as_ref().unwrap().source,
            ping_state.local_mac
        );
        assert_eq!(update_pkt.link.as_ref().unwrap().destination, gateway_mac);
        match update_pkt.transport {
            Some(TransportHeader::Icmpv4(hdr)) => match hdr.icmp_type {
                Icmpv4Type::EchoRequest(echo_hdr) => {
                    assert_eq!(echo_hdr.seq, 0);
                    assert_eq!(echo_hdr.id, system_tracker.ping_id);
                }
                _wut => panic!("Got non-echo request  ICMP4 packet"),
            },
            _wut => panic!("Got non-ICMP4 IP packet"),
        }
    }

    #[tokio::test]
    async fn test_ping_recv_state_machine_errors() {
        // setup test state
        let local_ip = IpAddr::from_str("192.168.1.34").unwrap();
        let local_mac = [1, 2, 3, 4, 5, 6];
        let gateway = IpAddr::from_str("192.168.1.1").unwrap();
        let gateway_mac = [0, 1, 2, 3, 4, 5];
        let mock_network_interface_state =
            NetworkInterfaceState::mk_mock("test".to_string(), Utc::now());
        let mut system_tracker = SystemTracker::mk_mock(mock_network_interface_state.clone());
        let key = system_tracker.make_gateway_ping_key_testing(&gateway, &local_ip);
        // manually hack in the state we want
        system_tracker.current_network_mut().gateways_ping.insert(
            gateway,
            NetworkGatewayPingState {
                key: key.clone(),
                next_seq: Wrapping(0),
                current_probe: None,
                local_mac,
                gateway_mac: Some(gateway_mac),
                historical_probes: VecDeque::new(),
            },
        );

        let now = Utc::now();
        // first test, if we receive a ping when not expecting one, do we bump the duplicate_ping counter?
        let ping = OwnedParsedPacket::try_from_timestamp(
            make_ping_icmp_echo_request(
                &local_ip,
                &gateway,
                local_mac,
                gateway_mac,
                system_tracker.ping_id,
                0,
                system_tracker.ping_payload.clone(),
            ),
            now,
        )
        .unwrap();
        assert_eq!(system_tracker.duplicate_ping.get_sum(), 0);
        system_tracker.handle_ping_recv(ping, key.clone());
        assert_eq!(system_tracker.duplicate_ping.get_sum(), 1);

        // setup ping state
        system_tracker.make_new_ping_state(&gateway).unwrap();
        // force send ping state in to prevent the actual ping from being sent (and simplify test)
        system_tracker
            .current_network_mut()
            .gateways_ping
            .get_mut(&gateway)
            .unwrap()
            .current_probe = Some(NetworkGatewayPingProbe {
            sent_time: None,
            recv_time: None,
            seqno: 0,
            dropped: false,
            ping_type: NetworkGatewayPingType::IcmpEcho,
        });

        // second test, if we receive a ping with wrong seq, do we bump the duplicate_ping counter?
        let ping = OwnedParsedPacket::try_from_timestamp(
            make_ping_icmp_echo_request(
                &local_ip,
                &gateway,
                local_mac,
                gateway_mac,
                system_tracker.ping_id,
                12345, // expecting zero
                system_tracker.ping_payload.clone(),
            ),
            now,
        )
        .unwrap();
        assert_eq!(system_tracker.out_of_sequence_ping.get_sum(), 0);
        system_tracker.handle_ping_recv(ping, key.clone());
        assert_eq!(system_tracker.out_of_sequence_ping.get_sum(), 1);

        // second test, if we receive a ping with wrong seq, do we bump the duplicate_ping counter?
        let ping = OwnedParsedPacket::try_from_timestamp(
            make_ping_icmp_echo_request(
                &local_ip,
                &gateway,
                local_mac,
                gateway_mac,
                system_tracker.ping_id,
                0,              // we expect seq 0
                vec![42u8; 64], // not the payload we expect
            ),
            now,
        )
        .unwrap();
        assert_eq!(system_tracker.ping_not_for_us.get_sum(), 0);
        system_tracker.handle_ping_recv(ping, key.clone());
        assert_eq!(system_tracker.ping_not_for_us.get_sum(), 1);

        // third, check what happens if we get a ping for an unknown gateway
        // rather than setting up everything for a new gateway, just remove this gateway's state
        system_tracker
            .current_network_mut()
            .gateways_ping
            .remove(&gateway);
        let ping = OwnedParsedPacket::try_from_timestamp(
            make_ping_icmp_echo_request(
                &local_ip,
                &gateway,
                local_mac,
                gateway_mac,
                system_tracker.ping_id,
                12345, // expecting zero
                system_tracker.ping_payload.clone(),
            ),
            now,
        )
        .unwrap();
        assert_eq!(system_tracker.unknown_gateway_ping.get_sum(), 0);
        system_tracker.handle_ping_recv(ping, key.clone());
        assert_eq!(system_tracker.unknown_gateway_ping.get_sum(), 1);
    }

    #[tokio::test]
    async fn test_ping_recv_state_machine_working() {
        // setup test state
        let local_ip = IpAddr::from_str("192.168.1.34").unwrap();
        let local_mac = [1, 2, 3, 4, 5, 6];
        let gateway = IpAddr::from_str("192.168.1.1").unwrap();
        let gateway_mac = [0, 1, 2, 3, 4, 5];
        let mut mock_network_interface_state =
            NetworkInterfaceState::mk_mock("test".to_string(), Utc::now());
        mock_network_interface_state.uuid = Uuid::from_u128(0x1234_0000_4242);
        let mut system_tracker = SystemTracker::mk_mock(mock_network_interface_state.clone());
        let key = system_tracker.make_gateway_ping_key_testing(&gateway, &local_ip);
        // manually hack in the state we want
        system_tracker.current_network_mut().gateways_ping.insert(
            gateway,
            NetworkGatewayPingState {
                key: key.clone(),
                next_seq: Wrapping(0),
                current_probe: Some(NetworkGatewayPingProbe {
                    sent_time: None,
                    recv_time: None,
                    seqno: 0,
                    dropped: false,
                    ping_type: NetworkGatewayPingType::IcmpEcho,
                }),
                local_mac,
                gateway_mac: Some(gateway_mac),
                historical_probes: VecDeque::new(),
            },
        );

        let now = Utc::now();
        // send an echo request and make sure we record the time
        let ping = OwnedParsedPacket::try_from_timestamp(
            make_ping_icmp_echo_request(
                &local_ip,
                &gateway,
                local_mac,
                gateway_mac,
                system_tracker.ping_id,
                0,
                system_tracker.ping_payload.clone(),
            ),
            now,
        )
        .unwrap();
        system_tracker.handle_ping_recv(ping, key.clone());
        // did we correctly record the outgoing time?
        assert_eq!(
            system_tracker
                .current_network()
                .gateways_ping
                .get(&gateway)
                .unwrap()
                .current_probe
                .as_ref()
                .unwrap()
                .sent_time
                .unwrap(),
            now
        );
        let rtt = Duration::from_millis(100);
        let reply_time = now + rtt;
        let ping_reply = OwnedParsedPacket::try_from_timestamp(
            make_ping_icmp_echo_reply(
                &gateway, // swap src + dst relative to the request
                &local_ip,
                gateway_mac,
                local_mac,
                system_tracker.ping_id,
                0,
                system_tracker.ping_payload.clone(),
            ),
            reply_time,
        )
        .unwrap();
        assert!(system_tracker
            .current_network()
            .gateways_ping
            .get(&gateway)
            .unwrap()
            .current_probe
            .is_some());
        assert_eq!(
            system_tracker
                .current_network()
                .gateways_ping
                .get(&gateway)
                .unwrap()
                .historical_probes
                .len(),
            0
        );
        system_tracker.handle_ping_recv(ping_reply, key.clone());
        // first, make sure the state machine saw both and thus moved the probe from
        // 'current' to 'historic'
        let ping_state = system_tracker
            .current_network()
            .gateways_ping
            .get(&gateway)
            .unwrap()
            .clone();
        assert!(ping_state.current_probe.is_none());
        assert_eq!(ping_state.historical_probes.len(), 1);
        let probe = ping_state.historical_probes.iter().last().unwrap();
        assert!(probe.sent_time.is_some());
        assert!(probe.recv_time.is_some());
        assert_eq!(probe.calc_rtt().unwrap().to_std().unwrap(), rtt);

        //
        // Now test exporting of ping data
        //
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        system_tracker.data_storage_client = Some(tx);
        let interface_state = system_tracker.current_network().clone();
        system_tracker
            .handle_update_network_state(interface_state.clone())
            .await;
        // no message should have been sent since not enough time has
        // passed since `last_ping_data_sent_time`
        assert_eq!(rx.try_recv().unwrap_err(), TryRecvError::Empty);

        // set the last_ping_data_sent_time in the past
        system_tracker.last_ping_data_sent_time =
            Instant::now() - Duration::from_millis(PING_DATA_EXPORT_INTERVAL_MS + 1);
        system_tracker
            .handle_update_network_state(interface_state.clone())
            .await;

        let msg = rx.try_recv().unwrap();
        match msg.skip_perf_check() {
            DataStorageMessage::StoreConnectionMeasurements { .. } => panic!(),
            DataStorageMessage::StoreNetworkInterfaceState { .. } => panic!(),
            DataStorageMessage::StoreDnsEntries { .. } => panic!(),
            DataStorageMessage::StoreGatewayPingData { ping_data } => {
                assert_eq!(ping_data.len(), 1);
                assert_eq!(
                    ping_data[0].network_interface_uuid,
                    Uuid::from_u128(0x1234_0000_4242)
                );
                assert_eq!(
                    ping_data[0].gateway_ip,
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
                );
                assert_eq!(ping_data[0].num_probes_sent, 1);
                assert_eq!(ping_data[0].num_responses_recv, 1);
                assert_eq!(ping_data[0].rtt_mean_ns, rtt.as_nanos() as u64);
                assert_eq!(ping_data[0].rtt_variance_ns, None);
                assert_eq!(ping_data[0].rtt_min_ns, rtt.as_nanos() as u64);
                assert_eq!(ping_data[0].rtt_p50_ns, rtt.as_nanos() as u64);
                assert_eq!(ping_data[0].rtt_p75_ns, rtt.as_nanos() as u64);
                assert_eq!(ping_data[0].rtt_p90_ns, rtt.as_nanos() as u64);
                assert_eq!(ping_data[0].rtt_p99_ns, rtt.as_nanos() as u64);
                assert_eq!(ping_data[0].rtt_max_ns, rtt.as_nanos() as u64);
            }
        }
        // there should be no more messages
        assert_eq!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
        // last_ping_data_sent should have been updated. We don't have an excat value we expect but
        // it should be reasonable close to "now"
        assert!(system_tracker.last_ping_data_sent_time.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    /// Given two routes with different gateways, can we correctly pick the best route
    /// given the hints for which interface to use
    async fn test_route_selection_by_hints() {
        // get the egress interface on the test machine
        let egress_device = lookup_egress_device().unwrap();
        // get all routes on the test machine
        let mut all_routes = net_route::Handle::new().unwrap().list().await.unwrap();
        // add an extra route just to make sure there's something to remove from the selection
        let bad_gateway = IpAddr::from_str("1.2.3.254").unwrap();
        all_routes.push(Route {
            destination: IpAddr::from_str("1.2.3.4").unwrap(),
            prefix: 0,
            gateway: Some(bad_gateway),
            ifindex: None,
            #[cfg(windows)]
            metric: None,
            #[cfg(windows)]
            luid: None,
            #[cfg(target_os = "linux")]
            table: 0,
        });

        let mut gateways = Vec::new();
        // do we correctly pick the gateway1 IP?
        SystemTracker::get_gateway_ip_by_all_hints(all_routes, Some(egress_device), &mut gateways);
        // make sure the bad_gateway isn't in our list
        let found_bad_gateway = gateways.iter().find(|gw_ip| **gw_ip == bad_gateway);
        assert_eq!(found_bad_gateway, None);
    }

    #[test]
    fn test_handle_no_routes() {
        let no_routes = Vec::new();
        let mut _ignore = Vec::new();
        // success is not panic!()'ing
        SystemTracker::get_gateway_ip_by_all_hints(no_routes, None, &mut _ignore);
    }

    #[test]
    fn test_aggregate_ping_state() {
        let contents = std::fs::read_to_string(test_dir(
            "libconntrack",
            "tests/network_interface_state--example.json",
        ))
        .unwrap();
        let network_interface_state =
            serde_json::from_str::<NetworkInterfaceState>(&contents).unwrap();
        // sanity checks
        assert_eq!(
            network_interface_state.uuid.hyphenated().to_string(),
            "e3dce6ad-055e-4b3e-b10e-5b36276519f8"
        );
        // The network_interface_state from the json files has two gateway
        let v6_gateway = IpAddr::from_str("fe80::ccb3:69ff:fea7:971f").unwrap();
        let v4_gateway = IpAddr::from_str("192.168.1.1").unwrap();
        assert_eq!(network_interface_state.gateways_ping.len(), 2);
        assert!(network_interface_state
            .gateways_ping
            .contains_key(&v4_gateway));
        assert!(network_interface_state
            .gateways_ping
            .contains_key(&v6_gateway));

        let agg_ping_list = aggregate_ping_state(&network_interface_state);
        println!("{}", serde_json::to_string_pretty(&agg_ping_list).unwrap());
        // The network_interface_state from the json files has two gateway
        // IPs. so we expect exactly two entries in the vector returned by
        // `aggregate_ping_data()`
        assert_eq!(agg_ping_list.len(), 2);
        for agg_ping in agg_ping_list {
            assert_eq!(
                agg_ping.network_interface_uuid.hyphenated().to_string(),
                "e3dce6ad-055e-4b3e-b10e-5b36276519f8"
            );
            match agg_ping.gateway_ip {
                ip if ip == v4_gateway => {
                    assert_eq!(agg_ping.num_probes_sent, 57);
                    assert_eq!(agg_ping.num_responses_recv, 57);
                }
                ip if ip == v6_gateway => {
                    assert_eq!(agg_ping.num_probes_sent, 57);
                    // two pings are marked as dropped
                    assert_eq!(agg_ping.num_responses_recv, 55);
                    /*  FYI: The raw RTT values for the 55 pings are:
                        2379000, 2301000, 2494000, 2222000, 3934000, 3825000, 2424000, 5250000, 2369000, 3754000, 4083000,
                        1186000, 4047000, 5268000, 5454000, 2865000, 3667000, 5599000, 2307000, 1808000, 1968000, 5163000,
                        2431000, 3800000, 2428000, 2744000, 2229000, 4076000, 2376000, 5424000, 3350000, 5519000, 2356000,
                        4278000, 2199000, 5504000, 5499000, 2341000, 2042000, 3905000, 2168000, 3184000, 2449000, 2025000,
                        2231000, 3882000, 5445000, 2687000, 2377000, 2510000, 2556000, 2250000, 4120000, 2446000, 5344000,
                    */
                    // Note, all these have been manually validated with numpy
                    // (but see caveat for variance)
                    assert_eq!(agg_ping.rtt_mean_ns, 3318945);
                    // numpy calculates the "population variance" while our code calculates
                    // the "sample variance". So I used: https://www.calculatorsoup.com/calculators/statistics/variance-calculator.php
                    // Another note: the variance from the only calculate and ours matches in the 8 most significant digits
                    // but then slighly diverges. Probably just floating point arithmetic.
                    assert_eq!(agg_ping.rtt_variance_ns, Some(1606098719192));
                    assert_eq!(agg_ping.rtt_min_ns, 1186000);
                    assert_eq!(agg_ping.rtt_p50_ns, 2687000);
                    assert_eq!(agg_ping.rtt_p75_ns, 4083000);
                    assert_eq!(agg_ping.rtt_p90_ns, 5445000);
                    assert_eq!(agg_ping.rtt_p99_ns, 5599000);
                    assert_eq!(agg_ping.rtt_max_ns, 5599000);
                }
                other => {
                    panic!("Unexpected gateway IP: {}", other);
                }
            }
        }
    }
}
