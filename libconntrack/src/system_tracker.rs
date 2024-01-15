use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use common_wasm::timeseries_stats::{ExportedStatRegistry, StatHandle, StatType, Units};
use itertools::Itertools;
use libconntrack_wasm::{
    ConnectionKey, NetworkGatewayPingProbe, NetworkGatewayPingState, NetworkInterfaceState,
};
use log::{debug, warn};
use pcap::{ConnectionStatus, IfFlags};
use tokio::sync::{mpsc::Sender, RwLock};

use crate::{
    connection::ConnectionUpdateListener,
    connection_tracker::{ConnectionTrackerMsg, ConnectionTrackerSender},
    pcap::lookup_egress_device,
    prober::ProbeMessage,
    send_or_log_async,
    utils::{remote_ip_to_local, PerfMsgCheck},
};

/**
 * The System Tracker tracks the state of the system, e.g., what is the current default Gateway, active network interface, cpu load, mem info etc.
 * It keeps historical information for comparisons over time.
 *
 * TODO: use the magic rust crate to get the gateway IP and ping it periodically
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
    pcap_dev: Result<pcap::Device, Box<dyn Error>>,
    gateways: Vec<IpAddr>, // If known
    comment: String,
) -> NetworkInterfaceState {
    match pcap_dev {
        Ok(pcap_dev) => NetworkInterfaceState {
            gateways,
            interface_name: Some(pcap_dev.name.clone()),
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
    /// The ID we put into all of our ping packets to mark it from us, just our $PID
    ping_id: u16,
    /// counter for number of network device changes
    network_device_changes: StatHandle,
    /// A pointer to our prober task that manages rate limiting, etc.
    prober_tx: Sender<PerfMsgCheck<ProbeMessage>>,
}

impl SystemTracker {
    pub async fn new(
        stats_registry: ExportedStatRegistry,
        max_histories: usize,
        max_pings_per_gateway: usize,
        connection_tracker: ConnectionTrackerSender,
        prober_tx: Sender<PerfMsgCheck<ProbeMessage>>,
    ) -> SystemTracker {
        let current_network = SystemTracker::snapshot_current_network_state().await;
        SystemTracker::new_with_network_state(
            stats_registry,
            max_histories,
            max_pings_per_gateway,
            current_network,
            connection_tracker,
            prober_tx,
        )
    }
    pub fn new_with_network_state(
        stats_registry: ExportedStatRegistry,
        max_histories: usize,
        max_pings_per_gateway: usize,
        current_network: NetworkInterfaceState,
        connection_tracker: ConnectionTrackerSender,
        prober_tx: Sender<PerfMsgCheck<ProbeMessage>>,
    ) -> SystemTracker {
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
            ping_id: std::process::id() as u16,
            prober_tx,
        }
    }

    #[cfg(test)]
    fn mk_mock(network_device: NetworkInterfaceState) -> SystemTracker {
        use tokio::sync::mpsc::channel;

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
        )
    }

    pub fn current_network(&self) -> &NetworkInterfaceState {
        // unwrap is ok b/c there will always be at least one
        self.network_history.iter().last().unwrap()
    }

    pub fn current_network_mut(&mut self) -> &mut NetworkInterfaceState {
        // unwrap is ok b/c there will always be at least one
        self.network_history.iter_mut().last().unwrap()
    }

    /**
     * Handle a potential network state update.
     *
     * Return true if state was updated, false if no update was needed
     *
     * Whether the state has changed or not, send a fresh round of pings to each gateway.
     *
     * NOTE: this function is called every ```update_period``` from the ```SystemTracker::network_update_watcher```
     * task, e.g., every 500ms
     */
    pub async fn handle_update_network_state(
        &mut self,
        interface_state: NetworkInterfaceState,
    ) -> bool {
        let changed = if self.current_network().has_state_changed(&interface_state) {
            self.current_network_mut().end_time = Some(Utc::now());
            let old_state = self.current_network().clone();
            self.network_history.push_back(interface_state.clone());
            while self.network_history.len() >= self.max_histories {
                self.network_history.pop_front();
            }
            self.network_device_changes.bump();
            warn!(
                "Network state change from {:?} to {:?}",
                old_state, interface_state
            );
            // TODO!  Unsub from old conntrack state
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
            self.send_next_ping(gateway).await;
        }
        changed
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
        tokio::spawn(async move {
            SystemTracker::ping_listener(system_tracker_clone).await;
        });
        // task #1
        tokio::spawn(async move {
            SystemTracker::network_change_watcher(system_tracker, update_period).await;
        });
    }

    pub async fn snapshot_current_network_state() -> NetworkInterfaceState {
        let gateways = match SystemTracker::get_default_gateways_async().await {
            Ok(g) => g,
            Err(e) => {
                warn!(
                    "Failed to collect the network route table !? :: {} - trying again later",
                    e
                );
                Vec::new()
            }
        };
        network_interface_state_from_pcap_device(
            lookup_egress_device(),
            gateways,
            "Update".to_string(),
        )
    }

    /// Get all of the default routes in the system in an OS-independent way
    pub async fn get_default_gateways_async() -> std::io::Result<Vec<IpAddr>> {
        // this magic crate claims to list the routing table on MacOs/Linux/Windows... let's see
        let handle = net_route::Handle::new()?;
        // don't use the handle.default_route() function as it only returns the first route it finds where we
        // want all of them (v4 and v6)
        Ok(handle
            .list()
            .await?
            .into_iter()
            // needs to have a prefix of 0 and a valid gateway to be considered a 'default' route
            .filter_map(|r| if r.prefix == 0 { r.gateway } else { None })
            .collect())
    }

    async fn ping_listener(_system_tracker_clone: Arc<RwLock<SystemTracker>>) {
        // todo!()
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
    async fn send_next_ping(&mut self, gateway: &IpAddr) {
        if !self.current_network().gateways_ping.contains_key(gateway) {
            self.make_new_ping_state(gateway).await;
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
        let seqno = state.next_seq;
        state.next_seq += 1;
        state.current_probe = Some(NetworkGatewayPingProbe::new(seqno));
        let key = state.key.clone();
        send_or_log_async!(
            self.prober_tx,
            "send ping",
            ProbeMessage::SendPing {
                local_mac: [1, 2, 3, 4, 5, 6], // TODO! Look up local mac address
                local_ip: key.local_ip,
                remote_mac: None, // TODO! Add ArpPing functionality to lookup remote mac
                remote_ip: key.remote_ip,
                id: self.ping_id,
                seq: seqno
            }
        )
        .await;
    }

    async fn make_new_ping_state(&mut self, gateway: &IpAddr) {
        // need to populate first time state and subscribe to ConnectionTracker updates
        let source_ip = remote_ip_to_local(*gateway).unwrap();
        let key = ConnectionKey::make_icmp_echo_key(source_ip, *gateway, self.ping_id);
        // subscribe to ping flow from ConnectionTracker, if it's defined
        if let Some(ping_listener) = &self.ping_listener_tx {
            send_or_log_async!(
                self.connection_tracker.clone(),
                "SystemTracker::send_next_ping",
                ConnectionTrackerMsg::AddConnectionUpdateListener {
                    desc: PING_LISTENER_DESC.to_string(),
                    tx: ping_listener.clone(),
                    key: key.clone(),
                }
            )
            .await;
        }
        let state = NetworkGatewayPingState {
            key,
            next_seq: 0,
            current_probe: None,
            historical_probes: VecDeque::new(),
        };
        self.current_network_mut()
            .gateways_ping
            .insert(*gateway, state);
    }
}

const PING_LISTENER_DESC: &str = "SystemTracker::ping_listener";

#[cfg(test)]
mod test {
    use std::{collections::HashSet, str::FromStr};

    use etherparse::{Icmpv4Type, TransportHeader};
    use tokio::sync::mpsc::channel;

    use crate::{pcap::MockRawSocketProber, utils::etherparse_ipheaders2ipaddr};

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
        intf.start_time = now + Duration::from_secs(1);
        assert!(!system_tracker.handle_update_network_state(intf).await);
        let intf2 =
            NetworkInterfaceState::mk_mock("mock dev2".to_string(), now + Duration::from_secs(2));
        assert!(system_tracker.handle_update_network_state(intf2).await);
    }

    /**
     * Assume what ever system we're running the test on has a valid network with at least
     * one default route
     */
    #[tokio::test]
    async fn test_get_default_routes_async() {
        let gateways = SystemTracker::get_default_gateways_async().await.unwrap();
        for gw in &gateways {
            println!("Found a default gw: {}", gw);
        }
        assert_ne!(gateways.len(), 0);
    }

    /****
     * Startup a Prober task and a SystemTracker and verify that we see outgoing pings and
     * that we get the right listener call backs
     */
    #[tokio::test]
    async fn test_system_tracker_gateway_ping() {
        let mut mock_writer = MockRawSocketProber::default();
        let gateway = IpAddr::from_str("192.168.1.1").unwrap();
        // what IP would the test machine use to connect to this gateway?
        let local_ip = remote_ip_to_local(gateway).unwrap();
        let mut mock_connection_tracker =
            crate::connection_tracker::test::mk_mock_connection_tracker(HashSet::from([local_ip]));
        let mut mock_network_interface_state =
            NetworkInterfaceState::mk_mock("test".to_string(), Utc::now());
        let (ping_listener_tx, mut ping_listener_rx) = channel(2);
        let mut system_tracker = SystemTracker::mk_mock(mock_network_interface_state.clone());
        system_tracker.connection_tracker = mock_connection_tracker.get_tx();
        system_tracker.prober_tx = mock_writer.tx.clone(); // put the mock prober into place
        system_tracker.ping_listener_tx = Some(ping_listener_tx); // put the ping listener into place

        // now make it appear like we found a new gateway
        mock_network_interface_state.gateways.push(gateway);
        // this should setup state for a ping including subscribing to the connection updates
        system_tracker
            .handle_update_network_state(mock_network_interface_state)
            .await;
        // verify the ping state
        let ping_state = system_tracker
            .current_network()
            .gateways_ping
            .get(&gateway)
            .unwrap();
        // verify the subscription
        mock_connection_tracker.flush_rx_loop().await; // let the conntrack process the subscription msg
        assert!(mock_connection_tracker
            .update_listeners
            .get(&ping_state.key)
            .is_some());
        let current_probe = ping_state.current_probe.as_ref().unwrap();
        assert_eq!(current_probe.seqno, 0);
        // this should queue a bunch of messages to the connection tracker
        // to send an update to the ping listenner
        mock_writer.redirect_into_connection_tracker(&mut mock_connection_tracker);
        // did we get an update!? Is it a correctly formated ping?
        let (update_pkt, key) = ping_listener_rx.recv().await.unwrap();
        assert_eq!(ping_state.key, key);
        let (ping_src_ip, ping_dst_ip) = etherparse_ipheaders2ipaddr(&update_pkt.ip).unwrap();
        assert_eq!(ping_src_ip, local_ip);
        assert_eq!(ping_dst_ip, gateway);
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
}
