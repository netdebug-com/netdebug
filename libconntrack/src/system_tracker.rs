use std::{collections::VecDeque, error::Error, net::IpAddr, time::Duration};

use chrono::Utc;
use common_wasm::timeseries_stats::{
    ExportedStatRegistry, StatHandle, StatHandleDuration, StatType, Units,
};
use itertools::Itertools;
use libconntrack_wasm::NetworkInterfaceState;
use log::{debug, warn};
use pcap::{ConnectionStatus, IfFlags};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::{pcap::lookup_egress_device, send_or_log_async, utils::PerfMsgCheck};

/**
 * The System Tracker tracks the state of the system, e.g., what is the current default Gateway, active network interface, cpu load, mem info etc.
 * It keeps historical information for comparisons over time.
 *
 * TODO: use the magic rust crate to get the gateway IP and ping it periodically
 * TODO: collect mem and cpu info, particularly to understand if the desktop process is using too much mem/cpu
 */

pub enum SystemTrackerMessage {
    GetDebugInfo { tx: Sender<SystemDebugInfo> },
    UpdateNetworkDeviceState { device_state: NetworkInterfaceState },
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SystemDebugInfo {
    /// A history of active network devices.
    /// If there are multiple devices active at the same time, this is the one that connects to the gateway/default route
    /// A history of active network devices, ordered from oldest to newest
    /// historic_network.last() is the current active one.
    pub historic_network: Vec<NetworkInterfaceState>,
}

pub type SystemTrackerSender = Sender<PerfMsgCheck<SystemTrackerMessage>>;
pub type SystemTrackerReceiver = Receiver<PerfMsgCheck<SystemTrackerMessage>>;
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
        },
    }
}

pub struct SystemTracker {
    /// A history of active network devices, ordered from oldest to newest
    /// network_history.last() is the current active device; but use helper function
    /// SystemTracker::current_network()
    network_history: VecDeque<NetworkInterfaceState>,
    /// Max number of histoical network states to keep
    max_histories: usize,
    tx: SystemTrackerSender,
    rx: SystemTrackerReceiver,
    /// how much time between polling the network state
    device_update_period: Duration,
    /// counter for number of network device changes
    network_device_changes: StatHandle,
    /// counter for time spent in our rx queue
    queue_duration: StatHandleDuration,
}

impl SystemTracker {
    pub async fn spawn(
        max_queue: usize,
        update_period: Duration,
        max_histories: usize,
        stats_registry: ExportedStatRegistry,
    ) -> SystemTrackerSender {
        let (tx, rx) = channel(max_queue);
        let interface = SystemTracker::snapshot_current_network_state().await;
        let system_tracker = SystemTracker::new(
            tx.clone(),
            rx,
            update_period,
            interface,
            stats_registry,
            max_histories,
        );
        tokio::spawn(async move {
            system_tracker.rx_loop().await;
        });

        tx
    }

    fn new(
        tx: Sender<PerfMsgCheck<SystemTrackerMessage>>,
        rx: Receiver<PerfMsgCheck<SystemTrackerMessage>>,
        update_period: Duration,
        current_network: NetworkInterfaceState,
        stats_registry: ExportedStatRegistry,
        max_histories: usize,
    ) -> SystemTracker {
        SystemTracker {
            network_history: VecDeque::from([current_network]),
            tx,
            rx,
            network_device_changes: stats_registry.add_stat(
                "network_device_changes",
                Units::None,
                [StatType::COUNT],
            ),
            device_update_period: update_period,
            queue_duration: stats_registry.add_duration_stat(
                "queue_duration",
                Units::Milliseconds,
                [StatType::COUNT, StatType::AVG],
            ),
            max_histories,
        }
    }

    #[cfg(test)]
    fn mk_mock(network_device: NetworkInterfaceState) -> SystemTracker {
        let (tx, rx) = channel(10);
        SystemTracker::new(
            tx,
            rx,
            Duration::from_millis(100),
            network_device,
            ExportedStatRegistry::new("testing", std::time::Instant::now()),
            10,
        )
    }

    async fn rx_loop(mut self) {
        SystemTracker::spawn_network_device_state_watcher(
            self.tx.clone(),
            self.device_update_period,
        );
        while let Some(msg) = self.rx.recv().await {
            let msg =
                msg.perf_check_get_with_stats("SystemTracker::rx_loop", &mut self.queue_duration);
            use SystemTrackerMessage::*;
            match msg {
                GetDebugInfo { tx } => {
                    if let Err(e) = tx
                        .send(SystemDebugInfo {
                            historic_network: Vec::from(self.network_history.clone()),
                        })
                        .await
                    {
                        warn!("Error sending SystemDebugInfo back to caller: {}", e);
                    }
                }
                UpdateNetworkDeviceState { device_state } => {
                    self.handle_update_network_state(device_state).await;
                }
            }
        }
        warn!("SystemTracker exiting...");
    }

    pub fn get_tx(&self) -> SystemTrackerSender {
        self.tx.clone()
    }

    fn current_network(&self) -> &NetworkInterfaceState {
        // unwrap is ok b/c there will always be at least one
        self.network_history.iter().last().unwrap()
    }

    fn current_network_mut(&mut self) -> &mut NetworkInterfaceState {
        // unwrap is ok b/c there will always be at least one
        self.network_history.iter_mut().last().unwrap()
    }

    /**
     * Handle a potential network state update.
     *
     * Return true if state was updated, false if no update was needed
     */
    async fn handle_update_network_state(
        &mut self,
        interface_state: NetworkInterfaceState,
    ) -> bool {
        if !self.current_network().has_state_changed(&interface_state) {
            debug!(
                "Ignoring network state update - unchanged! {:?}",
                interface_state
            );
            return false; // no state update
        }
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
        true
    }

    /**
     * Spawn a task that just periodically queries the network device state and sends an update message
     * to the SystemTracker.  Do this in a separate task in case it blocks/has random OS delays.  Who knows
     * how pcap implements this on all of the various platforms.  If we cared about super-precise periodicity,
     * we would track the time it took to process this and subtract it from the update_period on each run,
     * but that level of precision isn't needed.
     *
     * Ideally we could subscribe to OS-specific push updates rather than periodic pulls like this, but this
     * seems more portable.  TODO: investigate if there are other rust crate magics that solve this for us.
     */
    fn spawn_network_device_state_watcher(
        system_tracker_tx: SystemTrackerSender,
        update_period: Duration,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(update_period).await;
                let device_state = SystemTracker::snapshot_current_network_state().await;
                // send the update whether it's changed or not; let the other side figure it out
                send_or_log_async!(
                    system_tracker_tx,
                    "SystemTracker: network device state watcher",
                    SystemTrackerMessage::UpdateNetworkDeviceState { device_state }
                )
                .await;
            }
        });
    }

    pub async fn snapshot_current_network_state() -> NetworkInterfaceState {
        let gateways = match SystemTracker::get_default_gateways().await {
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
    pub async fn get_default_gateways() -> std::io::Result<Vec<IpAddr>> {
        // this magic crate claims to list the routing table on MacOs/Linux/Windows... let's see
        let handle = net_route::Handle::new()?;
        // we could do this whole function on one statement because Rust is Beautiful, but that seems like too much
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
}

#[cfg(test)]
mod test {
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
    async fn test_get_default_routes() {
        let gateways = SystemTracker::get_default_gateways().await.unwrap();
        for gw in &gateways {
            println!("Found a default gw: {}", gw);
        }
        assert_ne!(gateways.len(), 0);
    }
}
