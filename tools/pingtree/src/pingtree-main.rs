use libconntrack_wasm::NetworkInterfaceState;
use log::{info, warn};
use mac_address::MacAddress;
use std::{
    collections::HashSet,
    error::Error,
    net::IpAddr,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc::{Receiver, Sender};

use libconntrack::{
    connection_tracker::ConnectionTrackerMsg,
    neighbor_cache::{LookupMacByIpResult, NeighborCache},
    owned_packet::ConnectionKeyError,
    pcap::{pcap_find_all_local_addrs, run_blocking_pcap_loop_in_thread},
    prober::{spawn_raw_prober, ProbeMessage},
    system_tracker::SystemTracker,
    utils::{remote_ip_to_local, PerfMsgCheck},
};

const NON_DNS_PAYLOAD_LEN: usize = 65_535;

pub async fn rx_loop(
    mut pkt_rx: Receiver<PerfMsgCheck<ConnectionTrackerMsg>>,
    local_addrs: HashSet<IpAddr>,
    neighbor_cache: Arc<Mutex<NeighborCache<'_>>>,
) {
    while let Some(msg) = pkt_rx
        .recv()
        .await
        .map(|msg| msg.perf_check_get("from pkt_rx"))
    {
        match msg {
            ConnectionTrackerMsg::Pkt(pkt) => match pkt.to_connection_key(&local_addrs) {
                Ok((_key, _src_is_local)) => todo!(),
                Err(ConnectionKeyError::Arp) => {
                    if let Err(e) = neighbor_cache.lock().unwrap().process_arp_packet(pkt) {
                        warn!("Ignoring failed to parse Arp packet: {}", e);
                    }
                }
                Err(ConnectionKeyError::NdpNeighbor) => {
                    if let Err(e) = neighbor_cache.lock().unwrap().process_ndp_packet(pkt) {
                        warn!("Ignoring failed to parse NDP packet: {}", e);
                    }
                }
                _ => (),
            },
            _ => panic!("Unexpected Message"),
        }
    }
}

struct GatewayLookup<'a> {
    pub v4_gateway: Option<(IpAddr, MacAddress)>,
    pub v6_gateway: Option<(IpAddr, MacAddress)>,
    neighbor_cache: Arc<Mutex<NeighborCache<'a>>>,
    prober_tx: Sender<PerfMsgCheck<ProbeMessage>>,
    local_mac: MacAddress,
    interface_state: NetworkInterfaceState,
}

impl<'a> GatewayLookup<'a> {
    pub fn new(
        neighbor_cache: Arc<Mutex<NeighborCache<'a>>>,
        prober_tx: Sender<PerfMsgCheck<ProbeMessage>>,
        interface_state: NetworkInterfaceState,
    ) -> Self {
        let local_mac =
            mac_address::mac_address_by_name(interface_state.interface_name.as_ref().unwrap())
                .unwrap()
                .unwrap();
        Self {
            v4_gateway: None,
            v6_gateway: None,
            neighbor_cache,
            interface_state,
            prober_tx,
            local_mac,
        }
    }

    pub async fn do_lookup(&mut self) {
        for gw in self.interface_state.gateways.clone() {
            match gw {
                IpAddr::V4(ip) => {
                    if let Some(old_v4_gateway) = self.v4_gateway {
                        panic!(
                            "More than one IPv4 gateway IP: {} and {} -- giving up",
                            old_v4_gateway.0, ip
                        );
                    }
                    self.v4_gateway = Some(self.lookup_mac_by_ip(gw).await);
                }
                IpAddr::V6(ip) => {
                    if let Some(old_v6_gateway) = self.v6_gateway {
                        panic!(
                            "More than one IPv6 gateway IP: {} and {} -- giving up",
                            old_v6_gateway.0, ip
                        );
                    }
                    self.v6_gateway = Some(self.lookup_mac_by_ip(gw).await);
                }
            }
        }
    }

    async fn lookup_mac_by_ip(&mut self, gateway_ip: IpAddr) -> (IpAddr, MacAddress) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let local_ip = remote_ip_to_local(gateway_ip).unwrap();
        info!("Looking up Mac for IP: {}", gateway_ip);
        match self
            .neighbor_cache
            .lock()
            .unwrap()
            .lookup_mac_by_ip_pending(String::default(), &gateway_ip, tx)
        {
            LookupMacByIpResult::Found => (),
            LookupMacByIpResult::NotFound => {
                info!("Sending ARP/NDP for IP: {}", gateway_ip);
                self.prober_tx
                    .try_send(PerfMsgCheck::new(
                        libconntrack::prober::ProbeMessage::SendIpLookup {
                            local_mac: self.local_mac.bytes(),
                            local_ip,
                            target_ip: gateway_ip,
                        },
                    ))
                    .unwrap();
            }
        }
        rx.recv().await.unwrap()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    common::init::netdebug_init();
    println!("Hello, world!");

    let network_state = SystemTracker::snapshot_current_network_state().await;
    println!(
        "Got network interface state. Egress iface `{:?}`, gateways: {:?}",
        network_state.interface_name, network_state.gateways
    );

    let local_addrs = pcap_find_all_local_addrs()?;
    let raw_sock = libconntrack::pcap::bind_writable_pcap(local_addrs.clone());
    let prober_tx = spawn_raw_prober(raw_sock, 4096);
    let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel(4096);

    let _handle = run_blocking_pcap_loop_in_thread(
        network_state.interface_name.clone().unwrap(),
        Some("icmp or icmp6 or arp".to_owned()),
        pkt_tx.clone(),
        NON_DNS_PAYLOAD_LEN,
        None,
        None,
    );
    let neighbor_cache = Arc::new(Mutex::new(NeighborCache::new(4096)));

    let neighbor_cache_cloned = neighbor_cache.clone();
    tokio::spawn(async move {
        info!("Starting rx_loop");
        rx_loop(pkt_rx, local_addrs, neighbor_cache_cloned).await;
        info!("rx_loop terminated");
    });

    let mut gw_lookup =
        GatewayLookup::new(neighbor_cache.clone(), prober_tx.clone(), network_state);
    gw_lookup.do_lookup().await;

    info!(
        "Looked up Gateways. V4: {:?} -- V6: {:?}",
        gw_lookup.v4_gateway, gw_lookup.v6_gateway
    );

    Ok(())
}
