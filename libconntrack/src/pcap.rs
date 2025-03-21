use etherparse::TransportHeader;
use pcap::{ConnectionStatus, Error as PcapError};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::thread::JoinHandle;
use std::{collections::HashMap, error::Error};

use crate::{
    connection_tracker::{ConnectionTrackerMsg, ConnectionTrackerSender},
    perf_check,
    utils::PerfMsgCheck,
};
#[cfg(not(windows))]
use futures_util::StreamExt;
use itertools::Itertools;
use log::{debug, error, info, warn};
use pcap::Capture;

use crate::owned_packet::OwnedParsedPacket;
struct PacketParserCodec {}

const PCAP_INTERFACE_MONITOR_INTERVAL_MS: u64 = 1000;

impl pcap::PacketCodec for PacketParserCodec {
    type Item = Box<OwnedParsedPacket>;

    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(packet.data);
        if let Ok(pkt) = parsed {
            Box::new(OwnedParsedPacket::new(pkt, *packet.header))
        } else {
            warn!("Failed to parse packet {:?} - punting", packet.data);
            let fake_pkt = etherparse::PacketHeaders {
                link: None,
                vlan: None,
                ip: None,
                transport: None,
                payload: packet.data,
            };
            Box::new(OwnedParsedPacket::new(fake_pkt, *packet.header))
        }
    }
}

/**
 * Main control loop for reading raw packets, currently from libpcap
 *
 * Use this to punt packets to the connection ConnectionTracker
 *
 * Store connection_tracker into the context so other agents can talk to it
 *
 * This is setup to have many parallel connection trackers to achieve
 * parallelism with the hash/sloppy_hash(), but it's not implemented
 * yet.
 *
 * ONLY works on Linux/MacOS - need to do something different for windows
 */

#[cfg(not(windows))]
pub async fn start_pcap_stream(
    device: pcap::Device,
    local_tcp_port: u16,
    tx: ConnectionTrackerSender,
) -> Result<(), Box<dyn Error>> {
    info!("Starting pcap capture on {}", &device.name);
    let mut capture = Capture::from_device(device)?
        .buffer_size(64_000_000) // try to prevent any packet loss
        .timeout(1000)
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    // only capture/probe traffic to the webserver
    let filter_rule = format!("tcp port {} or icmp or icmp6", local_tcp_port);
    info!("Applying pcap filter '{}'", filter_rule);
    capture.filter(filter_rule.as_str(), true)?;
    let stream = capture.stream(PacketParserCodec {})?;
    stream
        .for_each(|pkt| {
            // NOTE: this closure is intentionally sync and thus we can't call await in it
            // making it async causes a bunch of compliler problems I haven't figured out how to fix
            match pkt {
                Ok(pkt) => {
                    let _hash = pkt.sloppy_hash();
                    // TODO: use this hash to map to 256 parallel ConnectionTrackers for parallelism
                    if let Err(e) = tx.try_send(PerfMsgCheck::new(ConnectionTrackerMsg::Pkt(pkt))) {
                        warn!("Failed to send to the ConnectionTracker: {}", e);
                    }
                }
                Err(e) => {
                    warn!("start_pcap_stream got error: {} - exiting", e);
                }
            }
            futures::future::ready(()) // TODO: how do we return an error to stop the stream?
        })
        .await;

    Ok(())
}

/**
 * STUB!
 *
 * Iterate through the ethernet interfaces and return the ones that either (1)
 * were specified on the command line or (2) seem alive/active/worth listening
 * to.
 *
 * Right now, just return the one with the default route if not specified.
 * The API supports multiple interfaces to future proof for VPNs, etc.
 */

pub fn find_interesting_pcap_interfaces(
    device_name: &Option<String>,
) -> Result<Vec<pcap::Device>, Box<dyn Error>> {
    let device = match device_name {
        Some(name) => lookup_pcap_device_by_name(name)?,
        None => lookup_egress_device()?,
    };

    Ok(vec![device])
}

pub struct PcapMonitorOptions {
    pub filter_rule: Option<String>,
    pub connection_tracker_tx: ConnectionTrackerSender,
    pub payload_len_for_non_dns: usize,
    pub startup_delay: Option<chrono::Duration>,
    pub stats_polling_frequency: Option<chrono::Duration>,
}

/// Start an OS-level thread to spawn pcap threads for all active interfaces
/// Return a channel, that when someone sends a 'true' message to it, recheck all
/// of the threads for new/dynamic interfaces
pub fn spawn_pcap_monitor_all_interfaces(options: PcapMonitorOptions) {
    std::thread::spawn(move || {
        if let Err(e) = pcap_monitor_all_interfaces(options) {
            panic!("pcap_monitor_all_interfaces returned: {}", e);
        }
    });
}

/// Blocking loop to monitor the list of interfaces and keep an active
/// pcap thread for each one.
/// Update the list on a channel signal
fn pcap_monitor_all_interfaces(options: PcapMonitorOptions) -> Result<(), pcap::Error> {
    let mut device_thread_handle_map: HashMap<String, JoinHandle<Result<(), PcapLoopError>>> =
        HashMap::new();
    loop {
        // for each previously existing pcap thread, find the ones that have finished
        let dead_threads = device_thread_handle_map
            .iter()
            .filter_map(|(dev, handle)| {
                if handle.is_finished() {
                    Some(dev)
                } else {
                    None
                }
            })
            .cloned()
            .collect::<Vec<String>>();
        // clean up any dead threads
        for dev in dead_threads {
            // unwrap is ok, b/c we just verified each dev was in the list
            let join_handle = device_thread_handle_map.remove(&dev).unwrap();
            // Join only returns an Err() if the child thread panic'ed. That
            // can't happen in our code since we abort() on panic so we
            // unwrap the join() and then match on the contained result

            match join_handle.join().unwrap() {
                Err(PcapLoopError::OpenDevice(e)) => {
                    // TODO: instead of panic'ing, print error and exit cleanly
                    panic!("Failed to open pcap device {}: {}. Exiting", dev, e);
                }
                Err(PcapLoopError::Loop(e)) => {
                    warn!("Pcap thread for device {} exited with {}", dev, e);
                }
                Ok(()) => {
                    info!("Pcap thread for device {} exited cleanly", dev);
                }
            }
        }
        // for each active device, make sure we've launched a pcap thread for it
        // and record all local IPs.
        let mut local_addr = HashSet::new();
        for dev in pcap::Device::list()? {
            for addr in &dev.addresses {
                local_addr.insert(addr.addr);
            }
            // start a new pcap thread if not already setup and is connected
            if dev.flags.connection_status == ConnectionStatus::Connected
                && !device_thread_handle_map.contains_key(&dev.name)
            {
                // NOTE: this function will do lots of logging, no need to add to it
                let join_handle = run_blocking_pcap_loop_in_thread(
                    dev.name.clone(),
                    options.filter_rule.clone(),
                    options.connection_tracker_tx.clone(),
                    options.payload_len_for_non_dns,
                    options.startup_delay,
                    options.stats_polling_frequency,
                );
                device_thread_handle_map.insert(dev.name.clone(), join_handle);
            }
        }
        let _ = options.connection_tracker_tx.try_send(PerfMsgCheck::new(
            ConnectionTrackerMsg::UpdateLocalAddr { local_addr },
        ));
        std::thread::sleep(std::time::Duration::from_millis(
            PCAP_INTERFACE_MONITOR_INTERVAL_MS,
        ));
    }
}

pub fn pcap_find_all_local_addrs() -> Result<HashSet<IpAddr>, pcap::Error> {
    let mut local_addrs = HashSet::new();
    for dev in pcap::Device::list()? {
        for addr in dev.addresses {
            local_addrs.insert(addr.addr);
        }
    }
    Ok(local_addrs)
}

// cannot create a const chrono::Duration at compile time, so use seconds instead
const DEFAULT_STATS_POLLING_FREQUENCY_SECONDS: u64 = 5;

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum PcapLoopError {
    #[error("Error opening and starting capture")]
    OpenDevice(pcap::Error),
    #[error("Error during pcap loop capture")]
    Loop(pcap::Error),
}

pub fn blocking_pcap_loop(
    device_name: String,
    filter_rule: Option<String>,
    tx: ConnectionTrackerSender,
    payload_len_for_non_dns: usize,
    stats_polling_frequency: Option<chrono::Duration>,
) -> Result<(), PcapLoopError> {
    // small hack: create and immediately call a lambda that initializes the
    // device/capture. We do this since we use `?` in a couple of places
    // the capture and try-blocks are not yet stable.
    let capture_res = (|| {
        let device = lookup_pcap_device_by_name(&device_name)?;
        info!(
            "Starting pcap capture on {} ({:?})",
            &device.name, &device.desc
        );
        let mut capture = Capture::from_device(device)?
            .buffer_size(64_000_000) // try to prevent any packet loss
            .immediate_mode(true)
            .open()?;
        // only capture/probe traffic to the webserver
        if let Some(filter_rule) = filter_rule {
            info!("Applying pcap filter '{}'", filter_rule);
            capture.filter(filter_rule.as_str(), true)?;
        }

        // panic if not Ethernet for now (see #344)
        if capture.get_datalink() != pcap::Linktype::ETHERNET {
            let datalink = capture.get_datalink();
            return Err(pcap::Error::PcapError(format!(
                "Unsupported link capture type - only support ethernet:  {:?} ({:?}) - {:?}",
                datalink.get_name(),
                datalink,
                datalink.get_description()
            )));
        }
        Ok(capture)
    })();
    let mut capture = match capture_res {
        Ok(capture) => capture,
        Err(e) => {
            error!("Failed to open and init pcap device: {}", e);
            return Err(PcapLoopError::OpenDevice(e));
        }
    };
    let mut last_stats: Option<pcap::Stat> = None;
    let mut next_stats_time = 0u64;
    let stats_polling_frequency = match stats_polling_frequency {
        Some(t) => t.num_seconds() as u64,
        None => DEFAULT_STATS_POLLING_FREQUENCY_SECONDS,
    };
    let throttle_threshold = tx.max_capacity() / 2; // start throttling packet loss when we exceed 50% capacity
    info!(
        "Setting packet throttling threashold to {} - 50% of {}",
        throttle_threshold,
        tx.max_capacity()
    );
    loop {
        match capture.next_packet() {
            Ok(pkt) => {
                let pkt_timestamp = pkt.header.ts; // save this for stats checking
                let parsed = etherparse::PacketHeaders::from_ethernet_slice(pkt.data);
                if let Ok(parsed_pkt) = parsed {
                    let mut parsed_packet =
                        Box::new(OwnedParsedPacket::new(parsed_pkt, *pkt.header));
                    let mut should_truncate = true;
                    if let Some(TransportHeader::Udp(ref udph)) = parsed_packet.transport {
                        if udph.source_port == 53
                            || udph.destination_port == 53
                            || udph.source_port == 5353
                            || udph.destination_port == 5353
                        {
                            should_truncate = false;
                        }
                    }
                    if should_truncate {
                        parsed_packet.truncate_payload(payload_len_for_non_dns);
                    }

                    let _hash = parsed_packet.sloppy_hash();
                    // TODO: use this hash to map to 256 parallel ConnectionTrackers for parallelism
                    if tx.capacity() < throttle_threshold {
                        warn!("ConnectionTrackerSender exceeding 50% capacity: throttling pkts: {} > {}", tx.capacity(), throttle_threshold);
                        continue;
                    }
                    if let Err(e) =
                        tx.try_send(PerfMsgCheck::new(ConnectionTrackerMsg::Pkt(parsed_packet)))
                    {
                        warn!(
                            "Tried to enqueue to the ConnectionTrackerSender and failed: {}",
                            e
                        );
                    }
                }
                // periodically check the pcap stats to see if we're losing packets
                // this is potentially a huge perf impact if we naively do gettimeofday() with each packet rx
                // so instead use the pcap header timestamps instead.  Don't bother with the usecs math,
                // because we only care about seconds-level precison, just check the seconds field
                if pkt_timestamp.tv_sec as u64 > next_stats_time {
                    last_stats = check_pcap_stats(&mut capture, last_stats);
                    // update our estimate based on how many packets we did see in the interval
                    // and cut in half just to be conservative, e.g., get the stats twice as
                    // often as our estimator suggests just so we don't go too long during an idle period
                    next_stats_time = pkt_timestamp.tv_sec as u64 + stats_polling_frequency;
                }
            }
            Err(e) => {
                match e {
                    pcap::Error::TimeoutExpired => continue, // just keep going if we get a timeout
                    _ => {
                        // die on any other error
                        warn!("start_pcap_stream got error: {} - exiting", e);
                        return Err(PcapLoopError::Loop(e));
                    }
                }
            }
        }
    }
    // never returns unless there's an error
}

pub fn run_blocking_pcap_loop_in_thread(
    device_name: String,
    filter_rule: Option<String>,
    tx: ConnectionTrackerSender,
    payload_len_for_non_dns: usize,
    // delay starting the loop for that long to give other threads/tasks a chance to start up
    // before starting the packet capture
    startup_delay: Option<chrono::Duration>,
    stats_polling_frequency: Option<chrono::Duration>,
) -> std::thread::JoinHandle<Result<(), PcapLoopError>> {
    std::thread::spawn(move || {
        if let Some(delay) = startup_delay {
            std::thread::sleep(delay.to_std().unwrap());
        }
        blocking_pcap_loop(
            device_name,
            filter_rule,
            tx,
            payload_len_for_non_dns,
            stats_polling_frequency,
        )
    })
}

/**
 * Check whether pcap is dropping packets and log if it is.  This function should be called
 * periodically from a packet capture loop, e.g., ``blocking_pcap_loop()``
 */
fn check_pcap_stats(
    capture: &mut Capture<pcap::Active>,
    last_stats: Option<pcap::Stat>,
) -> Option<pcap::Stat> {
    match capture.stats() {
        Ok(stats) => {
            match last_stats {
                Some(last_stats) => {
                    // we got valid new and old stats - compare them and warn if losing packets
                    let new_dropped = stats.dropped - last_stats.dropped;
                    let new_if_dropped = stats.if_dropped - last_stats.if_dropped;
                    if new_dropped > 0 || new_if_dropped > 0 {
                        warn!("Pcap sytem is dropping packets: {} dropped by pcap, {} by network inteface", new_dropped, new_if_dropped);
                    } else {
                        debug!("Pcap stats check - no dropped packets");
                    }
                    Some(stats)
                }
                None => {
                    // no old stats, assume first time call and warn about any drops
                    if stats.dropped > 0 || stats.if_dropped > 0 {
                        warn!("Pcap sytem is dropping packets: {} dropped by pcap, {} by network inteface", stats.dropped, stats.if_dropped);
                    }
                    Some(stats)
                }
            }
        }
        Err(e) => {
            // failed to get new stats, can't really do anything
            // just log and return old_stats for next time in case the problem goes away!?
            warn!("Pcap:: Failed to collect stats : {}", e);
            last_stats
        }
    }
}

/**
 * Bind a socket to a remote addr (8.8.8.8) and see which
 * IP it maps to and return the corresponding device
 *
 */

pub fn lookup_egress_device() -> Result<pcap::Device, PcapError> {
    let addr = crate::utils::remote_ip_to_local(IpAddr::from_str("8.8.8.8").unwrap())?;
    for d in &pcap::Device::list()? {
        if d.addresses.iter().any(|a| a.addr == addr) {
            return Ok(d.clone());
        }
    }
    warn!("Default route lookup algorithm failed: defaulting to pcap's default device");
    // if we got here, we failed to lookup a device via its default route
    // just return the default device and hope for the best
    if let Some(device) = pcap::Device::lookup()? {
        Ok(device)
    } else {
        Err(pcap::Error::PcapError(
            "Failed to find any default pcap device".to_string(),
        ))
    }
}

pub fn lookup_pcap_device_by_name(name: &String) -> Result<pcap::Device, PcapError> {
    for d in &pcap::Device::list()? {
        if d.name == *name {
            return Ok(d.clone());
        }
    }
    let all_interfaces = pcap::Device::list()?
        .iter()
        .map(|d| d.name.clone())
        .join(" , ");
    Err(pcap::Error::PcapError(format!(
        "Failed to find any pcap device with name '{}' out of {}",
        name, all_interfaces
    )))
}

pub fn lookup_pcap_device_by_ip(ip: &IpAddr) -> Result<pcap::Device, PcapError> {
    for d in &pcap::Device::list()? {
        if d.addresses.iter().any(|d| d.addr == *ip) {
            return Ok(d.clone());
        }
    }
    let all_interfaces = pcap::Device::list()?
        .iter()
        .map(|d| d.name.clone())
        .join(" , ");
    Err(pcap::Error::PcapError(format!(
        "Failed to find any pcap device with ip '{}' out of {}",
        ip, all_interfaces
    )))
}

/**
 * Wrapper around pcap::Capture::sendpacket() so we can mock it during testing
 */
pub trait RawSocketWriter: Send {
    /// Send the ethernet packet (with L2 headers) out the interface that matches
    /// [`src_ip]
    fn sendpacket(&mut self, interface_ip: IpAddr, buf: &[u8]) -> Result<(), pcap::Error>;
    /// Update the IpAddresses we know to be local to this machine
    fn update_local_addrs(&mut self, local_addr: HashSet<IpAddr>);
}

/**
 * Real instantiation of a RawSocketWriter using the portable libpcap library
 */
struct PcapRawSocketWriter {
    interface_map: HashMap<IpAddr, Capture<pcap::Active>>,
    /// IpAddresses we know to be local to this machine
    local_addrs: HashSet<IpAddr>,
}

impl PcapRawSocketWriter {
    pub fn new(local_addrs: HashSet<IpAddr>) -> PcapRawSocketWriter {
        PcapRawSocketWriter {
            interface_map: HashMap::new(),
            local_addrs,
        }
    }
}

impl RawSocketWriter for PcapRawSocketWriter {
    fn sendpacket(&mut self, interface_ip: IpAddr, buf: &[u8]) -> Result<(), pcap::Error> {
        if !self.local_addrs.contains(&interface_ip) {
            // This can happen if the system_tracker is still sending pings and hasn't yet detected that
            // an interface has gone away.
            debug!(
                "Interface IP {} for outgoing packet is not a local IP -- skipping",
                interface_ip
            );
            return Ok(());
        }
        let start = std::time::Instant::now();
        // include the lookup time in the performance check
        let capture = match self.interface_map.get_mut(&interface_ip) {
            Some(capture) => capture,
            None => {
                // we haven't tried to send out this interface before
                // lookup the interface by IP, create a capture to it, and cache it
                let device = lookup_pcap_device_by_ip(&interface_ip)?;
                info!(
                    "Starting new raw_socket capture for IP {} on device {}",
                    interface_ip,
                    device.desc.as_ref().unwrap_or(&device.name)
                );
                let capture = device.open()?;
                self.interface_map.insert(interface_ip, capture);
                self.interface_map.get_mut(&interface_ip).unwrap()
            }
        };
        let result = capture.sendpacket(buf);
        perf_check!(
            "Pcap::sendpacket",
            start,
            std::time::Duration::from_millis(30)
        );
        result
    }

    fn update_local_addrs(&mut self, local_addrs: HashSet<IpAddr>) {
        let current_ips = self.interface_map.keys().cloned().collect_vec();
        for ip in &current_ips {
            if !local_addrs.contains(ip) {
                info!("Removing raw_socket capture for IP {}", ip);
                self.interface_map.remove(ip);
            }
        }
        self.local_addrs = local_addrs;
    }
}

/**
 * Create a RawSocketWriter
 *
 * NOTE: funky implementation issue in Linux: if you pcap::sendpacket() out a pcap instance,
 * that same instance does NOT actually see the outgoing packet.  We get around this by
 * binding a different instance for reading vs. writing packets.
 */
pub fn bind_writable_pcap(local_addrs: HashSet<IpAddr>) -> impl RawSocketWriter {
    PcapRawSocketWriter::new(local_addrs)
}

#[cfg(test)]
pub mod test {
    use super::*;
    use tokio::sync::mpsc::{channel, Receiver, Sender};

    /**
     * Used for testing - just capture and buffer anything written to it
     */
    #[cfg(test)]
    pub struct MockRawSocketProber {
        pub tx: Sender<PerfMsgCheck<crate::prober::ProbeMessage>>,
        pub rx: Receiver<PerfMsgCheck<crate::prober::ProbeMessage>>,
        pub captured: Vec<Vec<u8>>,
    }

    #[cfg(test)]
    impl Default for MockRawSocketProber {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(test)]
    impl MockRawSocketProber {
        pub fn new() -> MockRawSocketProber {
            let (tx, rx) = channel(1024);
            MockRawSocketProber {
                tx,
                rx,
                captured: Vec::new(),
            }
        }

        /**
         * Take the messages that were queued to be sent, make the Prober calls to turn them into packets,
         * and put them into the * connection tracker as if pcap had received them.  Useful in testing.
         */
        pub fn redirect_into_connection_tracker(
            &mut self,
            connection_tracker: &mut crate::connection_tracker::ConnectionTracker,
        ) {
            while let Ok(msg) = self.rx.try_recv() {
                let msg = msg.skip_perf_check();
                crate::prober::prober_handle_one_message(self, msg);
                while let Some(probe) = self.captured.pop() {
                    let parsed_probe = OwnedParsedPacket::try_from_fake_time(probe).unwrap();
                    connection_tracker.add(parsed_probe);
                }
            }
        }
    }

    #[cfg(test)]
    impl RawSocketWriter for MockRawSocketProber {
        /// NOTE: the MockRawSocketProber ignores which interface we try to send on
        /// and just stores all of the packets sent to it in the same buffer
        fn sendpacket(&mut self, _interface_ip: IpAddr, buf: &[u8]) -> Result<(), pcap::Error> {
            self.captured.push(buf.to_vec());
            Ok(())
        }

        fn update_local_addrs(&mut self, _local_addrs: HashSet<IpAddr>) {
            unimplemented!()
        }
    }
}
