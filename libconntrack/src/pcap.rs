use pcap::Error as PcapError;
use std::net::IpAddr;
use std::str::FromStr;
use std::{collections::HashMap, error::Error};

use crate::{
    connection_tracker::{ConnectionTrackerMsg, ConnectionTrackerSender},
    perf_check,
    utils::PerfMsgCheck,
};
#[cfg(not(windows))]
use futures_util::StreamExt;
use itertools::Itertools;
use log::{debug, info, warn};
use pcap::Capture;
#[cfg(test)]
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::owned_packet::OwnedParsedPacket;
struct PacketParserCodec {}

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

// cannot create a const chrono::Duration at compile time, so use seconds instead
const DEFAULT_STATS_POLLING_FREQUENCY_SECONDS: u64 = 5;

pub fn blocking_pcap_loop(
    device_name: String,
    filter_rule: Option<String>,
    tx: ConnectionTrackerSender,
    stats_polling_frequency: Option<chrono::Duration>,
) -> Result<(), Box<dyn Error>> {
    let device = lookup_pcap_device_by_name(&device_name)?;
    info!("Starting pcap capture on {}", &device.name);
    let mut capture = Capture::from_device(device)?
        .buffer_size(64_000_000) // try to prevent any packet loss
        .snaplen(512)
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
        return Err(format!(
            "Unsupported link capture type - only support ethernet:  {:?} ({:?}) - {:?}",
            datalink.get_name(),
            datalink,
            datalink.get_description()
        )
        .into());
    }
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
                    let parsed_packet = Box::new(OwnedParsedPacket::new(parsed_pkt, *pkt.header));
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
                        return Err(Box::new(e));
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
    stats_polling_frequency: Option<chrono::Duration>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if let Err(e) = blocking_pcap_loop(device_name, filter_rule, tx, stats_polling_frequency) {
            panic!("pcap thread failed to start loop: {}", e);
        }
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

pub fn lookup_egress_device() -> Result<pcap::Device, Box<dyn Error>> {
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
        Err(Box::new(pcap::Error::PcapError(
            "Failed to find any default pcap device".to_string(),
        )))
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
}

/**
 * Real instantiation of a RawSocketWriter using the portable libpcap library
 */
struct PcapRawSocketWriter {
    interface_map: HashMap<IpAddr, Capture<pcap::Active>>,
}

impl PcapRawSocketWriter {
    pub fn new() -> PcapRawSocketWriter {
        PcapRawSocketWriter {
            interface_map: HashMap::new(),
        }
    }
}

impl RawSocketWriter for PcapRawSocketWriter {
    fn sendpacket(&mut self, interface_ip: IpAddr, buf: &[u8]) -> Result<(), pcap::Error> {
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
}

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
}

/**
 * Create a RawSocketWriter
 *
 * NOTE: funky implementation issue in Linux: if you pcap::sendpacket() out a pcap instance,
 * that same instance does NOT actually see the outgoing packet.  We get around this by
 * binding a different instance for reading vs. writing packets.
 */
pub fn bind_writable_pcap() -> impl RawSocketWriter {
    PcapRawSocketWriter::new()
}
