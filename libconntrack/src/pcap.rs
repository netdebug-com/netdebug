use std::error::Error;
use std::net::IpAddr;
use std::str::FromStr;

use crate::connection::ConnectionTrackerMsg;
#[cfg(not(windows))]
use futures_util::StreamExt;
use log::{debug, info, warn};
use pcap::Capture;

use crate::owned_packet::OwnedParsedPacket;
struct PacketParserCodec {}

impl pcap::PacketCodec for PacketParserCodec {
    type Item = OwnedParsedPacket;

    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(packet.data);
        if let Ok(pkt) = parsed {
            OwnedParsedPacket::new(pkt, *packet.header)
        } else {
            warn!("Failed to parse packet {:?} - punting", packet.data);
            OwnedParsedPacket {
                pcap_header: *packet.header,
                link: None,
                vlan: None,
                ip: None,
                transport: None,
                payload: packet.data.to_vec(),
            }
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
    tx: tokio::sync::mpsc::UnboundedSender<ConnectionTrackerMsg>,
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
                    tx.send(ConnectionTrackerMsg::Pkt(pkt)).unwrap();
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

// cannot create a const chrono::Duration at compile time, so use seconds instead
const DEFAULT_STATS_POLLING_FREQUENCY_SECONDS: u64 = 5;

pub fn blocking_pcap_loop(
    device_name: String,
    filter_rule: Option<String>,
    tx: tokio::sync::mpsc::UnboundedSender<ConnectionTrackerMsg>,
    stats_polling_frequency: Option<chrono::Duration>,
) -> Result<(), Box<dyn Error>> {
    let device = lookup_pcap_device_by_name(&device_name)?;
    info!("Starting pcap capture on {}", &device.name);
    let mut capture = Capture::from_device(device)?
        .buffer_size(64_000_000) // try to prevent any packet loss
        .timeout(1000) // for macos, so it doesn't get stuck
        .open()?;
    // only capture/probe traffic to the webserver
    if let Some(filter_rule) = filter_rule {
        info!("Applying pcap filter '{}'", filter_rule);
        capture.filter(filter_rule.as_str(), true)?;
    }
    let mut last_stats: Option<pcap::Stat> = None;
    let mut next_stats_time = 0u64;
    let stats_polling_frequency = match stats_polling_frequency {
        Some(t) => t.num_seconds() as u64,
        None => DEFAULT_STATS_POLLING_FREQUENCY_SECONDS,
    };
    loop {
        match capture.next_packet() {
            Ok(pkt) => {
                let pkt_timestamp = pkt.header.ts; // save this for stats checking
                let parsed = etherparse::PacketHeaders::from_ethernet_slice(pkt.data);
                if let Ok(parsed_pkt) = parsed {
                    let parsed_packet = OwnedParsedPacket::new(parsed_pkt, pkt.header.clone());
                    let _hash = parsed_packet.sloppy_hash();
                    // TODO: use this hash to map to 256 parallel ConnectionTrackers for parallelism
                    tx.send(ConnectionTrackerMsg::Pkt(parsed_packet)).unwrap();
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
            match last_stats {
                Some(stats) => Some(stats),
                None => None,
            }
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
        if d.addresses.iter().find(|&a| a.addr == addr).is_some() {
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

pub fn lookup_pcap_device_by_name(name: &String) -> Result<pcap::Device, Box<dyn Error>> {
    for d in &pcap::Device::list()? {
        if d.name == *name {
            return Ok(d.clone());
        }
    }
    Err(Box::new(pcap::Error::PcapError(format!(
        "Failed to find any pcap device with name '{}'",
        name
    ))))
}

/**
 * Wrapper around pcap::Capture::sendpacket() so we can mock it during testing
 */
pub trait RawSocketWriter: Send {
    fn sendpacket(&mut self, buf: &[u8]) -> Result<(), pcap::Error>;
}

/**
 * Real instantiation of a RawSocketWriter using the portable libpcap library
 */
struct PcapRawSocketWriter {
    capture: Capture<pcap::Active>,
}

impl PcapRawSocketWriter {
    pub fn new(capture: Capture<pcap::Active>) -> PcapRawSocketWriter {
        PcapRawSocketWriter { capture }
    }
}

impl RawSocketWriter for PcapRawSocketWriter {
    fn sendpacket(&mut self, buf: &[u8]) -> Result<(), pcap::Error> {
        self.capture.sendpacket(buf)
    }
}

/**
 * Used for testing - just capture and buffer anything written to it
 */
pub struct MockRawSocketWriter {
    pub captured: Vec<Vec<u8>>,
}

impl MockRawSocketWriter {
    pub fn new() -> MockRawSocketWriter {
        MockRawSocketWriter {
            captured: Vec::new(),
        }
    }
}

impl RawSocketWriter for MockRawSocketWriter {
    fn sendpacket(&mut self, buf: &[u8]) -> Result<(), pcap::Error> {
        self.captured.push(buf.to_vec());
        Ok(())
    }
}

/**
 * Bind a pcap capture instance so we can raw write packets out of it.
 *
 * NOTE: funky implementation issue in Linux: if you pcap::sendpacket() out a pcap instance,
 * that same instance does NOT actually see the outgoing packet.  We get around this by
 * binding a different instance for reading vs. writing packets.
 */
pub fn bind_writable_pcap(device: pcap::Device) -> Result<impl RawSocketWriter, Box<dyn Error>> {
    let cap = Capture::from_device(device)?.open()?;
    Ok(PcapRawSocketWriter::new(cap))
}

pub fn bind_writable_pcap_by_name(
    pcap_device_name: String,
) -> Result<impl RawSocketWriter, Box<dyn Error>> {
    let device = lookup_pcap_device_by_name(&pcap_device_name)?;
    bind_writable_pcap(device)
}
