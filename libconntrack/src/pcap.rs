use std::error::Error;
use std::net::IpAddr;
use std::str::FromStr;

use crate::connection::ConnectionTrackerMsg;
#[cfg(not(windows))]
use futures_util::StreamExt;
use log::{info, warn};
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

pub fn blocking_pcap_loop(
    device_name: String,
    filter_rule: Option<String>,
    tx: tokio::sync::mpsc::UnboundedSender<ConnectionTrackerMsg>,
) -> Result<(), Box<dyn Error>> {
    let device = lookup_pcap_device_by_name(&device_name)?;
    info!("Starting pcap capture on {}", &device.name);
    let mut capture = Capture::from_device(device)?
        .buffer_size(64_000_000) // try to prevent any packet loss
        .open()?;
    // only capture/probe traffic to the webserver
    if let Some(filter_rule) = filter_rule {
        info!("Applying pcap filter '{}'", filter_rule);
        capture.filter(filter_rule.as_str(), true)?;
    }
    loop {
        match capture.next_packet() {
            Ok(pkt) => {
                let parsed = etherparse::PacketHeaders::from_ethernet_slice(pkt.data);
                if let Ok(parsed_pkt) = parsed {
                    let parsed_packet = OwnedParsedPacket::new(parsed_pkt, pkt.header.clone());
                    let _hash = parsed_packet.sloppy_hash();
                    // TODO: use this hash to map to 256 parallel ConnectionTrackers for parallelism
                    tx.send(ConnectionTrackerMsg::Pkt(parsed_packet)).unwrap();
                }
            }
            Err(e) => {
                warn!("start_pcap_stream got error: {} - exiting", e);
                break;
            }
        }
    }

    Ok(())
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
