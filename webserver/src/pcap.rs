use std::{collections::HashSet, error::Error};

use crate::connection::ConnectionTracker;
use futures_util::StreamExt;
use log::{info, warn};
use pcap::Capture;

use crate::context::Context;
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
 * This is setup to have many parallel connection trackers to achieve
 * parallelism with the hash/sloppy_hash(), but it's not implemented
 * yet.
 */

pub async fn start_pcap_stream(context: Context) -> Result<(), Box<dyn Error>> {
    let device = context.read().await.pcap_device.clone();

    let mut local_addrs = HashSet::new();
    for a in &device.addresses {
        local_addrs.insert(a.addr);
    }

    let local_tcp_port = context.read().await.local_tcp_listen_port;
    let raw_sock = bind_writable_pcap(&context).await?;
    let mut connection_tracker = ConnectionTracker::new(context, local_addrs, raw_sock).await;
    info!("Starting pcap capture on {}", &device.name);
    let mut capture = Capture::from_device(device)?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    // only capture/probe traffic to the webserver
    let filter_rule = format!("tcp port {}", local_tcp_port);
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
                    connection_tracker.add(pkt);
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
 * Bind a socket to a remote addr (8.8.8.8) and see which
 * IP it maps to and return the corresponding device
 *
 * NOTE: this technique actually sends no traffic; it's purely local
 */

pub fn lookup_egress_device() -> Result<pcap::Device, Box<dyn Error>> {
    let udp_sock = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
    udp_sock.connect(("8.8.8.8", 53))?;
    let addr = udp_sock.local_addr()?.ip();
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
pub async fn bind_writable_pcap(context: &Context) -> Result<impl RawSocketWriter, Box<dyn Error>> {
    let device = context.read().await.pcap_device.clone();
    let cap = Capture::from_device(device)?.open()?;
    Ok(PcapRawSocketWriter::new(cap))
}
