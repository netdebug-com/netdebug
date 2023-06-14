use std::error::Error;

use futures_util::StreamExt;
use log::{info, warn};
use pcap::Capture;

use crate::context::Context;

/**
 * This is like an etherparse::PacketHeader struct, but is 'owned'
 * in that there are no references/external life times.
 *
 * Creating this structure requires a memcpy() which is a performance
 * hit but it simplifies the rest of the code by removing the external
 * references.
 *
 * If performancec becomes an issue, we'll probably have to rewrite
 * all of this with, e.g., AF_XDP anyway
 */
#[derive(Clone, Debug)]
struct OwnedParsedPacket {
    // timestamp and other capture info
    pub pcap_header: pcap::PacketHeader,
    /// Ethernet II header if present.
    pub link: Option<etherparse::Ethernet2Header>,
    /// Single or double vlan headers if present.
    pub vlan: Option<etherparse::VlanHeader>,
    /// IPv4 or IPv6 header and IP extension headers if present.
    pub ip: Option<etherparse::IpHeader>,
    /// TCP or UDP header if present.
    pub transport: Option<etherparse::TransportHeader>,
    /// Rest of the packet that could not be decoded as a header (usually the payload).
    pub payload: Vec<u8>,
}

impl OwnedParsedPacket {
    pub fn new(
        headers: etherparse::PacketHeaders,
        pcap_header: pcap::PacketHeader,
    ) -> OwnedParsedPacket {
        OwnedParsedPacket {
            pcap_header,
            link: headers.link,
            vlan: headers.vlan,
            ip: headers.ip,
            transport: headers.transport,
            payload: headers.payload.to_vec(),
        }
    }
}

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

pub async fn start_pcap_stream(_context: Context) -> Result<(), Box<dyn Error>> {
    let device = lookup_egress_device()?;
    info!("Starting pcap capture on {}", &device.name);
    let capture = Capture::from_device(device)?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    let stream = capture.stream(PacketParserCodec {})?;
    stream
        .for_each(|pkt| {
            if let Ok(pkt) = pkt {
                println!("Captured pkt {:?}", pkt);
            }
            futures::future::ready(())
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

fn lookup_egress_device() -> Result<pcap::Device, Box<dyn Error>> {
    let udp_sock = std::net::UdpSocket::bind(("0.0.0.0", 0))?;
    udp_sock.connect(("8.8.8.8", 53))?;
    let addr = udp_sock.peer_addr()?.ip();
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
