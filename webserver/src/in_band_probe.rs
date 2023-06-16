use std::error::Error;

use etherparse::TransportHeader;
use log::warn;
use pcap::Capture;

use crate::{
    context::Context,
    pcap::{Connection, OwnedParsedPacket},
};

/**
 * Create a bunch of packets with the same local/remote five tuple
 * that look like retransmited data but are in fact probe packets
 *
 * pipe them out of a pcap live capture with send_packet()
*/
pub async fn tcp_inband_probe(
    context: Context,
    _connection: Connection,
    packet: OwnedParsedPacket,
) -> Result<(), Box<dyn Error>> {
    let mut capture = bind_writable_pcap(&context).await?;
    let l2 = packet.link.as_ref().unwrap();
    // build up probes
    let probes: Vec<Vec<u8>> = (1..16)
        .map(|ttl| {
            let builder = etherparse::PacketBuilder::ethernet2(l2.source, l2.destination);
            let ip_header = packet.ip.as_ref().unwrap();
            let builder = match &ip_header {
                etherparse::IpHeader::Version4(ip4, _) => {
                    builder.ipv4(ip4.source, ip4.destination, ttl)
                }
                etherparse::IpHeader::Version6(ip6, _) => {
                    builder.ipv6(ip6.source, ip6.destination, ttl)
                }
            };
            let builder = match &packet.transport {
                Some(TransportHeader::Tcp(tcp)) => builder.tcp(
                    tcp.source_port,
                    tcp.destination_port,
                    tcp.sequence_number,
                    tcp.window_size,
                ),
                _ => panic!("Called tcp_band_probe on non-TCP connection: {:?}", packet),
            };
            // try to encode the TTL into the payload; this solves a bunch of problems for us
            let payload_len = std::cmp::min(ttl as usize, packet.payload.len());
            let payload = packet.payload[0..payload_len].to_vec();
            let mut probe = Vec::<u8>::with_capacity(builder.size(payload.len()));
            builder.write(&mut probe, &payload).unwrap();
            probe
        })
        .collect();
    for probe in probes {
        if let Err(e) = capture.sendpacket(probe) {
            warn!("Error sending tcp_band_probe() : {} -- {:?}", e, packet);
        }
    }

    Ok(())
}

/**
 * Bind a pcap capture instance so we can raw write packets out of it.
 *
 * NOTE: funky implementation issue in Linux: if you pcap::sendpacket() out a pcap instance,
 * that same instance does NOT actually see the outgoing packet.  We get around this by
 * binding a different instance for reading vs. writing packets.
 */
pub async fn bind_writable_pcap(
    context: &Context,
) -> Result<pcap::Capture<pcap::Active>, Box<dyn Error>> {
    let device = context.read().await.pcap_device.clone();
    let cap = Capture::from_device(device)?.open()?;
    Ok(cap)
}
