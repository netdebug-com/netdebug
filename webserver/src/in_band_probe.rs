use std::error::Error;

use etherparse::{PacketHeaders, TransportHeader};
use log::{info, warn};

use crate::{
    context::Context,
    pcap::{Connection, OwnedParsedPacket, RawSocketWriter},
};

/**
 * Create a bunch of packets with the same local/remote five tuple
 * that look like retransmited data but are in fact probe packets
 *
 * pipe them out of a pcap live capture with send_packet()
 *
 * take the 'raw_sock' param explicitly to facilitate testing
*/
pub fn tcp_inband_probe(
    _context: Context,
    _connection: Connection, // do we really need this?
    packet: OwnedParsedPacket,
    raw_sock: &mut dyn RawSocketWriter, // used with testing
) -> Result<(), Box<dyn Error>> {
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
    if let Some(first_probe) = probes.first() {
        // only log the first probe
        // we are reparsing from the bytes rather than starting with the inputs to log what we're sending
        // not what we think we're sending.
        // unwrap() here should be ok because if this doesn't parse, we should die obviously
        let parsed_probe = PacketHeaders::from_ethernet_slice(first_probe).unwrap();
        info!("Sending tcp_inband_probes() :: {:?}", parsed_probe);
    }
    for probe in probes {
        if let Err(e) = raw_sock.sendpacket(&probe) {
            warn!("Error sending tcp_band_probe() : {} -- {:?}", e, packet);
        }
    }

    Ok(())
}
