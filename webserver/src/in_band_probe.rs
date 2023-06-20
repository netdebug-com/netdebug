use std::error::Error;

use etherparse::{PacketHeaders, TransportHeader};
use log::{info, warn};

use crate::{
    context::Context,
    pcap::{OwnedParsedPacket, RawSocketWriter},
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
    packet: OwnedParsedPacket,
    raw_sock: &mut dyn RawSocketWriter, // used with testing
) -> Result<(), Box<dyn Error>> {
    let l2 = packet.link.as_ref().unwrap();
    // build up probes
    let probes: Vec<Vec<u8>> = (1..=16)
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

#[cfg(test)]
mod test {
    use super::*;
    use etherparse::PacketBuilder;

    use crate::pcap::{MockRawSocketWriter, OwnedParsedPacket};

    fn test_tcp_packet() -> OwnedParsedPacket {
        let builder = PacketBuilder::ethernet2(
            [1, 2, 3, 4, 5, 6], //source mac
            [7, 8, 9, 10, 11, 12],
        ) //destionation mac
        .ipv4(
            [192, 168, 1, 1], //source ip
            [192, 168, 1, 2], //desitionation ip
            20,
        ) //time to life
        .tcp(
            21, //source port
            1234, 0, 50000,
        ); //desitnation port
           // make a decent sized payload
        let payload = vec![0; 128];
        let mut buf = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut buf, &payload).unwrap();
        let pcap_header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: buf.len() as u32,
            len: buf.len() as u32,
        };
        let headers = etherparse::PacketHeaders::from_ethernet_slice(&buf).unwrap();
        OwnedParsedPacket::new(headers, pcap_header)
    }

    #[tokio::test]
    async fn test_inband_tcp_probes() {
        let mut mock_raw_sock = MockRawSocketWriter::new();
        assert_eq!(mock_raw_sock.captured.len(), 0);
        let packet = test_tcp_packet();
        let context = crate::context::test::make_test_context();

        tcp_inband_probe(context, packet, &mut mock_raw_sock).unwrap();

        assert_eq!(mock_raw_sock.captured.len(), 16);

        // now verify the last packet is what we think it should be
        let last_pkt =
            PacketHeaders::from_ethernet_slice(mock_raw_sock.captured.last().unwrap()).unwrap();
        // 16th pkt should have a 16 byte payload
        assert_eq!(last_pkt.payload.len(), 16);
        // TODO: more checks as needed, but if we got here, it's probably mostly working
    }
}
