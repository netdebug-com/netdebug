use std::error::Error;

use common_wasm::PROBE_MAX_TTL;
use etherparse::{PacketHeaders, TcpHeader, TransportHeader};
use log::{debug, warn};
use tokio::sync::mpsc::{channel, Sender};

use crate::{owned_packet::OwnedParsedPacket, pcap::RawSocketWriter, utils::PerfMsgCheck};

pub enum ProbeMessage {
    SendProbe {
        packet: OwnedParsedPacket,
        min_ttl: u8,
    },
}

pub async fn spawn_raw_prober<R>(
    mut raw_sock: R,
    max_queued: usize,
) -> Sender<PerfMsgCheck<ProbeMessage>>
where
    R: RawSocketWriter + 'static,
{
    let (tx, mut rx) = channel::<PerfMsgCheck<ProbeMessage>>(max_queued);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let msg = msg.perf_check_get("spawn_raw_prober");
            prober_handle_one_message(&mut raw_sock, &msg);
        }
    });
    tx
}

/**
 * Split this function out for ease of testing
 */
pub fn prober_handle_one_message(raw_sock: &mut dyn RawSocketWriter, message: &ProbeMessage) {
    match message {
        ProbeMessage::SendProbe { packet, min_ttl } => {
            if let Err(e) = tcp_inband_probe(packet, raw_sock, *min_ttl) {
                warn!("Problem running tcp_inband_probe: {}", e);
            }
        }
    }
}

/**
 * Create a bunch of packets with the same local/remote five tuple
 * that look like retransmited data but are in fact probe packets
 *
 * pipe them out of a pcap live capture with send_packet()
 *
 * take the 'raw_sock' param explicitly to facilitate testing
*/
pub fn tcp_inband_probe(
    packet: &OwnedParsedPacket,
    raw_sock: &mut dyn RawSocketWriter, // used with testing
    min_ttl: u8,
) -> Result<(), Box<dyn Error>> {
    let l2 = packet.link.as_ref().unwrap();
    // build up probes
    let probes: Vec<Vec<u8>> = (min_ttl..=PROBE_MAX_TTL)
        .map(|ttl| {
            let builder = etherparse::PacketBuilder::ethernet2(l2.source, l2.destination);
            let ip_header = packet.ip.as_ref().unwrap();
            let mut new_ip = ip_header.clone();
            match new_ip {
                etherparse::IpHeader::Version4(ref mut ip4, _) => {
                    ip4.time_to_live = ttl;
                    ip4.identification = ttl as u16; // redundant but useful!
                }
                etherparse::IpHeader::Version6(ref mut ip6, _) => {
                    ip6.hop_limit = ttl;
                    // TODO: consider setting the flow_label BUT some ISPs might hash on it..
                }
            }
            let builder = builder.ip(new_ip);
            let builder = match &packet.transport {
                Some(TransportHeader::Tcp(tcp)) => {
                    let mut tcph = TcpHeader::new(
                        tcp.source_port,
                        tcp.destination_port,
                        tcp.sequence_number,
                        tcp.window_size,
                    );
                    // make this probe look more believable
                    tcph.psh = true;
                    tcph.ack = true;
                    tcph.acknowledgment_number = tcp.acknowledgment_number;
                    // don't set the TCP options for now - lazy
                    builder.tcp_header(tcph)
                }
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
        debug!("Sending tcp_inband_probes() :: {:?}", parsed_probe);
    }
    for probe in probes {
        if let Err(e) = raw_sock.sendpacket(&probe) {
            warn!("Error sending tcp_band_probe() : {} -- {:?}", e, packet);
        }
    }

    Ok(())
}

#[cfg(test)]
pub mod test {
    use std::{net::IpAddr, str::FromStr};

    use super::*;
    use etherparse::{IpHeader, PacketBuilder};

    use crate::owned_packet::OwnedParsedPacket;
    use crate::pcap::MockRawSocketProber;

    pub fn test_tcp_packet(src_ip: IpAddr, dst_ip: IpAddr) -> Box<OwnedParsedPacket> {
        test_tcp_packet_ports(src_ip, dst_ip, 21, 1234)
    }

    pub fn test_tcp_packet_ports(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tcp_src: u16,
        tcp_dst: u16,
    ) -> Box<OwnedParsedPacket> {
        let builder = PacketBuilder::ethernet2(
            [1, 2, 3, 4, 5, 6], //source mac
            [7, 8, 9, 10, 11, 12],
        ) //destionation mac
        ;
        let builder = match (src_ip, dst_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => builder.ipv4(s.octets(), d.octets(), 20), //time to life
            (IpAddr::V6(s), IpAddr::V6(d)) => builder.ipv6(s.octets(), d.octets(), 20),
            (IpAddr::V6(_), IpAddr::V4(_)) | (IpAddr::V4(_), IpAddr::V6(_)) => {
                panic!("Mismatched v4 and v6 src/dst : {} vs {}", src_ip, dst_ip)
            }
        };
        let builder = builder.tcp(
            tcp_src, //source port
            tcp_dst, 0, 50000,
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
        Box::new(OwnedParsedPacket::new(headers, pcap_header))
    }

    fn get_v4_ttl(pkt: &PacketHeaders) -> Option<u8> {
        match pkt.ip.as_ref().unwrap() {
            IpHeader::Version4(iph, _) => Some(iph.time_to_live),
            _ => None,
        }
    }

    #[tokio::test]
    async fn test_inband_tcp_probes() {
        let mut mock_raw_sock = MockRawSocketProber::new();
        assert_eq!(mock_raw_sock.captured.len(), 0);
        let packet = test_tcp_packet(
            IpAddr::from_str("192.168.1.1").unwrap(),
            IpAddr::from_str("192.168.1.2").unwrap(),
        );

        tcp_inband_probe(&packet, &mut mock_raw_sock, 1).unwrap();

        assert_eq!(mock_raw_sock.captured.len(), PROBE_MAX_TTL as usize);

        // now verify the last packet is what we think it should be
        let last_pkt =
            PacketHeaders::from_ethernet_slice(mock_raw_sock.captured.last().unwrap()).unwrap();
        let first_pkt =
            PacketHeaders::from_ethernet_slice(mock_raw_sock.captured.first().unwrap()).unwrap();
        // nth pkt should have a 16 byte payload
        assert_eq!(last_pkt.payload.len(), PROBE_MAX_TTL as usize);

        assert_eq!(get_v4_ttl(&first_pkt), Some(1));
        assert_eq!(get_v4_ttl(&last_pkt), Some(32));
        // TODO: more checks as needed, but if we got here, it's probably mostly working
    }

    #[tokio::test]
    async fn test_inband_tcp_probes_min_ttl() {
        let mut mock_raw_sock = MockRawSocketProber::new();
        assert_eq!(mock_raw_sock.captured.len(), 0);
        let packet = test_tcp_packet(
            IpAddr::from_str("192.168.1.1").unwrap(),
            IpAddr::from_str("192.168.1.2").unwrap(),
        );

        tcp_inband_probe(&packet, &mut mock_raw_sock, 5).unwrap();

        assert_eq!(mock_raw_sock.captured.len(), PROBE_MAX_TTL as usize - 4);

        // now verify the last packet is what we think it should be
        let last_pkt =
            PacketHeaders::from_ethernet_slice(mock_raw_sock.captured.last().unwrap()).unwrap();
        let first_pkt =
            PacketHeaders::from_ethernet_slice(mock_raw_sock.captured.first().unwrap()).unwrap();
        // nth pkt should have a 16 byte payload
        assert_eq!(last_pkt.payload.len(), PROBE_MAX_TTL as usize);
        assert_eq!(get_v4_ttl(&first_pkt), Some(5));
        assert_eq!(get_v4_ttl(&last_pkt), Some(32));
    }
}
