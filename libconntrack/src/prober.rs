use std::{
    error::Error,
    io::{Cursor, Write},
    net::IpAddr,
};

use common_wasm::PROBE_MAX_TTL;
use etherparse::{icmpv6::TYPE_NEIGHBOR_SOLICITATION, PacketHeaders, TcpHeader, TransportHeader};
use log::{debug, warn};
use tokio::sync::mpsc::{channel, Sender};

use crate::{
    neighbor_cache::{ArpPacket, MIN_NDP_SIZE},
    owned_packet::OwnedParsedPacket,
    pcap::RawSocketWriter,
    utils::PerfMsgCheck,
};

pub type ProberSender = Sender<PerfMsgCheck<ProbeMessage>>;

#[derive(Clone, Debug)]
pub enum ProbeMessage {
    SendProbe {
        packet: Box<OwnedParsedPacket>,
        min_ttl: u8,
    },
    SendPing {
        local_mac: [u8; 6],
        local_ip: IpAddr,
        /// If remote_mac is not known, use the broadcast mac ff:ff:ff:ff:ff:ff
        remote_mac: Option<[u8; 6]>,
        remote_ip: IpAddr,
        id: u16,
        seq: u16,
    },
    /// Send an Arp or an IPv6 ICMP Neighbor solicitation message to lookup this address
    SendIpLookup {
        local_mac: [u8; 6],
        local_ip: IpAddr,
        target_ip: IpAddr,
    },
}

pub fn spawn_raw_prober<R>(mut raw_sock: R, max_queued: usize) -> Sender<PerfMsgCheck<ProbeMessage>>
where
    R: RawSocketWriter + 'static,
{
    let (tx, mut rx) = channel::<PerfMsgCheck<ProbeMessage>>(max_queued);
    tokio::task::spawn_blocking(move || {
        while let Some(msg) = rx.blocking_recv() {
            let msg = msg.perf_check_get("spawn_raw_prober");
            prober_handle_one_message(&mut raw_sock, msg);
        }
    });
    tx
}

/**
 * Split this function out for ease of testing
 */
pub fn prober_handle_one_message(raw_sock: &mut dyn RawSocketWriter, message: ProbeMessage) {
    use ProbeMessage::*;
    match message {
        SendProbe { packet, min_ttl } => {
            if let Err(e) = tcp_inband_probe(&packet, raw_sock, min_ttl) {
                warn!("Problem running tcp_inband_probe: {}", e);
            }
        }
        SendPing {
            local_mac,
            local_ip,
            remote_mac,
            remote_ip,
            id,
            seq,
        } => icmp_ping(
            raw_sock, local_mac, local_ip, remote_mac, remote_ip, id, seq,
        ),
        // leave as TODO until next diff
        SendIpLookup {
            local_mac,
            local_ip,
            target_ip,
        } => send_neighbor_discovery(raw_sock, local_ip, local_mac, target_ip),
    }
}

fn send_neighbor_discovery(
    raw_sock: &mut dyn RawSocketWriter,
    local_ip: IpAddr,
    local_mac: [u8; 6],
    target_ip: IpAddr,
) {
    // can't think of why this should ever fail, so panic
    let pkt = match (local_ip.is_ipv4(), target_ip.is_ipv4()) {
        (true, true) => {
            let arp_request = ArpPacket::new_request(local_mac, local_ip, target_ip)
                .expect("valid IP/mac for Arp Request");
            arp_request.to_ethernet_pkt().unwrap()
        }
        (false, false) => make_icmp6_neighbor_discovery_solicit(local_ip, local_mac, target_ip),
        _ => {
            panic!("Tried to call Prober::send_arp with a mixed v4/v6 Ip address combo!")
        }
    };
    if let Err(e) = raw_sock.sendpacket(local_ip, &pkt) {
        warn!("Failed to send out Arp request from Prober: {}", e);
    }
}

const ICMP6_NDP_MULTICAST_MAC_ADDR: [u8; 6] = [0x33, 0x33, 0xff, 0x00, 0x00, 0x53];
const ICMP6_NDP_MULTICAST_IP_ADDR: [u8; 16] = [
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x53,
];

fn make_icmp6_neighbor_discovery_solicit(
    local_ip: IpAddr,
    local_mac: [u8; 6],
    target_ip: IpAddr,
) -> Vec<u8> {
    let mut cursor = Cursor::new([0; MIN_NDP_SIZE]); // just the size of the target IPv6 addr
    let (local_ip_buf, target_ip_buf) = match (local_ip, target_ip) {
        (IpAddr::V6(local), IpAddr::V6(target)) => (local.octets(), target.octets()),
        _ => panic!("Called make_icmp6_neighbor_discovery with a v4 target adddress"),
    };
    cursor
        .write_all(&target_ip_buf)
        .expect("Bad length for icmp6 ndp!?");
    let payload = cursor.into_inner();
    let builder = etherparse::PacketBuilder::ethernet2(local_mac, ICMP6_NDP_MULTICAST_MAC_ADDR)
        .ipv6(local_ip_buf, ICMP6_NDP_MULTICAST_IP_ADDR, 64)
        .icmpv6_raw(TYPE_NEIGHBOR_SOLICITATION, 0, [0, 0, 0, 0]);
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).unwrap(); // unwrap ok; unless our math is bad
    pkt
}

pub fn make_ping_icmp_echo_request(
    local_ip: &IpAddr,
    remote_ip: &IpAddr,
    local_mac: [u8; 6],
    remote_mac: [u8; 6],
    id: u16,
    seq: u16,
) -> Vec<u8> {
    let payload = [0u8; 128];
    let builder = etherparse::PacketBuilder::ethernet2(local_mac, remote_mac);
    match (local_ip, remote_ip) {
        (IpAddr::V4(local_ip4), IpAddr::V4(remote_ip4)) => {
            let builder = builder
                .ipv4(local_ip4.octets(), remote_ip4.octets(), 64)
                .icmpv4_echo_request(id, seq);
            // NOTE: this looks like duplicate code with the ipv6 case, but the types are different
            let mut buf = Vec::with_capacity(builder.size(payload.len()));
            builder.write(&mut buf, &payload).unwrap();
            buf
        }
        (IpAddr::V6(local_ip6), IpAddr::V6(remote_ip6)) => {
            let builder = builder
                .ipv6(local_ip6.octets(), remote_ip6.octets(), 64)
                .icmpv6_echo_request(id, seq);
            // NOTE: this looks like duplicate code with the ipv6 case, but the types are different
            let mut buf = Vec::with_capacity(builder.size(payload.len()));
            builder.write(&mut buf, &payload).unwrap();
            buf
        }
        _ => panic!(
            "Tried to mix a v4 and v6 local and remote ip - no can do!: {} vs. {}",
            local_ip, remote_ip
        ),
    }
}

/// Create an EchoReply; could probably share more code with [`make_ping_icmp_echo_request`] but meh
pub fn make_ping_icmp_echo_reply(
    local_ip: &IpAddr,
    remote_ip: &IpAddr,
    local_mac: [u8; 6],
    remote_mac: [u8; 6],
    id: u16,
    seq: u16,
) -> Vec<u8> {
    let payload = [0u8; 128];
    let builder = etherparse::PacketBuilder::ethernet2(local_mac, remote_mac);
    match (local_ip, remote_ip) {
        (IpAddr::V4(local_ip4), IpAddr::V4(remote_ip4)) => {
            let builder = builder
                .ipv4(local_ip4.octets(), remote_ip4.octets(), 64)
                .icmpv4_echo_reply(id, seq);
            // NOTE: this looks like duplicate code with the ipv6 case, but the types are different
            let mut buf = Vec::with_capacity(builder.size(payload.len()));
            builder.write(&mut buf, &payload).unwrap();
            buf
        }
        (IpAddr::V6(local_ip6), IpAddr::V6(remote_ip6)) => {
            let builder = builder
                .ipv6(local_ip6.octets(), remote_ip6.octets(), 64)
                .icmpv6_echo_reply(id, seq);
            // NOTE: this looks like duplicate code with the ipv6 case, but the types are different
            let mut buf = Vec::with_capacity(builder.size(payload.len()));
            builder.write(&mut buf, &payload).unwrap();
            buf
        }
        _ => panic!(
            "Tried to mix a v4 and v6 local and remote ip - no can do!: {} vs. {}",
            local_ip, remote_ip
        ),
    }
}

fn icmp_ping(
    raw_sock: &mut dyn RawSocketWriter,
    local_mac: [u8; 6],
    local_ip: IpAddr,
    remote_mac: Option<[u8; 6]>,
    remote_ip: IpAddr,
    id: u16,
    seq: u16,
) {
    // If we don't know the remote_mac address, fall back to broadcast
    let remote_mac = remote_mac.unwrap_or([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    let buf = make_ping_icmp_echo_request(&local_ip, &remote_ip, local_mac, remote_mac, id, seq);
    if let Err(e) = raw_sock.sendpacket(local_ip, &buf) {
        warn!("Error sending ping in icmp_ping: {}", e);
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
    let (src_ip, _dst_ip) = packet.get_src_dst_ips().unwrap();
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
        if let Err(e) = raw_sock.sendpacket(src_ip, &probe) {
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
    use mac_address::MacAddress;

    use crate::neighbor_cache::{self, ArpOperation, NeighborCache};
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

    #[test]
    fn test_send_arp_request() {
        let mut mock_raw_sock = MockRawSocketProber::new();
        let local_mac = [0, 1, 2, 3, 4, 5];
        let local_ip = IpAddr::from_str("192.168.1.34").unwrap();
        let target_ip = IpAddr::from_str("192.168.1.1").unwrap();
        send_neighbor_discovery(&mut mock_raw_sock, local_ip, local_mac, target_ip);
        // make sure we got 1 packet
        assert_eq!(mock_raw_sock.captured.len(), 1);
        let pkt =
            OwnedParsedPacket::try_from_fake_time(mock_raw_sock.captured.pop().unwrap()).unwrap();
        let arp = ArpPacket::from_wire(&pkt.payload).unwrap();
        assert_eq!(arp.get_sender_ip().unwrap(), local_ip);
        assert_eq!(arp.get_target_ip().unwrap(), target_ip);
        assert_eq!(arp.get_sender_mac().unwrap(), MacAddress::from(local_mac));
        assert_eq!(arp.operation, ArpOperation::Request);
    }

    #[test]
    fn test_send_ndp_request() {
        let mut mock_raw_sock = MockRawSocketProber::new();
        let local_mac = [0, 1, 2, 3, 4, 5];
        let local_ip = IpAddr::from_str("2600:1700:5b20:4e10:78eb:ea4d:7d28:8d7").unwrap();
        let target_ip = IpAddr::from_str("2600:1700:5b20:4e10::2b").unwrap();
        send_neighbor_discovery(&mut mock_raw_sock, local_ip, local_mac, target_ip);
        // make sure we got 1 packet
        assert_eq!(mock_raw_sock.captured.len(), 1);
        let pkt =
            OwnedParsedPacket::try_from_fake_time(mock_raw_sock.captured.pop().unwrap()).unwrap();
        let mut neighbor_cache = NeighborCache::new(10);
        neighbor_cache.process_ndp_packet(pkt).unwrap();
        neighbor_cache::test::assert_learned(
            &mut neighbor_cache,
            local_ip,
            MacAddress::from(local_mac),
        );
    }
}
