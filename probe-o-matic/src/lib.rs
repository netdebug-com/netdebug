use chrono::{DateTime, Utc};
use etherparse::{icmpv4, Icmpv4Type, IpHeader, Ipv4Extensions, Ipv6Extensions, TransportHeader};
use libconntrack::{
    connection::ConnectionTrackerMsg, owned_packet::OwnedParsedPacket, pcap::RawSocketWriter,
};
use log::{debug, error, info, warn};
use priority_queue::PriorityQueue;
use std::{
    cmp::Reverse,
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
};
use tokio::{sync::mpsc, time::sleep_until};

const TIME_BETWEEN_PROBE_MS: u64 = 1_000;
/// Number of probes to send to the same destination port per IP
/// (these probes should all take the same path
/// total number of probes per IP is PROBES_PER_PORT * NUM_PORTS_TO_PROBE
const PROBES_PER_PORT: u16 = 3;
/// The number of different destination ports to probe. If there
/// ECMP path, it's likely some will take divergent paths
/// total number of probes per IP is PROBES_PER_PORT * NUM_PORTS_TO_PROBE
const NUM_PORTS_TO_PROBE: u16 = 5;
const DEFAULT_TTL: u8 = 64;
const START_DST_PORT: u16 = 33434;

pub fn to_socket_addr_v4(sa: SocketAddr) -> Option<SocketAddrV4> {
    match sa {
        SocketAddr::V4(sa) => Some(sa),
        _ => None,
    }
}

pub fn to_socket_addr_v6(sa: SocketAddr) -> Option<SocketAddrV6> {
    match sa {
        SocketAddr::V6(sa) => Some(sa),
        _ => None,
    }
}

/**
 Basic information of the probing machine's local addresses, src ports,
 and the MAC address of the gateway to use for probes
*/
#[derive(Clone, Debug)]
pub struct LocalAddressConfig {
    /// The MAC address of the (default) gateway to send probes to
    pub gateway_mac: mac_address::MacAddress,
    /// MAC of the outgoing interface
    pub src_mac: mac_address::MacAddress,
    /// IP + UDP port for outgoing probes
    pub v4_src_addr: SocketAddrV4,
    /// IP + UDP port for outgoing probes
    pub v6_src_addr: SocketAddrV6,
    /// Interface name to probe from
    pub if_name: String,
}

impl LocalAddressConfig {
    /// Return true if the src_ip, src_port of `hdr` is a local address
    pub fn is_local_socket_addr(&self, hdr: &SimpleHeader) -> bool {
        let addr = SocketAddr::new(hdr.src_ip, hdr.src_port);
        match addr {
            SocketAddr::V4(v4) => v4 == self.v4_src_addr,
            SocketAddr::V6(v6) => v6 == self.v6_src_addr,
        }
    }
}

pub enum ProbeOMaticMsg {
    ProbeAddr(IpAddr),
    TheEnd,
}

/// A simplified enum to represent the type of packet we are
/// dealing with
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum SimpleProtocol {
    /// A UDP packet, which we use for outgoing probes
    Udp,
    /// An ICMP port unreachable, which we expect for incoming probes
    IcmpPortUnreachable,
    /// Anything else
    Other,
}

/// A simple way to represent a 5-tuple (plus some additional useful info)
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct SimpleHeader {
    /// Timestamp the packet was captured (from pcap)
    timestamp: DateTime<Utc>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: SimpleProtocol,
    /// If it's an IPv4 packet: the IP_ID
    ip_id: Option<u16>,
    ttl: u8,
    /// If protocol == Udp: the UDP src port, 0 otherwise
    src_port: u16,
    /// If protocol == Udp: the UDP dst port, 0 otherwise
    dst_port: u16,
    /// payload len (as derived/inferred from udphdr.length field)
    /// For IcmpPortUnreachable it will be the length inferred from the
    /// embedded udphdr
    payload_len: u16,
}

impl TryFrom<&OwnedParsedPacket> for SimpleHeader {
    type Error = ProbeInfoError;

    fn try_from(pkt: &OwnedParsedPacket) -> Result<Self, Self::Error> {
        // Check that we have both L3 and L4 header and unpack them from their Option's
        // if we do have them.
        let (ip_header, transport_header) = match (pkt.ip.as_ref(), pkt.transport.as_ref()) {
            (Some(ip), Some(transport)) => (ip, transport),
            _ => return Err(ProbeInfoError::NotAProbe),
        };

        let (src_port, dst_port, proto, payload_len) = match transport_header {
            TransportHeader::Udp(udphdr) => (
                udphdr.source_port,
                udphdr.destination_port,
                SimpleProtocol::Udp,
                udphdr.length.saturating_sub(8 /* len of udp hdr */),
            ),
            TransportHeader::Icmpv4(icmp4) => match &icmp4.icmp_type {
                Icmpv4Type::DestinationUnreachable(unreach_hdr)
                    if *unreach_hdr == icmpv4::DestUnreachableHeader::Port =>
                {
                    (
                        0,
                        0,
                        SimpleProtocol::IcmpPortUnreachable,
                        pkt.payload.len() as u16,
                    )
                }
                _ => (0, 0, SimpleProtocol::Other, 0),
            },
            _ => (0, 0, SimpleProtocol::Other, 0),
        };
        match ip_header {
            IpHeader::Version4(v4hdr, _) => Ok(SimpleHeader {
                timestamp: pkt.timestamp,
                src_ip: IpAddr::from(v4hdr.source),
                dst_ip: IpAddr::from(v4hdr.destination),
                protocol: proto,
                ip_id: Some(v4hdr.identification),
                ttl: v4hdr.time_to_live,
                src_port,
                dst_port,
                payload_len,
            }),

            IpHeader::Version6(v6hdr, _) => Ok(SimpleHeader {
                timestamp: pkt.timestamp,
                src_ip: IpAddr::from(v6hdr.source),
                dst_ip: IpAddr::from(v6hdr.destination),
                protocol: proto,
                ip_id: None,
                ttl: v6hdr.hop_limit,
                src_port,
                dst_port,
                payload_len,
            }),
        }
    }
}

/// Direction of probe packets sniffed by pcap
#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy)]
enum ProbeDirection {
    /// Probe is sent by us
    Outgoing,
    /// Response from the remote side
    Incoming,
}

#[derive(thiserror::Error, Debug)]
pub enum ProbeInfoError {
    #[error("failed to parse packet data")]
    PacketParsingError(#[from] Box<dyn std::error::Error>),
    #[error("Packet is not a probe")]
    NotAProbe,
}

impl PartialEq for ProbeInfoError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::PacketParsingError(l0), Self::PacketParsingError(r0)) => {
                l0.to_string() == r0.to_string()
            }
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

/// Summary of incoming or outgoing probes
#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub struct ProbePacketInfo {
    /// The IP address of our target that we sent the probe to
    target_ip: IpAddr,
    /// The port we sent the probe to. Usually one of the traceroute ports
    port: u16,
    /// Timestamp when the packet was captured by pcap
    timestamp: DateTime<Utc>,
    /// Direction of the probe
    direction: ProbeDirection,
    /// The IP_ID we chose when we sent the packet (if IPv4)
    /// Is set for both outgoing and incomning probes (if IPv4)
    our_ip_id: Option<u16>,
    /// For incoming probes: the IP_ID that the remote side (i.e., the
    /// target) put in its response packet. Used for IP_ID velocity
    remote_ip_id: Option<u16>,
    /// For incoming probes: the IP that the remote/target sent the
    /// response from. This could be the `target_ip`, but could also
    /// be another IP/interface on the same router
    remote_src_ip: Option<IpAddr>,
    /// Identifies the number/sequence of probes we sent. We use the
    /// payload length to encode it.
    probe_num: u16,
    // TODO: add TTL
}

impl ProbePacketInfo {
    pub fn try_from_parsed_packet(
        addr_config: &LocalAddressConfig,
        pkt: Box<OwnedParsedPacket>,
    ) -> Result<Self, ProbeInfoError> {
        if pkt.ip.is_none() || pkt.transport.is_none() {
            return Err(ProbeInfoError::NotAProbe);
        }

        let hdr = SimpleHeader::try_from(&*pkt).unwrap();

        match hdr.protocol {
            SimpleProtocol::Udp if addr_config.is_local_socket_addr(&hdr) => Ok(ProbePacketInfo {
                target_ip: hdr.dst_ip,
                port: hdr.dst_port,
                timestamp: hdr.timestamp,
                direction: ProbeDirection::Outgoing,
                our_ip_id: hdr.ip_id,
                remote_ip_id: None,
                remote_src_ip: None,
                probe_num: hdr.payload_len,
            }),
            SimpleProtocol::IcmpPortUnreachable => {
                let inner_pkt = OwnedParsedPacket::from_partial_embedded_ip_packet(
                    &pkt.payload,
                    pkt.timestamp,
                    pkt.payload.len() as u32,
                )?
                .0;
                let inner_hdr = SimpleHeader::try_from(&inner_pkt)?;
                if addr_config.is_local_socket_addr(&inner_hdr) {
                    Ok(ProbePacketInfo {
                        target_ip: inner_hdr.dst_ip,
                        port: inner_hdr.dst_port,
                        timestamp: inner_hdr.timestamp,
                        direction: ProbeDirection::Incoming,
                        our_ip_id: inner_hdr.ip_id,
                        remote_ip_id: hdr.ip_id, // this is the ip_id of the outer packet
                        remote_src_ip: Some(hdr.src_ip), // The src_ip in the outer packet
                        probe_num: inner_hdr.payload_len,
                    })
                } else {
                    Err(ProbeInfoError::NotAProbe)
                }
            }
            _ => Err(ProbeInfoError::NotAProbe),
        }
    }
}

struct InProgressProbeState {
    target: IpAddr,
    next_probe_num: u16,
    probe_infos: Vec<ProbePacketInfo>,
}

impl InProgressProbeState {
    pub fn new(target: IpAddr) -> Self {
        InProgressProbeState {
            target,
            next_probe_num: 0,
            probe_infos: Vec::new(),
        }
    }

    pub fn all_probes_sent(&self) -> bool {
        self.next_probe_num >= PROBES_PER_PORT * NUM_PORTS_TO_PROBE
    }
}

impl Display for InProgressProbeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ProbeReport for {}", self.target)?;
        for info in &self.probe_infos {
            writeln!(
                f,
                "  #{:02} {} {:#?} port {}",
                info.probe_num, info.timestamp, info.direction, info.port
            )?;
        }
        Ok(())
    }
}

pub struct ProbeOMatic {
    pkt_rx: mpsc::UnboundedReceiver<ConnectionTrackerMsg>,
    probe_rx: mpsc::UnboundedReceiver<ProbeOMaticMsg>,
    raw_sock: Box<dyn RawSocketWriter>,
    addr_config: LocalAddressConfig,
    /// This map keeps track of the IPs we are currently probing. When we receive
    /// a request to probe an IP, we add it to this map. Once we are done with an
    /// IP, we remove it from this map.
    probes: HashMap<IpAddr, InProgressProbeState>,
    /// Work we need to do. Either send the next probe for a given IP, or if
    /// all probes have been sent, we remove the IP from `probes` and report
    /// it.
    work_queue: PriorityQueue<IpAddr, Reverse<tokio::time::Instant>>,
    should_terminate_loop: bool,
}

impl ProbeOMatic {
    pub fn spawn(
        pkt_rx: mpsc::UnboundedReceiver<ConnectionTrackerMsg>,
        probe_rx: mpsc::UnboundedReceiver<ProbeOMaticMsg>,
        raw_sock: Box<dyn RawSocketWriter>,
        addr_config: LocalAddressConfig,
    ) -> tokio::task::JoinHandle<()> {
        let mut pom = ProbeOMatic {
            pkt_rx,
            probe_rx,
            raw_sock,
            addr_config,
            probes: HashMap::new(),
            work_queue: PriorityQueue::new(),
            should_terminate_loop: false,
        };
        tokio::spawn(async move {
            pom.rx_loop().await;
        })
    }

    pub async fn rx_loop(&mut self) {
        loop {
            let next_wakeup = match self.work_queue.peek() {
                Some((_, deadline)) => deadline.0,
                None => {
                    tokio::time::Instant::now()
                        + tokio::time::Duration::from_millis(TIME_BETWEEN_PROBE_MS)
                }
            };
            tokio::select! {
                Some(conn_msg) = self.pkt_rx.recv() => self.handle_conn_msg(conn_msg),
                Some(probe_msg) = self.probe_rx.recv() => self.handle_probe_msg(probe_msg),
                _ = sleep_until(next_wakeup) => {
                    debug!("Got woken up from my sleep");
                    let work_item = self.work_queue.pop();
                    if let Some((ip, _)) = work_item {
                        self.do_work_item(ip);
                    } else if self.should_terminate_loop {
                        // Work queue is empty and we've been requested to termiante.
                        break;
                    }
                },
                else => break

            }
        }
        info!("Exiting rx_loop");
    }

    fn handle_conn_msg(&mut self, msg: ConnectionTrackerMsg) {
        use ConnectionTrackerMsg::*;
        match msg {
            Pkt(pkt) => match ProbePacketInfo::try_from_parsed_packet(&self.addr_config, pkt) {
                Ok(probe_info) => {
                    info!(
                        "We got a probe packet (#{}) for {}",
                        probe_info.probe_num, probe_info.target_ip
                    );
                    match self.probes.get_mut(&probe_info.target_ip) {
                        Some(probe_state) => {
                            probe_state.probe_infos.push(probe_info);
                        }
                        None => warn!(
                            "Got probe response for {}, but don't have a record for it. Delayed?",
                            probe_info.target_ip
                        ),
                    }
                }
                Err(e1) => match e1 {
                    ProbeInfoError::PacketParsingError(e2) => {
                        warn!("Failed to parse packet: {}", e2)
                    }
                    ProbeInfoError::NotAProbe => debug!("We got a Not-A-Probe"),
                },
            },
            _ => warn!("We can only handle `Pkt` messages, but got: {:?}", msg),
        }
    }

    fn handle_probe_msg(&mut self, msg: ProbeOMaticMsg) {
        use ProbeOMaticMsg::*;
        match msg {
            ProbeAddr(ip) => {
                info!("Got a probe request msg for {}", ip);
                let prev = self.probes.insert(ip, InProgressProbeState::new(ip));
                if prev.is_some() {
                    // TODO: do something more useful here
                    error!("We already had a probe record for {}", ip);
                }
                self.do_work_item(ip);
            }
            TheEnd => self.should_terminate_loop = true,
        }
    }

    fn do_work_item(&mut self, ip: IpAddr) {
        if let Some(probe_state) = self.probes.get_mut(&ip) {
            if probe_state.all_probes_sent() {
                info!("We are done for IP {}", ip);
                info!("{}", probe_state);
                // TODO: ship off finished probe_state
                self.probes.remove(&ip);
                return;
            }
            probe_state.next_probe_num += 1;
            let port_diff = (probe_state.next_probe_num - 1) / PROBES_PER_PORT;
            let dst_port = START_DST_PORT + port_diff;
            let payload: Vec<u8> = (0..probe_state.next_probe_num as u8).collect();
            assert_eq!(payload.len(), probe_state.next_probe_num as usize);
            let dst = SocketAddr::new(probe_state.target, dst_port);
            let pkt = create_probe_packet(&self.addr_config, dst, DEFAULT_TTL, &payload);
            match self.raw_sock.sendpacket(&pkt) {
                Err(e) => warn!("Failed to send probe to {}: {}", probe_state.target, e),
                Ok(_) => info!(
                    "Sent probe #{} to {}",
                    probe_state.next_probe_num, probe_state.target
                ),
            }
            let deadline = tokio::time::Instant::now()
                + tokio::time::Duration::from_millis(TIME_BETWEEN_PROBE_MS);
            self.work_queue.push(probe_state.target, Reverse(deadline));
        } else {
            warn!(
                "Got work for IP {}, but didn't find it in pending probes",
                ip
            );
        }
    }
}

pub fn create_probe_packet(
    addr_config: &LocalAddressConfig,
    dst: SocketAddr,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let builder = etherparse::PacketBuilder::ethernet2(
        addr_config.src_mac.bytes(),
        addr_config.gateway_mac.bytes(),
    );
    let builder = builder.ip(match dst {
        SocketAddr::V4(dst) => {
            // asdf
            let mut iph = etherparse::Ipv4Header::new(
                0,
                ttl,
                etherparse::ip_number::UDP,
                addr_config.v4_src_addr.ip().octets(),
                dst.ip().octets(),
            );
            iph.identification = 0x4242;
            IpHeader::Version4(iph, Ipv4Extensions::default())
        }
        SocketAddr::V6(dst) => {
            IpHeader::Version6(
                etherparse::Ipv6Header {
                    traffic_class: 0,
                    flow_label: 0,
                    payload_length: 0, // will be replaced during write
                    next_header: 0,    // will be replaced during write
                    hop_limit: ttl,
                    source: addr_config.v6_src_addr.ip().octets(),
                    destination: dst.ip().octets(),
                },
                Ipv6Extensions::default(),
            )
        }
    });
    let src_port = if dst.is_ipv4() {
        addr_config.v4_src_addr.port()
    } else {
        addr_config.v6_src_addr.port()
    };
    let builder = builder.udp(src_port, dst.port());
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut result, payload).unwrap();
    result
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::TimeZone;
    use etherparse::{IcmpEchoHeader, PacketHeaders, TransportHeader};
    use mac_address::MacAddress;
    use std::{net::Ipv6Addr, str::FromStr};

    fn mk_addr_config() -> LocalAddressConfig {
        LocalAddressConfig {
            gateway_mac: MacAddress::new([1, 2, 3, 4, 5, 6]),
            src_mac: MacAddress::new([7, 8, 9, 10, 11, 12]),
            v4_src_addr: SocketAddrV4::from_str("1.2.3.4:42").unwrap(),
            v6_src_addr: SocketAddrV6::from_str("[1234::5678]:23").unwrap(),
            if_name: "eth0".to_string(),
        }
    }

    #[test]
    fn test_create_probe_packet_v4() {
        let dst = SocketAddr::from_str("8.8.8.8:53").unwrap();
        let addr_config = mk_addr_config();

        let serialized = create_probe_packet(&addr_config, dst, 12, &[0xde, 0xad, 0xbe, 0xef]);
        let parsed = PacketHeaders::from_ethernet_slice(&serialized).unwrap();

        let l2hdr = parsed.link.unwrap();
        assert_eq!(l2hdr.ether_type, 0x0800);
        assert_eq!(l2hdr.source, [7, 8, 9, 10, 11, 12]);
        assert_eq!(l2hdr.destination, [1, 2, 3, 4, 5, 6]);

        let iphdr = match parsed.ip.unwrap() {
            IpHeader::Version4(v4, _) => v4,
            _ => panic!("Expected an Ipv4 header"),
        };
        assert_eq!(iphdr.source, [1, 2, 3, 4]);
        assert_eq!(iphdr.destination, [8, 8, 8, 8]);
        assert_eq!(iphdr.identification, 0x4242);
        assert_eq!(iphdr.time_to_live, 12);

        let udphdr = match parsed.transport.unwrap() {
            TransportHeader::Udp(udphdr) => udphdr,
            _ => panic!("Expected a UDP header"),
        };
        assert_eq!(udphdr.source_port, 42);
        assert_eq!(udphdr.destination_port, 53);

        assert_eq!(parsed.payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_create_probe_packet_v6() {
        let dst = SocketAddr::from_str("[2001:4860:4860::8888]:5353").unwrap();
        let addr_config = mk_addr_config();

        let serialized = create_probe_packet(&addr_config, dst, 12, &[0xca, 0xfe, 0xd0, 0x0d]);
        let parsed = PacketHeaders::from_ethernet_slice(&serialized).unwrap();

        let l2hdr = parsed.link.unwrap();
        assert_eq!(l2hdr.ether_type, 0x86dd);
        assert_eq!(l2hdr.source, [7, 8, 9, 10, 11, 12]);
        assert_eq!(l2hdr.destination, [1, 2, 3, 4, 5, 6]);

        let iphdr = match parsed.ip.unwrap() {
            IpHeader::Version6(v6, _) => v6,
            _ => panic!("Expected an Ipv4 header"),
        };
        assert_eq!(
            iphdr.source,
            Ipv6Addr::from_str("1234::5678").unwrap().octets()
        );
        assert_eq!(
            iphdr.destination,
            Ipv6Addr::from_str("2001:4860:4860::8888").unwrap().octets()
        );
        assert_eq!(iphdr.hop_limit, 12);

        let udphdr = match parsed.transport.unwrap() {
            TransportHeader::Udp(udphdr) => udphdr,
            _ => panic!("Expected a UDP header"),
        };
        assert_eq!(udphdr.source_port, 23);
        assert_eq!(udphdr.destination_port, 5353);

        assert_eq!(parsed.payload, &[0xca, 0xfe, 0xd0, 0x0d]);
    }

    #[test]
    fn test_udp_probe_packet_handling() {
        let dst = SocketAddr::from_str("8.8.8.8:53").unwrap();
        let addr_config = mk_addr_config();

        let serialized = create_probe_packet(&addr_config, dst, 12, &[0xde, 0xad, 0xbe, 0xef]);
        let parsed = PacketHeaders::from_ethernet_slice(&serialized).unwrap();
        let ts = Utc.timestamp_opt(1696473476, 12345).unwrap();
        let owned_packet = Box::new(OwnedParsedPacket::from_headers_and_ts(
            parsed,
            ts,
            serialized.len() as u32,
        ));
        let simple_hdr = SimpleHeader::try_from(&*owned_packet).unwrap();
        assert_eq!(simple_hdr.timestamp, ts);
        assert_eq!(simple_hdr.src_ip, IpAddr::from_str("1.2.3.4").unwrap());
        assert_eq!(simple_hdr.dst_ip, IpAddr::from_str("8.8.8.8").unwrap());
        assert_eq!(simple_hdr.ip_id, Some(0x4242));
        assert_eq!(simple_hdr.ttl, 12);
        assert_eq!(simple_hdr.protocol, SimpleProtocol::Udp);
        assert_eq!(simple_hdr.src_port, 42);
        assert_eq!(simple_hdr.dst_port, 53);
        assert_eq!(simple_hdr.payload_len, 4);

        let ppi = ProbePacketInfo::try_from_parsed_packet(&addr_config, owned_packet).unwrap();
        assert_eq!(ppi.timestamp, ts);
        assert_eq!(ppi.target_ip, IpAddr::from_str("8.8.8.8").unwrap());
        assert_eq!(ppi.direction, ProbeDirection::Outgoing);
        assert_eq!(ppi.port, 53);
        assert_eq!(ppi.our_ip_id, Some(0x4242));
        assert_eq!(ppi.remote_ip_id, None);
        assert_eq!(ppi.remote_src_ip, None);
        assert_eq!(ppi.probe_num, 4);
    }

    fn mk_not_a_probe_udp() -> Vec<u8> {
        let mut buf = Vec::<u8>::new();
        let payload = vec![0xa, 0xb, 0xc];
        etherparse::PacketBuilder::ipv4([10, 0, 0, 1], [6, 7, 8, 9], 20 /* ttl */)
            .udp(1024 /* sport */, 123 /* dport */)
            .write(&mut buf, &payload)
            .unwrap();
        buf
    }

    #[test]
    fn test_udp_not_a_probe_packet_handling() {
        let raw_pkt = mk_not_a_probe_udp();
        let parsed = etherparse::PacketHeaders::from_ip_slice(&raw_pkt).unwrap();
        let ts = Utc.timestamp_opt(1696473476, 12345).unwrap();
        let owned_packet = Box::new(OwnedParsedPacket::from_headers_and_ts(
            parsed,
            ts,
            raw_pkt.len() as u32,
        ));
        let addr_config = mk_addr_config();
        assert_eq!(
            ProbePacketInfo::try_from_parsed_packet(&addr_config, owned_packet),
            Err(ProbeInfoError::NotAProbe)
        );
    }

    #[test]
    fn test_tcp_packet_handling() {
        let mut buf = Vec::<u8>::new();
        let payload = vec![0xa, 0xb, 0xc];
        etherparse::PacketBuilder::ipv4([1, 2, 3, 4], [6, 7, 8, 9], 20 /* ttl */)
            .tcp(
                1024, /* sport */
                80,   /* dport */
                0,    /* seq */
                0,    /* win */
            )
            .write(&mut buf, &payload)
            .unwrap();
        let parsed = etherparse::PacketHeaders::from_ip_slice(&buf).unwrap();
        let ts = Utc.timestamp_opt(1696473476, 12345).unwrap();
        let owned_packet = Box::new(OwnedParsedPacket::from_headers_and_ts(
            parsed,
            ts,
            buf.len() as u32,
        ));
        let simple_hdr = SimpleHeader::try_from(&*owned_packet).unwrap();
        assert_eq!(simple_hdr.timestamp, ts);
        assert_eq!(simple_hdr.src_ip, IpAddr::from_str("1.2.3.4").unwrap());
        assert_eq!(simple_hdr.dst_ip, IpAddr::from_str("6.7.8.9").unwrap());
        assert!(simple_hdr.ip_id.is_some());
        assert_eq!(simple_hdr.ttl, 20);
        // SimpleHeader doesn't handle TCP yet
        assert_eq!(simple_hdr.protocol, SimpleProtocol::Other);
        assert_eq!(simple_hdr.src_port, 0);
        assert_eq!(simple_hdr.dst_port, 0);
        assert_eq!(simple_hdr.payload_len, 0);

        let addr_config = mk_addr_config();
        assert_eq!(
            ProbePacketInfo::try_from_parsed_packet(&addr_config, owned_packet),
            Err(ProbeInfoError::NotAProbe)
        );
    }

    fn mk_iph_with_icmp4() -> IpHeader {
        let mut iph = etherparse::Ipv4Header::new(
            0,
            42, /* ttl */
            etherparse::ip_number::ICMP,
            [10, 0, 0, 1], // src IP doesn't have to be target IP
            [1, 2, 3, 4],
        );
        iph.identification = 0x2323;
        IpHeader::Version4(iph, Default::default())
    }

    #[test]
    fn test_icmp_probe_packet_handling() {
        let dst = SocketAddr::from_str("8.8.8.8:53").unwrap();
        let addr_config = mk_addr_config();

        let serialized_embedded = create_probe_packet(&addr_config, dst, 12, &[0xde, 0xad]);
        // skip ethernet header (14 bytes) and truncate payload (2 bytes)
        let serialized_partial_embedded = &serialized_embedded[14..(serialized_embedded.len() - 2)];

        let mut buf = Vec::<u8>::new();
        etherparse::PacketBuilder::ip(mk_iph_with_icmp4())
            .icmpv4(Icmpv4Type::DestinationUnreachable(
                icmpv4::DestUnreachableHeader::Port,
            ))
            .write(&mut buf, serialized_partial_embedded)
            .unwrap();

        let parsed = etherparse::PacketHeaders::from_ip_slice(&buf).unwrap();
        let ts = Utc.timestamp_opt(1696473476, 12345).unwrap();
        let owned_packet = Box::new(OwnedParsedPacket::from_headers_and_ts(
            parsed,
            ts,
            buf.len() as u32,
        ));
        let addr_config = mk_addr_config();
        let ppi = ProbePacketInfo::try_from_parsed_packet(&addr_config, owned_packet).unwrap();
        assert_eq!(ppi.timestamp, ts);
        assert_eq!(ppi.target_ip, IpAddr::from_str("8.8.8.8").unwrap());
        assert_eq!(ppi.direction, ProbeDirection::Incoming);
        assert_eq!(ppi.port, 53);
        assert_eq!(ppi.our_ip_id, Some(0x4242));
        assert_eq!(ppi.remote_ip_id, Some(0x2323));
        assert_eq!(
            ppi.remote_src_ip,
            Some(IpAddr::from_str("10.0.0.1").unwrap())
        );
        assert_eq!(ppi.probe_num, 2);
    }

    #[test]
    fn test_icmp_not_a_probe_packet_handling() {
        let serialized_embedded = mk_not_a_probe_udp();
        // 20 bytes IP + 8 byte UDP header
        let serialized_partial_embedded = &serialized_embedded[0..28];

        let mut buf = Vec::<u8>::new();
        etherparse::PacketBuilder::ip(mk_iph_with_icmp4())
            .icmpv4(Icmpv4Type::DestinationUnreachable(
                icmpv4::DestUnreachableHeader::Port,
            ))
            .write(&mut buf, serialized_partial_embedded)
            .unwrap();

        let parsed = etherparse::PacketHeaders::from_ip_slice(&buf).unwrap();
        let ts = Utc.timestamp_opt(1696473476, 12345).unwrap();
        let owned_packet = Box::new(OwnedParsedPacket::from_headers_and_ts(
            parsed,
            ts,
            buf.len() as u32,
        ));
        let addr_config = mk_addr_config();
        assert_eq!(
            ProbePacketInfo::try_from_parsed_packet(&addr_config, owned_packet),
            Err(ProbeInfoError::NotAProbe),
        );

        buf.clear();
        etherparse::PacketBuilder::ip(mk_iph_with_icmp4())
            .icmpv4(Icmpv4Type::EchoReply(IcmpEchoHeader { id: 1, seq: 2 }))
            // EchoReply payload can be arbritrary, so we just put the embedded packet there.
            .write(&mut buf, serialized_partial_embedded)
            .unwrap();
        let parsed = etherparse::PacketHeaders::from_ip_slice(&buf).unwrap();
        let owned_packet = Box::new(OwnedParsedPacket::from_headers_and_ts(
            parsed,
            ts,
            buf.len() as u32,
        ));
        assert_eq!(
            ProbePacketInfo::try_from_parsed_packet(&addr_config, owned_packet),
            Err(ProbeInfoError::NotAProbe),
        );
    }
}
