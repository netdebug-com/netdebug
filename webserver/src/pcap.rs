use std::{
    collections::{HashMap, HashSet},
    error::Error,
    net::IpAddr,
};

use etherparse::{IpHeader, IpNumber};
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

    /***
     * Much like a five-tuple ECMP hash, but just use
     * the highest layer that's defined rather than the
     * full five tuple.  Arguably lower entropy (though
     * not likely) but faster to compute.
     *
     * NOTE: it's a critical property of this hash that packets
     * from A-->B and B-->A have the same hash, e.g., that
     * the hash function is symetric
     */
    pub fn sloppy_hash(&self) -> u8 {
        use etherparse::TransportHeader::*;
        // if there's a UDP or TCP header, return the hash of that
        match &self.transport {
            Some(Udp(udp)) => {
                let mix_16 = udp.source_port ^ udp.destination_port;
                return (((mix_16 & 0xff00) >> 8) ^ (mix_16 & 0x00ff)) as u8;
            }
            Some(Tcp(tcp)) => {
                let mix_16 = tcp.source_port ^ tcp.destination_port;
                return (((mix_16 & 0xff00) >> 8) ^ (mix_16 & 0x00ff)) as u8;
            }
            _ => (),
        }
        // if not, try hashing just l3 src + dst addrs
        use etherparse::IpHeader::*;
        match &self.ip {
            // these hashes could be more machine code effficient - come back if perf is needed
            Some(Version4(ip4, _)) => {
                let mut hash = 0;
                for i in 0..=3 {
                    hash = hash ^ ip4.source[i];
                }
                for i in 0..=3 {
                    hash = hash ^ ip4.destination[i];
                }
                return hash;
            }
            Some(Version6(ip6, _)) => {
                let mut hash = 0;
                for i in 0..=3 {
                    hash = hash ^ ip6.source[i];
                }
                for i in 0..=3 {
                    hash = hash ^ ip6.destination[i];
                }
                return hash;
            }
            None => (),
        }
        // if no l4 or l3, try l2
        match &self.link {
            Some(e) => {
                let mut hash = 0;
                for i in 0..=5 {
                    hash = hash ^ e.source[i];
                }
                for i in 0..=5 {
                    hash = hash ^ e.destination[i];
                }
                return hash;
            }
            None => 0, // just give up, this packet didn't even have an l2 header!?
        }
    }

    /**
     * If the connection is a TCP/UDP packet, map it to the corresponding
     * ConnectionKey, normalizing the local vs. remote port so that A-->B and B-->A
     * packets have the same key.
     *
     * Further, if the packet is an ICMP unreachable with an encapsulated packet,
     * generate the ConnectionKey for the *encapsulated* packet, not the outer packet
     *
     * This will let us match ICMP Unreachables back to the flows that sent them.
     */
    fn to_connection_key(&self, local_addrs: &HashSet<IpAddr>) -> Option<ConnectionKey> {
        let (local_ip, remote_ip, source_is_local) = match &self.ip {
            Some(IpHeader::Version4(ip4, _)) => {
                let source_ip = IpAddr::from(ip4.source);
                let dest_ip = IpAddr::from(ip4.destination);
                if local_addrs.contains(&source_ip) {
                    (source_ip, dest_ip, true)
                } else {
                    (dest_ip, source_ip, false)
                }
            }
            Some(IpHeader::Version6(ip6, _)) => {
                let source_ip = IpAddr::from(ip6.source);
                let dest_ip = IpAddr::from(ip6.destination);
                if local_addrs.contains(&source_ip) {
                    (source_ip, dest_ip, true)
                } else {
                    (dest_ip, source_ip, false)
                }
            }
            None => return None, // if there's no IP layer, just return None
        };
        use etherparse::TransportHeader::*;
        match &self.transport {
            None => None,
            Some(Tcp(tcp)) => {
                let (local_l4_port, remote_l4_port) = if source_is_local {
                    (tcp.source_port, tcp.destination_port)
                } else {
                    (tcp.destination_port, tcp.source_port)
                };
                Some(ConnectionKey {
                    local_ip,
                    remote_ip,
                    local_l4_port,
                    remote_l4_port,
                    ip_proto: IpNumber::Tcp as u8,
                })
            }
            Some(Udp(udp)) => {
                let (local_l4_port, remote_l4_port) = if source_is_local {
                    (udp.source_port, udp.destination_port)
                } else {
                    (udp.destination_port, udp.source_port)
                };
                Some(ConnectionKey {
                    local_ip,
                    remote_ip,
                    local_l4_port,
                    remote_l4_port,
                    ip_proto: IpNumber::Udp as u8,
                })
            }
            Some(Icmpv4(icmp4)) => self.to_icmp4_connection_key(icmp4),
            Some(Icmpv6(icmp6)) => self.to_icmp6_connection_key(icmp6),
        }
    }

    fn to_icmp4_connection_key(&self, icmp4: &etherparse::Icmpv4Header) -> Option<ConnectionKey> {
        use etherparse::Icmpv4Type::*;
        match &icmp4.icmp_type {
            Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            } => None,
            EchoReply(_) => None,
            DestinationUnreachable(_d) => {
                todo!()
            }
            Redirect(_) => todo!(),
            EchoRequest(_) => None,
            TimeExceeded(_) => todo!(),
            ParameterProblem(_) => None,
            TimestampRequest(_) => None,
            TimestampReply(_) => None,
        }
    }

    fn to_icmp6_connection_key(&self, icmp6: &etherparse::Icmpv6Header) -> Option<ConnectionKey> {
        todo!()
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

    let mut local_addrs = HashSet::new();
    for a in &device.addresses {
        local_addrs.insert(a.addr);
    }

    let mut connection_tracker = ConnectionTracker::new(local_addrs);
    info!("Starting pcap capture on {}", &device.name);
    let capture = Capture::from_device(device)?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    let stream = capture.stream(PacketParserCodec {})?;
    stream
        .for_each(|pkt| {
            if let Ok(pkt) = pkt {
                connection_tracker.add(pkt);
            }
            futures::future::ready(())
        })
        .await;

    Ok(())
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
struct ConnectionKey {
    local_ip: IpAddr,
    remote_ip: IpAddr,
    local_l4_port: u16,
    remote_l4_port: u16,
    ip_proto: u8,
}

struct ConnectionTracker {
    connections: HashMap<ConnectionKey, Connection>,
    local_addrs: HashSet<IpAddr>,
}
impl ConnectionTracker {
    fn new(local_addrs: HashSet<IpAddr>) -> ConnectionTracker {
        ConnectionTracker {
            connections: HashMap::new(),
            local_addrs,
        }
    }

    fn add(&mut self, packet: OwnedParsedPacket) -> Result<(), Box<dyn Error>> {
        if let Some(key) = packet.to_connection_key(&self.local_addrs) {
            if let Some(connection) = self.connections.get(&key) {
                connection.update(packet)
            } else {
                self.new_connection(packet, key)
            }
        }
        // if we got here, the packet didn't have enough info to be called a 'connection'
        // just return OK and move on for now
        Ok(())
    }

    fn new_connection(&self, pkt: OwnedParsedPacket, key: ConnectionKey) {
        todo!()
    }
}

struct Connection {}
impl Connection {
    fn update(&self, packet: OwnedParsedPacket) {
        todo!()
    }
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
