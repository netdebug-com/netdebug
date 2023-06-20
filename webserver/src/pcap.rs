use std::{
    collections::{HashMap, HashSet},
    error::Error,
    net::IpAddr,
};

use crate::in_band_probe::tcp_inband_probe;
use etherparse::{IpHeader, IpNumber, TcpHeader, TransportHeader};
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
#[allow(dead_code)]
pub struct OwnedParsedPacket {
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
    /**
     * Create a new OwnedParsedPacket from a pcap capture
     */
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
            None => None, // no l4 protocol --> don't track this flow
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
                let (local_l4_port, remote_l4_port): (u16, u16) = if source_is_local {
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
            DestinationUnreachable(_d) => self.to_icmp_payload_connection_key(),
            Redirect(_) => todo!(),
            EchoRequest(_) => None,
            TimeExceeded(_) => self.to_icmp_payload_connection_key(),
            ParameterProblem(_) => None,
            TimestampRequest(_) => None,
            TimestampReply(_) => None,
        }
    }

    fn to_icmp_payload_connection_key(&self) -> Option<ConnectionKey> {
        match etherparse::PacketHeaders::from_ip_slice(&self.payload) {
            Err(e) => {
                warn!("Unparsed inner ICMP packet - skipping - {}", e);
                None
            }
            Ok(_embedded) => {
                // TODO : properly extract this and map to a key
                // for now, just punt and come back later
                None
            }
        }
    }

    fn to_icmp6_connection_key(&self, _icmp6: &etherparse::Icmpv6Header) -> Option<ConnectionKey> {
        None
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

pub async fn start_pcap_stream(context: Context) -> Result<(), Box<dyn Error>> {
    let device = context.read().await.pcap_device.clone();

    let mut local_addrs = HashSet::new();
    for a in &device.addresses {
        local_addrs.insert(a.addr);
    }

    let mut connection_tracker = ConnectionTracker::new(context, local_addrs);
    info!("Starting pcap capture on {}", &device.name);
    let capture = Capture::from_device(device)?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    let stream = capture.stream(PacketParserCodec {})?;
    stream
        .for_each(|pkt| {
            if let Ok(pkt) = pkt {
                let _hash = pkt.sloppy_hash();
                // TODO: use this hash to map to 256 parallel ConnectionTrackers for parallelism
                connection_tracker.add(pkt);
            }
            futures::future::ready(())
        })
        .await;

    Ok(())
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub struct ConnectionKey {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub local_l4_port: u16,
    pub remote_l4_port: u16,
    pub ip_proto: u8,
}

impl std::fmt::Display for ConnectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto_desc = format!("ip_proto={}", self.ip_proto);
        write!(
            f,
            "{} [{}]::{} --> [{}]::{} ",
            proto_desc, self.local_ip, self.local_l4_port, self.remote_ip, self.remote_l4_port,
        )
    }
}

struct ConnectionTracker {
    context: Context,
    connections: HashMap<ConnectionKey, Connection>,
    local_addrs: HashSet<IpAddr>,
}
impl ConnectionTracker {
    fn new(context: Context, local_addrs: HashSet<IpAddr>) -> ConnectionTracker {
        ConnectionTracker {
            context,
            connections: HashMap::new(),
            local_addrs,
        }
    }

    fn add(&mut self, packet: OwnedParsedPacket) {
        if let Some(key) = packet.to_connection_key(&self.local_addrs) {
            if let Some(connection) = self.connections.get_mut(&key) {
                connection.update(&self.context, packet, &key)
            } else {
                self.new_connection(packet, key)
            }
        }
        // if we got here, the packet didn't have enough info to be called a 'connection'
        // just return and move on for now
    }

    fn new_connection(&mut self, packet: OwnedParsedPacket, key: ConnectionKey) {
        let mut connection = Connection {
            local_syn: None,
            remote_syn: None,
            local_seq: None,
            local_ack: None,
            local_data: None,
        };
        info!("Tracking new connection: {}", &key);

        connection.update(&self.context, packet, &key);
        self.connections.insert(key, connection);
    }
}

#[derive(Clone, Debug)]
pub struct Connection {
    pub local_syn: Option<OwnedParsedPacket>,
    pub remote_syn: Option<OwnedParsedPacket>,
    pub local_seq: Option<u32>,
    pub local_ack: Option<u32>,
    pub local_data: Option<Vec<u8>>, // data sent for retransmits
}
impl Connection {
    fn update(&mut self, context: &Context, packet: OwnedParsedPacket, key: &ConnectionKey) {
        let src_is_local = Connection::src_is_local(&packet, key);
        match &packet.transport {
            Some(TransportHeader::Tcp(tcp)) => {
                if src_is_local {
                    self.update_tcp_local(context, &packet, tcp);
                } else {
                    self.update_tcp_remote(&packet, tcp);
                }
            }
            _ => warn!("Got Connection::update() for non-TCP packet - ignoring for now"),
        }
    }

    /**
     * Should be able to cache this somehow - TODO: rethink
     */
    fn src_is_local(packet: &OwnedParsedPacket, key: &ConnectionKey) -> bool {
        match &packet.ip {
            Some(IpHeader::Version4(ip4, _)) => IpAddr::from(ip4.source) == key.local_ip,
            Some(IpHeader::Version6(ip6, _)) => IpAddr::from(ip6.source) == key.local_ip,
            None => false,
        }
    }

    fn update_tcp_local(&mut self, context: &Context, packet: &OwnedParsedPacket, tcp: &TcpHeader) {
        // record the SYN to see which TCP options are negotiated
        if tcp.syn {
            self.local_syn = Some(packet.clone()); // memcpy() but doesn't happen that much or with much data
        }

        // record how far the local side has acknowledged
        if tcp.ack {
            self.local_ack = Some(tcp.acknowledgment_number);
        }

        // did we send some payload?
        if !packet.payload.is_empty() {
            let mut first_time = false;
            if self.local_data.is_none() {
                // this is the first time in the connection lifetime we sent some payload
                // spawn an inband probe
                first_time = true;
            }
            self.local_data = Some(packet.payload.clone());
            if first_time {
                let connection_clone = self.clone();
                let packet_clone = packet.clone();
                let context_clone = context.clone();
                tokio::spawn(async move {
                    tcp_inband_probe(context_clone, connection_clone, packet_clone)
                        .await
                        .unwrap();
                    // https://rust-lang.github.io/async-book/07_workarounds/02_err_in_async_blocks.html
                    // Except that 'dyn Error' isn't Send so it can't go between threads - just unwrap for now
                    // Ok::<(), Box<dyn Error>>(()) // this magic hints return type to compiler
                });
            }
        }

        // TODO: look for outgoing selective acks (indicates packet loss)
    }

    fn update_tcp_remote(&mut self, packet: &OwnedParsedPacket, tcp: &TcpHeader) {
        if tcp.syn {
            self.remote_syn = Some(packet.clone()); // memcpy() but doesn't happen that much or with much data
        }
        // TODO: look for incoming selective acks (indicates packet loss)
    }
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
