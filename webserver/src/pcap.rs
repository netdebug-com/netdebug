use std::{
    collections::{HashMap, HashSet},
    error::Error,
    net::IpAddr,
};

use crate::{
    in_band_probe::{tcp_inband_probe, PROBE_MAX_TTL},
    utils::etherparse_ipheaders2ipaddr,
};
use etherparse::{
    Icmpv4Header, Icmpv6Header, IpHeader, IpNumber, TcpHeader, TransportHeader, UdpHeader,
};
use futures_util::StreamExt;
use log::{info, warn};
use pcap::{Capture, PacketHeader};
use std::hash::{Hash, Hasher};

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
#[derive(Clone, Debug, Eq, PartialEq)]
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

/**
 * Need to implement this by hand b/c a bunch of the underlying data
 * doesn't implement hash itself
 *
 * Kinda annoying - will need to make this more complete if we use
 * this for more than just the HashMap() packet tracking
 */
impl Hash for OwnedParsedPacket {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sloppy_hash().hash(state);
    }
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
    fn to_connection_key(
        &self,
        local_addrs: &HashSet<IpAddr>,
        local_tcp_ports: &HashSet<u16>,
    ) -> Option<(ConnectionKey, bool)> {
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
                // NOTE: if local_ip == remote_ip, e.g., 127.0.0.1,
                // we also need to check the tcp ports to figure out
                // which side is 'local'/matches the webserver
                if local_ip != remote_ip || local_tcp_ports.contains(&local_l4_port) {
                    Some((
                        ConnectionKey {
                            local_ip,
                            remote_ip,
                            local_l4_port,
                            remote_l4_port,
                            ip_proto: IpNumber::Tcp as u8,
                        },
                        source_is_local,
                    ))
                } else {
                    Some((
                        ConnectionKey {
                            local_ip,
                            remote_ip,
                            remote_l4_port: local_l4_port, // swap b/c we guessed backwards
                            local_l4_port: remote_l4_port,
                            ip_proto: IpNumber::Tcp as u8,
                        },
                        false,
                    ))
                }
            }
            Some(Udp(udp)) => {
                let (local_l4_port, remote_l4_port): (u16, u16) = if source_is_local {
                    (udp.source_port, udp.destination_port)
                } else {
                    (udp.destination_port, udp.source_port)
                };
                Some((
                    ConnectionKey {
                        local_ip,
                        remote_ip,
                        local_l4_port,
                        remote_l4_port,
                        ip_proto: IpNumber::Udp as u8,
                    },
                    source_is_local, // TODO: figure out UDP + src_ip == dst_ip case
                ))
            }
            Some(Icmpv4(icmp4)) => {
                self.to_icmp4_connection_key(icmp4, local_addrs, local_tcp_ports)
            }
            Some(Icmpv6(icmp6)) => {
                self.to_icmp6_connection_key(icmp6, local_addrs, local_tcp_ports)
            }
        }
    }

    fn to_icmp4_connection_key(
        &self,
        icmp4: &etherparse::Icmpv4Header,
        local_addrs: &HashSet<IpAddr>,
        local_tcp_ports: &HashSet<u16>,
    ) -> Option<(ConnectionKey, bool)> {
        use etherparse::Icmpv4Type::*;
        match &icmp4.icmp_type {
            Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            } => None,
            EchoReply(_) => None,
            DestinationUnreachable(_d) => {
                self.to_icmp_payload_connection_key(local_addrs, local_tcp_ports)
            }
            Redirect(_) => todo!(),
            EchoRequest(_) => None,
            TimeExceeded(_) => self.to_icmp_payload_connection_key(local_addrs, local_tcp_ports),
            ParameterProblem(_) => None,
            TimestampRequest(_) => None,
            TimestampReply(_) => None,
        }
    }

    /**
     * Look at the packet embedded in the ICMP{v4,v6} payload, parse it,
     * and return the key for the matching flow
     *
     * Should work for both v4 and v6 packets - crazy
     */
    fn to_icmp_payload_connection_key(
        &self,
        local_addrs: &HashSet<IpAddr>,
        local_tcp_ports: &HashSet<u16>,
    ) -> Option<(ConnectionKey, bool)> {
        match etherparse::PacketHeaders::from_ip_slice(&self.payload) {
            // case #1 - we didn't find a full packet
            Err(e1) => {
                // if the embedded packet is TCP, then we don't get the full
                // TCP header, only 8 bytes which is enough to recreate the
                // connection key.  Just manually parse and fake the rest
                match IpHeader::from_slice(&self.payload) {
                    Ok((ip, ip_proto, l4)) => {
                        if l4.len() < 4 {
                            return None; // ICMP standard is >= 8, so we should have at least 4 but oh well...
                        }
                        // unwrap here should be ok: Ip parsed and it's not None
                        let (sip, dip) = etherparse_ipheaders2ipaddr(Some(ip)).unwrap();
                        // extract the dst/src port in the packet; already verified length is there
                        // rust tries to make this hard - maybe someone smarter could do this cleaner :-/
                        let sport_bytes = <&[u8; 2]>::try_from(&l4[0..=1]).unwrap();
                        let sport = u16::from_be_bytes(*sport_bytes);
                        let dport_bytes = <&[u8; 2]>::try_from(&l4[2..=3]).unwrap();
                        let dport = u16::from_be_bytes(*dport_bytes);

                        Some((
                            ConnectionKey {
                                local_ip: sip,
                                remote_ip: dip,
                                local_l4_port: sport,
                                remote_l4_port: dport,
                                ip_proto,
                            },
                            false,
                        ))
                    }
                    Err(e) => {
                        warn!("Tried hard but Unparsed inner ICMP packet - skipping - first try: {}, second: {}", e1, e);
                        None
                    }
                }
            }
            // we did find a full packet
            Ok(embedded) => {
                // NOTE: Source NAT's are smart enough that if there is
                // an ICMP reply for a source NAT'd IP, it will parse into
                // the ICMP embedded packet and rewrite that BACK to the
                // original/local IP.  Net net - this check doesn't need
                // to know about the external/global IP even though that's
                // what was on the packet when it's TTL expired - crazy

                // Make this PacketHeader look like an OwnedParsedPacket to
                // recursively re-use the to_connection_key() logic.  But
                // NOTE that the returned src_is_local logic will be wrong
                let owned = OwnedParsedPacket {
                    pcap_header: pcap::PacketHeader {
                        ts: libc::timeval {
                            tv_sec: 0,
                            tv_usec: 0,
                        },
                        caplen: 0,
                        len: 0,
                    },
                    link: None,
                    vlan: None,
                    ip: embedded.ip,
                    transport: embedded.transport,
                    payload: embedded.payload.to_vec(),
                };
                match owned.to_connection_key(local_addrs, local_tcp_ports) {
                    Some((key, _src_is_local)) => {
                        // TODO: I can't convince myself there isn't a bug
                        // here if the src actually sources an ICMP message
                        // rather than just receives it.. maybe add a test?
                        // For now, just hard code the common case where an
                        // ICMP reply seen at the src should be either from
                        // the remote or for a connection we're not tracking
                        // e.g., like a locally running `ping`
                        Some((key, false))
                    }
                    None => {
                        warn!(
                            "Failed to parse a key out of an embedded ICMP pkt: {:?}",
                            self
                        );
                        None
                    }
                }
            }
        }
    }

    fn to_icmp6_connection_key(
        &self,
        icmp6: &etherparse::Icmpv6Header,
        local_addrs: &HashSet<IpAddr>,
        local_tcp_ports: &HashSet<u16>,
    ) -> Option<(ConnectionKey, bool)> {
        match icmp6.icmp_type {
            etherparse::Icmpv6Type::ParameterProblem(_)
            | etherparse::Icmpv6Type::TimeExceeded(_)
            | etherparse::Icmpv6Type::PacketTooBig { mtu: _ }
            | etherparse::Icmpv6Type::DestinationUnreachable(_) => {
                self.to_icmp_payload_connection_key(local_addrs, local_tcp_ports)
            }
            // no embedded packet for these types
            etherparse::Icmpv6Type::Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            } => None,
            etherparse::Icmpv6Type::EchoRequest(_) => None,
            etherparse::Icmpv6Type::EchoReply(_) => None,
        }
    }

    /**
     * Take a partial L3/IP packet, e.g., like one embedded in an ICMP response, and try
     * our best to parse as much of it as we can
     *
     * If we can reconstruct a packet, return it AND a bool for whether it's a
     * full packet or not.  A false return value implies that fields past 8 bytes
     * into the TCP header are all zero and should be ignored.
     *
     * Error out if we can't at least figure out the IP and L4 pieces
     */

    fn from_partial_embedded_ip_packet(
        buf: &[u8],
        pcap_header: Option<pcap::PacketHeader>,
    ) -> Result<(OwnedParsedPacket, bool), Box<dyn Error>> {
        let pcap_header = match pcap_header {
            Some(hdr) => hdr,
            None => pcap::PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: buf.len() as u32,
                len: buf.len() as u32,
            },
        };
        match etherparse::PacketHeaders::from_ip_slice(buf) {
            // case #1 - we didn't find a full packet
            Err(e1) => {
                // try to at least get an IP packet - fail if not
                let (ip, ip_proto, l4) = IpHeader::from_slice(buf)?;
                if l4.len() < 4 {
                    return Err(
                        pcap::Error::PcapError("Not even a full IP header".to_string()).into(),
                    );
                    // ICMP standard is >= 8, so we should have at least 4 but oh well...
                }
                if ip_proto != etherparse::ip_number::TCP {
                    return Err(pcap::Error::PcapError(format!(
                        "Failed partial read of ip-proto={} packet {:?}",
                        ip_proto, buf
                    ))
                    .into());
                }
                // if the embedded packet is TCP (and only TCP), then we don't get the full
                // TCP header, only 8 bytes which is enough to recreate the
                // header.  Just manually parse and fake the rest
                // extract the dst/src port in the packet; already verified length is there
                // rust tries to make this hard - maybe someone smarter could do this cleaner :-/
                let sport_bytes = <&[u8; 2]>::try_from(&l4[0..=1]).unwrap();
                let sport = u16::from_be_bytes(*sport_bytes);
                let dport_bytes = <&[u8; 2]>::try_from(&l4[2..=3]).unwrap();
                let dport = u16::from_be_bytes(*dport_bytes);
                let seq_bytes = <&[u8; 4]>::try_from(&l4[4..=8]).unwrap();
                let seq = u32::from_be_bytes(*seq_bytes);

                let tcph = TcpHeader {
                    source_port: sport,
                    destination_port: dport,
                    sequence_number: seq,
                    acknowledgment_number: 0,
                    _data_offset: 0,
                    ns: None,
                    fin: todo!(),
                    syn: todo!(),
                    rst: todo!(),
                    psh: todo!(),
                    ack: todo!(),
                    urg: todo!(),
                    ece: todo!(),
                    cwr: todo!(),
                    window_size: todo!(),
                    checksum: todo!(),
                    urgent_pointer: todo!(),
                    options_buffer: todo!(),
                };
                Ok((
                    OwnedParsedPacket {
                        pcap_header,
                        link: None,
                        vlan: None,
                        ip: Some(ip),
                        transport: Some(TransportHeader::Tcp(tcph)),
                        payload: Vec::new(), // zero length
                    },
                    false,
                ))
            }
            // we did find a full packet - easy case without parital reconstruction
            Ok(embedded) => {
                // NOTE: Source NAT's are smart enough that if there is
                // an ICMP reply for a source NAT'd IP, it will parse into
                // the ICMP embedded packet and rewrite that BACK to the
                // original/local IP.  Net net - this check doesn't need
                // to know about the external/global IP even though that's
                // what was on the packet when it's TTL expired - crazy

                // Make this PacketHeader look like an OwnedParsedPacket to
                // recursively re-use the to_connection_key() logic.  But
                // NOTE that the returned src_is_local logic will be wrong
                Ok((
                    OwnedParsedPacket {
                        pcap_header,
                        link: None,
                        vlan: None,
                        ip: embedded.ip,
                        transport: embedded.transport,
                        payload: embedded.payload.to_vec(),
                    },
                    true,
                ))
            }
        }
    }

    #[cfg(test)]
    fn try_from(pkt: pcap::Packet) -> Result<OwnedParsedPacket, Box<dyn Error>> {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(pkt.data)?;
        Ok(OwnedParsedPacket::new(parsed, pkt.header.clone()))
    }

    #[cfg(test)]
    /**
     * Utility to simplify testing - don't use in real code
     */
    fn try_from_fake_time(pkt: Vec<u8>) -> Result<OwnedParsedPacket, Box<dyn Error>> {
        let pcap_header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: pkt.len() as u32,
            len: pkt.len() as u32,
        };
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(&pkt)?;
        Ok(OwnedParsedPacket::new(parsed, pcap_header))
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

/***
 * Maintain the state for a bunch of connections.   Also, cache some information
 * that doesn't change often, e.g. ,the local IP addresses and listen port of
 * the webserver so we don't need to get the information from the WebServerContext every
 * packet.  The assumption is that if that information changes (e.g., new IP address),
 * then we would spin up new ConnectionTracker instances.
 */

struct ConnectionTracker<R>
where
    R: RawSocketWriter,
{
    context: Context,
    connections: HashMap<ConnectionKey, Connection>,
    local_addrs: HashSet<IpAddr>,
    local_tcp_ports: HashSet<u16>,
    raw_sock: R,
}
impl<R> ConnectionTracker<R>
where
    R: RawSocketWriter,
{
    async fn new(
        context: Context,
        local_addrs: HashSet<IpAddr>,
        raw_sock: R,
    ) -> ConnectionTracker<R> {
        let mut local_tcp_ports = HashSet::new();
        local_tcp_ports.insert(context.read().await.local_tcp_listen_port);
        ConnectionTracker {
            context,
            connections: HashMap::new(),
            local_addrs,
            local_tcp_ports,
            raw_sock,
        }
    }

    fn add(&mut self, packet: OwnedParsedPacket) {
        if let Some((key, src_is_local)) =
            packet.to_connection_key(&self.local_addrs, &self.local_tcp_ports)
        {
            if let Some(connection) = self.connections.get_mut(&key) {
                connection.update(
                    &self.context,
                    packet,
                    &mut self.raw_sock,
                    &key,
                    src_is_local,
                )
            } else {
                self.new_connection(packet, key, src_is_local)
            }
        }
        // if we got here, the packet didn't have enough info to be called a 'connection'
        // just return and move on for now
    }

    fn new_connection(
        &mut self,
        packet: OwnedParsedPacket,
        key: ConnectionKey,
        src_is_local: bool,
    ) {
        let mut connection = Connection {
            local_syn: None,
            remote_syn: None,
            local_seq: None,
            local_ack: None,
            local_data: None,
            outgoing_probe_timestamps: HashMap::new(),
            incoming_reply_timestamps: HashMap::new(),
        };
        info!("Tracking new connection: {}", &key);

        connection.update(
            &self.context,
            packet,
            &mut self.raw_sock,
            &key,
            src_is_local,
        );
        self.connections.insert(key, connection);
    }
}

type ProbeId = u8;
#[derive(Clone, Debug)]
pub struct Connection {
    pub local_syn: Option<OwnedParsedPacket>,
    pub remote_syn: Option<OwnedParsedPacket>,
    pub local_seq: Option<u32>,
    pub local_ack: Option<u32>,
    pub local_data: Option<Vec<u8>>, // data sent for retransmits
    pub outgoing_probe_timestamps: HashMap<ProbeId, HashSet<OwnedParsedPacket>>,
    pub incoming_reply_timestamps: HashMap<ProbeId, HashSet<OwnedParsedPacket>>,
}
impl Connection {
    fn update<R>(
        &mut self,
        context: &Context,
        packet: OwnedParsedPacket,
        raw_sock: &mut R,
        key: &ConnectionKey,
        src_is_local: bool,
    ) where
        R: RawSocketWriter,
    {
        match &packet.transport {
            Some(TransportHeader::Tcp(tcp)) => {
                if src_is_local {
                    self.update_tcp_local(context, &packet, tcp, raw_sock);
                } else {
                    self.update_tcp_remote(&packet, tcp);
                }
            }
            Some(TransportHeader::Icmpv4(icmp4)) => {
                if src_is_local {
                    warn!(
                        "Ignoring weird ICMP4 from our selves but for this connection: {} : {:?}",
                        key, packet
                    );
                } else {
                    self.update_icmp4_remote(context, &packet, icmp4);
                }
            }
            Some(TransportHeader::Icmpv6(icmp6)) => {
                todo!("Need to implement icmp6 handling")
            }
            _ => warn!("Got Connection::update() for non-TCP packet - ignoring for now"),
        }
    }

    /**
     * To avoid storing copies of all data, particularly in a high-speed connection,
     * we need a heuristic to separate outgoing probe packets and incoming incoming_reply_timestamps
     * from regular traffic...
     * .. but one that isn't obviously different enought to concern an IDS.
     *
     * It's performance issue if we mark too many packets as probes, so err on the
     * inclusive side and just say "any packet with a small payload" is a probe.
     *
     * Use the payload length to encode the probe ID/ttl
     */

    fn is_probe_heuristic(
        &self,
        src_is_local: bool,
        packet: &OwnedParsedPacket,
    ) -> Option<ProbeId> {
        // any packet with a small payload is a probe
        if packet.payload.len() <= PROBE_MAX_TTL as usize {
            if src_is_local {
                // for outgoing packets, the TTL of the probe is the ttl of the outer packet
                let ttl = match &packet.ip {
                    None => None, // no IP header, not a probe
                    Some(IpHeader::Version4(ip4, _)) => Some(ip4.time_to_live),
                    Some(IpHeader::Version6(ip6, _)) => Some(ip6.hop_limit),
                };
                if let Some(t) = ttl {
                    if t > PROBE_MAX_TTL {
                        return None; // can't have a probe with a ttl larger than we would send
                    }
                }
                return ttl; // else assume the heuristicis correct
            }
        } else {
            // TODO: need to parse into the packet to extract the encapped payload and thus the probe ID
            return None;
        }
        None
    }

    fn update_tcp_local<R>(
        &mut self,
        context: &Context,
        packet: &OwnedParsedPacket,
        tcp: &TcpHeader,
        raw_sock: &mut R,
    ) where
        R: RawSocketWriter,
    {
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
                let packet_clone = packet.clone();
                let context_clone = context.clone();
                tcp_inband_probe(context_clone, packet_clone, raw_sock).unwrap();
            }
        }
        if let Some(ttl) = self.is_probe_heuristic(true, packet) {
            // there's some super clean rust-ish way to compress this; don't care for now
            if let Some(probes) = self.outgoing_probe_timestamps.get_mut(&ttl) {
                probes.insert(packet.clone());
            } else {
                let mut probes = HashSet::new();
                probes.insert(packet.clone());
                self.outgoing_probe_timestamps.insert(ttl, probes);
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

    fn update_icmp4_remote(
        &self,
        context: &Context,
        packet: &OwnedParsedPacket,
        icmp4: &etherparse::Icmpv4Header,
    ) {
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

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    use crate::context::test::make_test_context;
    use crate::in_band_probe::test::test_tcp_packet_ports;
    /**
     *  ConnectionKey should be a direction agnostic key for mapping packets
     * to a flow identifier.  but, the logic around "is the src of the packet"
     * from the "local process" is complicated - test all of the permutations
     */
    #[tokio::test]
    async fn src_is_local() {
        let local_ip = IpAddr::from_str("192.168.1.1").unwrap();
        let remote_ip = IpAddr::from_str("192.168.1.2").unwrap();
        let localhost_ip = IpAddr::from_str("127.0.0.1").unwrap();
        let mut local_addrs = HashSet::new();
        local_addrs.insert(local_ip);
        local_addrs.insert(localhost_ip); // both the local ip and the localhost ip are 'local'
        let mut local_tcp_ports = HashSet::new();
        local_tcp_ports.insert(3030);

        let local_pkt = test_tcp_packet_ports(local_ip, remote_ip, 21, 12345);
        let (l_key, src_is_local) = local_pkt
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(src_is_local);

        let remote_pkt = test_tcp_packet_ports(remote_ip, local_ip, 12345, 21);
        let (r_key, src_is_local) = remote_pkt
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(!src_is_local);

        assert_eq!(l_key, r_key);

        let local_localhost_pkt = test_tcp_packet_ports(localhost_ip, localhost_ip, 3030, 12345);
        let (ll_key, src_is_local) = local_localhost_pkt
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(src_is_local);

        let remote_localhost_pkt = test_tcp_packet_ports(localhost_ip, localhost_ip, 12345, 3030);
        let (rl_key, src_is_local) = remote_localhost_pkt
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(!src_is_local);

        assert_eq!(ll_key, rl_key);
    }

    #[tokio::test]
    async fn connection_tracker_one_flow_outgoing() {
        let context = make_test_context();
        let raw_sock = MockRawSocketWriter::new();
        let mut local_addrs = HashSet::new();
        let localhost_ip = IpAddr::from_str("127.0.0.1").unwrap();
        local_addrs.insert(localhost_ip);
        let mut connection_tracker = ConnectionTracker::new(context, local_addrs, raw_sock).await;

        let mut capture =
            pcap::Capture::from_file("tests/simple_websocket_cleartxt_out_probes.pcap").unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            connection_tracker.add(owned_pkt);
        }
        assert_eq!(connection_tracker.connections.len(), 1);
        let connection = connection_tracker.connections.values().next().unwrap();
        // TODO; verify more about these pkts
        let _local_syn = connection.local_syn.as_ref().unwrap();
        let _remote_syn = connection.remote_syn.as_ref().unwrap();

        // verify we captured each of the outgoing probes
        assert_eq!(
            connection.outgoing_probe_timestamps.len(),
            PROBE_MAX_TTL as usize
        );
        for probes in connection.outgoing_probe_timestamps.values() {
            assert_eq!(probes.len(), 1);
        }
    }

    #[tokio::test]
    /**
     * Follow a TCP stream with outgoing probes and incoming replies and make sure
     * we can match them up to calculate RTTs, etc.
     */
    async fn connection_tracker_one_flow_out_and_in() {
        let context = make_test_context();
        let raw_sock = MockRawSocketWriter::new();
        let mut local_addrs = HashSet::new();
        let local_ip = IpAddr::from_str("172.31.2.61").unwrap();
        local_addrs.insert(local_ip);
        let mut local_tcp_ports = HashSet::new();
        local_tcp_ports.insert(3030);
        let mut connection_tracker =
            ConnectionTracker::new(context, local_addrs.clone(), raw_sock).await;

        let mut connection_key: Option<ConnectionKey> = None;
        let mut capture =
            pcap::Capture::from_file("tests/simple_websocket_cleartext_remote_probe_replies.pcap")
                .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            let (key, _) = owned_pkt
                .to_connection_key(&local_addrs, &local_tcp_ports)
                .unwrap();
            if let Some(prev_key) = connection_key {
                assert_eq!(prev_key, key);
            }
            connection_key = Some(key);
            connection_tracker.add(owned_pkt);
        }
        assert_eq!(connection_tracker.connections.len(), 1);
        let connection = connection_tracker.connections.values().next().unwrap();
        // TODO; verify more about these pkts
        let _local_syn = connection.local_syn.as_ref().unwrap();
        let _remote_syn = connection.remote_syn.as_ref().unwrap();

        // verify we captured each of the outgoing probes
        assert_eq!(
            connection.outgoing_probe_timestamps.len(),
            PROBE_MAX_TTL as usize
        );
        // verify we captured each of the incoming replies - note that we only got six replies!
        assert_eq!(connection.incoming_reply_timestamps.len(), 6);
        for probes in connection.outgoing_probe_timestamps.values() {
            assert_eq!(probes.len(), 1);
        }
    }

    #[tokio::test]
    /**
     * Make sure a probe and the corresponding ICMPv4 reply map to the same
     * connection key and the src_is_local logic is correct for both
     *
     * TODO: add ICMPv6 version of this test
     */
    async fn icmp4_to_connection_key() {
        pretty_env_logger::init();

        let mut local_addrs = HashSet::new();
        local_addrs.insert(IpAddr::from_str("172.31.2.61").unwrap());
        let mut local_tcp_ports = HashSet::new();
        local_tcp_ports.insert(3030);
        let probe = OwnedParsedPacket::try_from_fake_time(vec![
            0x06, 0x25, 0x76, 0xbf, 0x7a, 0x4f, 0x06, 0x2e, 0x63, 0x19, 0xe4, 0xd3, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x40, 0x00, 0x02, 0x06, 0x75, 0xfb, 0xac, 0x1f,
            0x02, 0x3d, 0x4b, 0x0b, 0x09, 0x6c, 0x01, 0xbb, 0xa1, 0x0e, 0x13, 0x87, 0x86, 0x22,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x01, 0xe6, 0x26, 0x62, 0x00, 0x00, 0x48, 0x54,
        ])
        .unwrap();

        let icmp_reply = OwnedParsedPacket::try_from_fake_time(vec![
            0x06, 0x2e, 0x63, 0x19, 0xe4, 0xd3, 0x06, 0x25, 0x76, 0xbf, 0x7a, 0x4f, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0xf5, 0x01, 0x56, 0x0b, 0x34, 0x5d,
            0x8d, 0x00, 0xac, 0x1f, 0x02, 0x3d, 0x0b, 0x00, 0xb8, 0x8c, 0x00, 0x00, 0x00, 0x00,
            0x45, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x40, 0x00, 0x01, 0x06, 0x76, 0xf6, 0xac, 0x1f,
            0x02, 0x3d, 0x4b, 0x0b, 0x09, 0x6c, 0x01, 0xbb, 0xa1, 0x0e, 0x13, 0x87, 0x86, 0x22,
        ])
        .unwrap();
        let (probe_key, src_is_local) = probe
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(src_is_local);

        let (reply_key, src_is_local) = icmp_reply
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(!src_is_local);

        assert_eq!(probe_key, reply_key);
    }
}
