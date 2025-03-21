use std::{
    collections::HashSet,
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use chrono::{DateTime, Utc};
use etherparse::{
    icmpv6::{TYPE_NEIGHBOR_ADVERTISEMENT, TYPE_NEIGHBOR_SOLICITATION},
    EtherType, IcmpEchoHeader, Icmpv4Header, Icmpv6Header, IpHeader, TcpHeader, TransportHeader,
    UdpHeader,
};
use libconntrack_wasm::{ConnectionKey, IpProtocol};
use log::warn;
use mac_address::MacAddress;
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Serialize};

/// The salient information from ICMPv4 of ICMPv6 echo request /
/// echo reply packet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpEchoInfo {
    pub id: u16,
    pub seq: u16,
    pub is_reply: bool,
    pub payload: Vec<u8>,
}

impl IcmpEchoInfo {
    fn new(hdr: IcmpEchoHeader, is_reply: bool, payload: Vec<u8>) -> Self {
        Self {
            id: hdr.id,
            seq: hdr.seq,
            is_reply,
            payload,
        }
    }
}

/// Errors when trying to create a `ConnectionKey` from a OwnedParsedPacket
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionKeyError {
    /// Neither src nor dst IPs are a local IP. A common case for this is
    /// multicast or broadcast traffic received. Esp. bonjour/mDns which
    /// used DNS-over-multicast is a frequent offender
    NoLocalAddr,
    /// The packet contained no (usable) L3 and/or L4 header. Or it was an ICMP type
    /// we are not handling.
    IgnoredPacket,
    /// The packet was in ICMP message of a type we handle but we failed to parse/
    /// extract the inner packet.
    IcmpInnerPacketError,
    /// This packet is an Arp, so no ConnectionKey but will want other parsing for it
    Arp,
    /// This packet is an Neighbor Discovery Protocol msg, so no ConnectionKey but will want other parsing for it
    NdpNeighbor,
}

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
    //pub pcap_header: pcap::PacketHeader,
    /// The pcap timestamp when the packet was captured
    pub timestamp: DateTime<Utc>,
    /// The length of the packet, in bytes (which might be more than the number of bytes available
    /// from the capture, if the length of the packet is larger than the maximum number of bytes to
    /// capture)
    pub len: u32,
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
impl std::hash::Hash for OwnedParsedPacket {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.sloppy_hash().hash(state);
    }
}

fn pcap_timestamp_to_utc(pcap_header: &pcap::PacketHeader) -> DateTime<Utc> {
    use chrono::TimeZone;
    Utc.timestamp_opt(
        #[allow(clippy::useless_conversion)] // needed because timeval differs between OSes
        pcap_header.ts.tv_sec.into(),
        (pcap_header.ts.tv_usec * 1000) as u32,
    )
    .unwrap()
    // TODO: should we handle conversion errors more gracefully??
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
            timestamp: pcap_timestamp_to_utc(&pcap_header),
            len: pcap_header.len,
            link: headers.link,
            vlan: headers.vlan,
            ip: headers.ip,
            transport: headers.transport,
            payload: headers.payload.to_vec(),
        }
    }

    pub fn from_headers_and_ts(
        headers: etherparse::PacketHeaders,
        timestamp: DateTime<Utc>,
        len: u32,
    ) -> OwnedParsedPacket {
        OwnedParsedPacket {
            timestamp,
            len,
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
                    hash ^= ip4.source[i];
                }
                for i in 0..=3 {
                    hash ^= ip4.destination[i];
                }
                return hash;
            }
            Some(Version6(ip6, _)) => {
                let mut hash = 0;
                for i in 0..=3 {
                    hash ^= ip6.source[i];
                }
                for i in 0..=3 {
                    hash ^= ip6.destination[i];
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
                    hash ^= e.source[i];
                }
                for i in 0..=5 {
                    hash ^= e.destination[i];
                }
                hash
            }
            None => 0, // just give up, this packet didn't even have an l2 header!?
        }
    }

    pub fn get_src_dst_ips(&self) -> Option<(IpAddr, IpAddr)> {
        match &self.ip {
            Some(iph) => {
                match iph {
                    IpHeader::Version4(v4hdr, _) => Some((
                        IpAddr::V4(Ipv4Addr::from(v4hdr.source)),
                        IpAddr::V4(Ipv4Addr::from(v4hdr.destination)),
                    )),
                    IpHeader::Version6(v6hdr, _) => Some((
                        IpAddr::V6(Ipv6Addr::from(v6hdr.source)),
                        IpAddr::V6(Ipv6Addr::from(v6hdr.destination)),
                    )),
                    //
                }
            }
            _ => None,
        }
    }

    pub fn get_src_dst_ports(&self) -> Option<(u16, u16)> {
        match &self.transport {
            Some(TransportHeader::Tcp(tcph)) => Some((tcph.source_port, tcph.destination_port)),
            Some(TransportHeader::Udp(udph)) => Some((udph.source_port, udph.destination_port)),
            _ => None,
        }
    }

    pub fn get_icmp_echo_info(&self) -> Option<IcmpEchoInfo> {
        // extract the relevant info
        match &self.transport {
            Some(TransportHeader::Icmpv4(icmp4)) => {
                use etherparse::Icmpv4Type::*;
                match icmp4.icmp_type {
                    EchoRequest(ping_hdr) => {
                        Some(IcmpEchoInfo::new(ping_hdr, false, self.payload.clone()))
                    }
                    EchoReply(ping_hdr) => {
                        Some(IcmpEchoInfo::new(ping_hdr, true, self.payload.clone()))
                    }
                    _ => None,
                }
            }
            Some(TransportHeader::Icmpv6(icmp6)) => {
                use etherparse::Icmpv6Type::*;
                match icmp6.icmp_type {
                    EchoRequest(ping_hdr) => {
                        Some(IcmpEchoInfo::new(ping_hdr, false, self.payload.clone()))
                    }
                    EchoReply(ping_hdr) => {
                        Some(IcmpEchoInfo::new(ping_hdr, true, self.payload.clone()))
                    }
                    _ => None,
                }
            }
            _ => None,
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
     *
     * On success it returns an `Ok(ConnectionKey, src_is_local)`. `src_is_local` is
     * a boolean indicating if the `src_ip` of the packet was local or remote
     *
     * TODO: this whole function (and the dependent functions) should probably be moved into
     * ConnectionKey
     */
    pub fn to_connection_key(
        &self,
        local_addrs: &HashSet<IpAddr>,
    ) -> Result<(ConnectionKey, bool), ConnectionKeyError> {
        let (local_ip, remote_ip, source_is_local) = match &self.ip {
            Some(IpHeader::Version4(ip4, _)) => {
                let source_ip = IpAddr::from(ip4.source);
                let dest_ip = IpAddr::from(ip4.destination);
                if local_addrs.contains(&source_ip) {
                    (source_ip, dest_ip, true)
                } else if local_addrs.contains(&dest_ip) {
                    (dest_ip, source_ip, false)
                } else {
                    return Err(ConnectionKeyError::NoLocalAddr);
                }
            }
            Some(IpHeader::Version6(ip6, _)) => {
                let source_ip = IpAddr::from(ip6.source);
                let dest_ip = IpAddr::from(ip6.destination);
                if local_addrs.contains(&source_ip) {
                    (source_ip, dest_ip, true)
                } else if local_addrs.contains(&dest_ip) {
                    (dest_ip, source_ip, false)
                } else {
                    return Err(ConnectionKeyError::NoLocalAddr);
                }
            }
            // if there's no IP layer, just return IgnoredPacket unless it's Arp
            None => {
                if self
                    .link
                    .as_ref()
                    .is_some_and(|l| l.ether_type == EtherType::Arp as u16)
                {
                    return Err(ConnectionKeyError::Arp);
                } else {
                    return Err(ConnectionKeyError::IgnoredPacket);
                }
            }
        };
        use etherparse::TransportHeader::*;
        match &self.transport {
            // no l4 protocol --> don't track this flow
            None => Err(ConnectionKeyError::IgnoredPacket),
            Some(Tcp(tcp)) => {
                let (local_l4_port, remote_l4_port) = if source_is_local {
                    (tcp.source_port, tcp.destination_port)
                } else {
                    (tcp.destination_port, tcp.source_port)
                };
                // NOTE: if local_ip == remote_ip, e.g., 127.0.0.1,
                // we also need to check the tcp ports to figure out
                // which side is 'local'/matches the webserver
                // if src_ip == dst_ip, tie break which is local by l4 port order
                if local_ip != remote_ip || local_l4_port < remote_l4_port {
                    Ok((
                        ConnectionKey {
                            local_ip,
                            remote_ip,
                            local_l4_port,
                            remote_l4_port,
                            ip_proto: IpProtocol::TCP,
                        },
                        source_is_local,
                    ))
                } else {
                    Ok((
                        ConnectionKey {
                            local_ip,
                            remote_ip,
                            remote_l4_port: local_l4_port, // swap b/c we guessed backwards
                            local_l4_port: remote_l4_port,
                            ip_proto: IpProtocol::TCP,
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
                Ok((
                    ConnectionKey {
                        local_ip,
                        remote_ip,
                        local_l4_port,
                        remote_l4_port,
                        ip_proto: IpProtocol::UDP,
                    },
                    source_is_local, // TODO: figure out UDP + src_ip == dst_ip case
                ))
            }
            Some(Icmpv4(icmp4)) => self.to_icmp4_connection_key(
                icmp4,
                local_ip,
                remote_ip,
                source_is_local,
                local_addrs,
            ),
            Some(Icmpv6(icmp6)) => self.to_icmp6_connection_key(
                icmp6,
                local_ip,
                remote_ip,
                source_is_local,
                local_addrs,
            ),
        }
    }

    fn to_icmp4_connection_key(
        &self,
        icmp4: &etherparse::Icmpv4Header,
        local_ip: IpAddr,
        remote_ip: IpAddr,
        src_is_local: bool,
        local_addrs: &HashSet<IpAddr>,
    ) -> Result<(ConnectionKey, bool), ConnectionKeyError> {
        use etherparse::Icmpv4Type::*;
        match &icmp4.icmp_type {
            Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            } => Err(ConnectionKeyError::IgnoredPacket),
            // map ping request/reply to the same key so they can be mapped
            EchoRequest(echo_hdr) | EchoReply(echo_hdr) => {
                make_icmp_ping_key(local_ip, remote_ip, src_is_local, echo_hdr)
            }
            DestinationUnreachable(_d) => self.to_icmp_payload_connection_key(local_addrs),
            Redirect(_) => Err(ConnectionKeyError::IgnoredPacket),
            TimeExceeded(_) => self.to_icmp_payload_connection_key(local_addrs),
            ParameterProblem(_) => Err(ConnectionKeyError::IgnoredPacket),
            TimestampRequest(_) => Err(ConnectionKeyError::IgnoredPacket),
            TimestampReply(_) => Err(ConnectionKeyError::IgnoredPacket),
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
    ) -> Result<(ConnectionKey, bool), ConnectionKeyError> {
        match OwnedParsedPacket::from_partial_embedded_ip_packet(
            &self.payload,
            DateTime::<Utc>::UNIX_EPOCH,
            0,
        ) {
            Err(e) => {
                warn!("Unparsed packet: {} : {:?}", e, self.payload);
                Err(ConnectionKeyError::IcmpInnerPacketError)
            }
            Ok((owned, _full_packet)) => {
                use ConnectionKeyError::*;
                // ignore if we parsed the full packet - doesn't matter for key
                match owned.to_connection_key(local_addrs) {
                    // Need to invert src_is_local, since the src of the inner packet is the
                    // destination of the outer ICMP packet
                    Ok((key, src_is_local)) => Ok((key, !src_is_local)),
                    Err(NoLocalAddr) => Err(NoLocalAddr), // Could happen if we e.g., have VMs running
                    Err(IgnoredPacket) => Err(IcmpInnerPacketError),
                    Err(IcmpInnerPacketError) => Err(IcmpInnerPacketError),
                    Err(Arp) => Err(IcmpInnerPacketError), // really can't happen
                    Err(NdpNeighbor) => Err(IcmpInnerPacketError), // don't think this can happen
                }
            }
        }
    }

    fn to_icmp6_connection_key(
        &self,
        icmp6: &etherparse::Icmpv6Header,
        local_ip: IpAddr,
        remote_ip: IpAddr,
        src_is_local: bool,
        local_addrs: &HashSet<IpAddr>,
    ) -> Result<(ConnectionKey, bool), ConnectionKeyError> {
        use etherparse::Icmpv6Type::*;
        match icmp6.icmp_type {
            ParameterProblem(_)
            | TimeExceeded(_)
            | PacketTooBig { mtu: _ }
            | DestinationUnreachable(_) => self.to_icmp_payload_connection_key(local_addrs),
            // no embedded packet for these types
            etherparse::Icmpv6Type::Unknown {
                type_u8,
                code_u8: _,
                bytes5to8: _,
            } if type_u8 == TYPE_NEIGHBOR_ADVERTISEMENT
                || type_u8 == TYPE_NEIGHBOR_SOLICITATION =>
            {
                Err(ConnectionKeyError::NdpNeighbor)
            }
            etherparse::Icmpv6Type::Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            } => Err(ConnectionKeyError::IgnoredPacket),
            etherparse::Icmpv6Type::EchoRequest(echo_hdr)
            | etherparse::Icmpv6Type::EchoReply(echo_hdr) => {
                make_icmp_ping_key(local_ip, remote_ip, src_is_local, &echo_hdr)
            }
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

    pub fn from_partial_embedded_ip_packet(
        buf: &[u8],
        timestamp: DateTime<Utc>,
        len: u32,
    ) -> Result<(OwnedParsedPacket, bool), Box<dyn Error>> {
        match etherparse::PacketHeaders::from_ip_slice(buf) {
            // case #1 - we didn't find a full packet
            Err(e1) => {
                // try to at least get an IP packet - fail if not
                let (ip, ip_proto, l4) = IpHeader::from_slice(buf)?;
                if l4.len() < 8 {
                    return Err(pcap::Error::PcapError(
                        "Not even a 8 bytes of a transport header".to_string(),
                    )
                    .into());
                    // ICMP standard is >= 8, so we should have at least 4 but oh well...
                }
                if ip_proto != etherparse::ip_number::TCP {
                    return Err(pcap::Error::PcapError(format!(
                        "Failed partial read of ip-proto={} packet {:?}: {}",
                        ip_proto, buf, e1
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
                let seq_bytes = <&[u8; 4]>::try_from(&l4[4..=7]).unwrap();
                let seq = u32::from_be_bytes(*seq_bytes);

                let tcph = TcpHeader::new(sport, dport, seq, 0);
                Ok((
                    OwnedParsedPacket {
                        timestamp,
                        len,
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
                        timestamp,
                        len,
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

    pub fn try_from_pcap(pkt: pcap::Packet) -> Result<Box<OwnedParsedPacket>, Box<dyn Error>> {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(pkt.data)?;
        Ok(Box::new(OwnedParsedPacket::new(parsed, *pkt.header)))
    }

    /// Truncate the payload of this packet to `len`. Useful for both
    /// performance as well as privacy
    pub fn truncate_payload(&mut self, len: usize) {
        self.payload.truncate(len);
    }

    #[cfg(test)]
    /**
     * Utility to simplify testing - don't use in real code
     */
    pub(crate) fn try_from_fake_time(
        pkt: Vec<u8>,
    ) -> Result<Box<OwnedParsedPacket>, Box<dyn Error>> {
        let pcap_header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: pkt.len() as u32,
            len: pkt.len() as u32,
        };
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(&pkt)?;
        Ok(Box::new(OwnedParsedPacket::new(parsed, pcap_header)))
    }

    /**
     * Utility to simplify testing - don't use in real code
     */
    #[cfg(test)]
    pub(crate) fn try_from_timestamp(
        pkt: Vec<u8>,
        ts: DateTime<Utc>,
    ) -> Result<Box<OwnedParsedPacket>, Box<dyn Error>> {
        let parsed = etherparse::PacketHeaders::from_ethernet_slice(&pkt)?;
        Ok(Box::new(OwnedParsedPacket::from_headers_and_ts(
            parsed,
            ts,
            pkt.len() as u32,
        )))
    }
    pub fn get_src_dst_mac_addresses(&self) -> Option<(MacAddress, MacAddress)> {
        self.link.as_ref().map(|hdr| {
            (
                MacAddress::from(hdr.source),
                MacAddress::from(hdr.destination),
            )
        })
    }
}

/**
 * We want the echo request and echo reply packets from the same ping stream/flow to have
 * the same connection key.  This means not just the src+dst IPs match and the ICMP types,
 * but also the IcmpEchoHeader.id (which traditionally is the pid of the ping process)
 *
 * Map all of this into a ConnectionKey
 */
fn make_icmp_ping_key(
    local_ip: IpAddr,
    remote_ip: IpAddr,
    src_is_local: bool,
    echo_hdr: &IcmpEchoHeader,
) -> Result<(ConnectionKey, bool), ConnectionKeyError> {
    Ok((
        ConnectionKey::make_icmp_echo_key(local_ip, remote_ip, echo_hdr.id),
        src_is_local,
    ))
}

/**
 * Grr - have to implement custom serialize/deserialize for OwnedParsedPacket
 * because none of their underyingly #%(*@&$*(&@!)) third-party structs
 * implement #[derive(Serialize,Deserialize)]
 *
 * NOTE that if the fields of OwnedParsedPacket change, this needs to be
 * manually updated!
 */

impl Serialize for OwnedParsedPacket {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // the pcap header doesn't implement serialize - hack around that
        let mut state = serializer.serialize_struct("struct OwnedParsedPacket", 6)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.serialize_field("len", &self.len)?;

        if let Some(eth) = &self.link {
            let mut buf = Vec::with_capacity(eth.header_len());
            // TODO : unwrap's here are annoying but .map_err() fought me and I lost :-(
            eth.write(&mut buf).unwrap();
            state.serialize_field("eth", buf.as_slice())?;
        }
        if let Some(vlan) = &self.vlan {
            let mut buf = Vec::with_capacity(vlan.header_len());
            vlan.write(&mut buf).unwrap();
            state.serialize_field("vlan", buf.as_slice())?;
        }
        if let Some(ip) = &self.ip {
            let mut buf = Vec::with_capacity(ip.header_len());
            ip.write(&mut buf).unwrap();
            state.serialize_field("ip", buf.as_slice())?;
        }
        if let Some(transport) = &self.transport {
            let mut buf = Vec::with_capacity(transport.header_len());
            transport.write(&mut buf).unwrap();
            // need to encode the transport type to decode easily
            use TransportHeader::*;
            let proto = match transport {
                Udp(_) => "Udp",
                Tcp(_) => "Tcp",
                Icmpv4(_) => "Icmp4",
                Icmpv6(_) => "Icmp6",
            }
            .to_string();
            state.serialize_field("transport", &(proto, buf.as_slice()))?;
        }
        state.serialize_field("payload", &self.payload)?;
        state.end()
    }
}

// Copying from https://serde.rs/deserialize-struct.html
impl<'de> Deserialize<'de> for OwnedParsedPacket {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Fields {
            Timestamp,
            Len,
            Eth,
            Vlan,
            Ip,
            Transport,
            Payload,
        }
        struct OwnedParsedPacketVisitor {}

        impl<'de> Visitor<'de> for OwnedParsedPacketVisitor {
            type Value = OwnedParsedPacket;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(r#"failed to deserialize OwnedParsedPacket"#)
            }

            // TODO : see if we need to implement visit_seq()

            /**
             * Super permissive deserializer; return an OwnedParsedPacket under almost
             * any circumstances
             */
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut pkt = OwnedParsedPacket {
                    timestamp: DateTime::<Utc>::UNIX_EPOCH,
                    len: 0,
                    link: None,
                    vlan: None,
                    ip: None,
                    transport: None,
                    payload: Vec::new(),
                };

                while let Some(key) = map.next_key::<Fields>()? {
                    match key {
                        Fields::Timestamp => {
                            pkt.timestamp = map.next_value::<DateTime<Utc>>()?;
                        }
                        Fields::Len => pkt.len = map.next_value::<u32>()?,
                        Fields::Eth => {
                            let buf = map.next_value::<Vec<u8>>()?;
                            let (hdr, _payload) =
                                etherparse::Ethernet2Header::from_slice(&buf).unwrap();
                            pkt.link = Some(hdr);
                        }
                        Fields::Vlan => {
                            todo!() // stoopid way of reading vlan headers; not needed now - fix if actually needed
                                    /*
                                    let buf = map.next_value::<Vec<u8>>()?;
                                    let (hdr, _payload) = etherparse::VlanHeader::(&buf).unwrap();
                                    pkt.vlan = Some(hdr);
                                    */
                        }
                        Fields::Ip => {
                            let buf = map.next_value::<Vec<u8>>()?;
                            let (hdr, _proto, _payload) =
                                etherparse::IpHeader::from_slice(&buf).unwrap();
                            pkt.ip = Some(hdr);
                        }
                        Fields::Transport => {
                            let (proto, buf) = map.next_value::<(String, Vec<u8>)>()?;
                            let hdr = match proto.as_str() {
                                // if anything is messed up, just panic - fix later if it's an issue
                                "Udp" => {
                                    Ok(TransportHeader::Udp(UdpHeader::from_slice(&buf).unwrap().0))
                                }
                                "Tcp" => {
                                    Ok(TransportHeader::Tcp(TcpHeader::from_slice(&buf).unwrap().0))
                                }
                                "Icmp4" => Ok(TransportHeader::Icmpv4(
                                    Icmpv4Header::from_slice(&buf).unwrap().0,
                                )),
                                "Icmp6" => Ok(TransportHeader::Icmpv6(
                                    Icmpv6Header::from_slice(&buf).unwrap().0,
                                )),
                                _ => Err(format!("Unknown transportheader {}", proto)),
                            }
                            .unwrap();
                            pkt.transport = Some(hdr);
                        }
                        Fields::Payload => {
                            pkt.payload = map.next_value::<Vec<u8>>()?;
                        }
                    }
                }
                Ok(pkt)
            }
        }
        const FIELDS: &[&str] = &["pcapheader", "eth", "vlan", "ip", "transport", "payload"];
        deserializer.deserialize_struct(
            "struct OwnedParsedPacket",
            FIELDS,
            OwnedParsedPacketVisitor {},
        )
    }
}

#[cfg(test)]
mod test {
    use chrono::TimeZone;
    use etherparse::ip_number;
    use itertools::Itertools;

    use crate::connection;

    use super::*;

    #[test]
    fn serialize() {
        let mut orig_pkt =
            OwnedParsedPacket::try_from_fake_time(connection::test::TEST_1_LOCAL_SYN.to_vec())
                .unwrap();
        // put real data in the pcap_header, so we test that as well
        orig_pkt.timestamp = Utc.timestamp_opt(1234, 567000).unwrap();
        orig_pkt.len = 8;
        let json = serde_json::to_string(&orig_pkt).unwrap();

        let new_pkt = serde_json::from_str(&json).unwrap();

        assert_eq!(orig_pkt, new_pkt);
    }

    #[test]
    fn test_get_src_dst_ips_v4() {
        use std::str::FromStr;
        let mut pkt_bytes: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
            .udp(1, 1)
            .write(&mut pkt_bytes, &[])
            .unwrap();
        let pkt = OwnedParsedPacket::try_from_fake_time(pkt_bytes).unwrap();
        assert_eq!(
            pkt.get_src_dst_ips().unwrap().0,
            IpAddr::from_str("192.168.1.1").unwrap()
        );
        assert_eq!(
            pkt.get_src_dst_ips().unwrap().1,
            IpAddr::from_str("192.168.1.2").unwrap()
        );
    }

    #[test]
    fn test_get_src_dst_ips_v6() {
        use std::str::FromStr;
        let mut pkt_bytes: Vec<u8> = Vec::new();
        let src = Ipv6Addr::from_str("2001:0db8::1").unwrap();
        let dst = Ipv6Addr::from_str("2001:0db8::4242").unwrap();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv6(src.octets(), dst.octets(), 64)
            .udp(1, 1)
            .write(&mut pkt_bytes, &[])
            .unwrap();
        let pkt = OwnedParsedPacket::try_from_fake_time(pkt_bytes).unwrap();
        assert_eq!(pkt.get_src_dst_ips().unwrap().0, IpAddr::V6(src));
        assert_eq!(pkt.get_src_dst_ips().unwrap().1, IpAddr::V6(dst));
    }

    #[test]
    fn test_get_src_dst_ports() {
        let mut pkt_bytes: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
            .udp(123, 456)
            .write(&mut pkt_bytes, &[])
            .unwrap();
        let pkt = OwnedParsedPacket::try_from_fake_time(pkt_bytes).unwrap();
        assert_eq!(pkt.get_src_dst_ports().unwrap(), (123, 456));

        let mut pkt_bytes: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
            .tcp(4242, 2323, 0, 0)
            .write(&mut pkt_bytes, &[])
            .unwrap();
        let pkt = OwnedParsedPacket::try_from_fake_time(pkt_bytes).unwrap();
        assert_eq!(pkt.get_src_dst_ports().unwrap(), (4242, 2323));

        // raw IP ==> no ports
        let mut pkt_bytes: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
            .write(&mut pkt_bytes, ip_number::EXP0, &[])
            .unwrap();
        let pkt = OwnedParsedPacket::try_from_fake_time(pkt_bytes).unwrap();
        assert_eq!(pkt.get_src_dst_ports(), None);

        let mut pkt_bytes: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
            .icmpv4_echo_request(0, 0)
            .write(&mut pkt_bytes, &[])
            .unwrap();
        let pkt = OwnedParsedPacket::try_from_fake_time(pkt_bytes).unwrap();
        assert_eq!(pkt.get_src_dst_ports(), None);
    }

    #[test]
    fn test_to_connection_key_v4() {
        use std::str::FromStr;
        let mut pkt_bytes: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
            .udp(123, 443)
            .write(&mut pkt_bytes, &[])
            .unwrap();
        let pkt = OwnedParsedPacket::try_from_fake_time(pkt_bytes).unwrap();

        let local_addrs = HashSet::from_iter([IpAddr::from_str("192.168.1.1").unwrap()]);
        let (conn_key, src_is_local) = pkt.to_connection_key(&local_addrs).unwrap();
        assert!(src_is_local);
        assert_eq!(conn_key.ip_proto, IpProtocol::UDP);
        assert_eq!(conn_key.local_l4_port, 123);
        assert_eq!(conn_key.remote_l4_port, 443);
        assert_eq!(conn_key.local_ip, IpAddr::from_str("192.168.1.1").unwrap());
        assert_eq!(conn_key.remote_ip, IpAddr::from_str("192.168.1.2").unwrap());

        // Now in reverse
        let local_addrs = HashSet::from_iter([IpAddr::from_str("192.168.1.2").unwrap()]);
        let (conn_key, src_is_local) = pkt.to_connection_key(&local_addrs).unwrap();
        assert!(!src_is_local);
        assert_eq!(conn_key.ip_proto, IpProtocol::UDP);
        assert_eq!(conn_key.local_l4_port, 443);
        assert_eq!(conn_key.remote_l4_port, 123);
        assert_eq!(conn_key.local_ip, IpAddr::from_str("192.168.1.2").unwrap());
        assert_eq!(conn_key.remote_ip, IpAddr::from_str("192.168.1.1").unwrap());

        // Neither IP is local
        let local_addrs = HashSet::from_iter([IpAddr::from_str("192.168.255.255").unwrap()]);
        assert_eq!(
            pkt.to_connection_key(&local_addrs),
            Err(ConnectionKeyError::NoLocalAddr)
        );
    }

    #[test]
    fn test_to_connection_key_v6() {
        use std::str::FromStr;
        let mut pkt_bytes: Vec<u8> = Vec::new();
        let src = Ipv6Addr::from_str("2001:0db8::1").unwrap();
        let dst = Ipv6Addr::from_str("2001:0db8::4242").unwrap();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv6(src.octets(), dst.octets(), 64)
            .tcp(123, 443, 4242 /* seq_no */, 65535 /* window */)
            .write(&mut pkt_bytes, &[])
            .unwrap();
        let pkt = OwnedParsedPacket::try_from_fake_time(pkt_bytes).unwrap();

        let local_addrs = HashSet::from_iter([IpAddr::V6(src)]);
        let (conn_key, src_is_local) = pkt.to_connection_key(&local_addrs).unwrap();
        assert!(src_is_local);
        assert_eq!(conn_key.ip_proto, IpProtocol::TCP);
        assert_eq!(conn_key.local_l4_port, 123);
        assert_eq!(conn_key.remote_l4_port, 443);
        assert_eq!(conn_key.local_ip, IpAddr::V6(src));
        assert_eq!(conn_key.remote_ip, IpAddr::V6(dst));

        // Now in reverse
        let local_addrs = HashSet::from_iter([IpAddr::V6(dst)]);
        let (conn_key, src_is_local) = pkt.to_connection_key(&local_addrs).unwrap();
        assert!(!src_is_local);
        assert_eq!(conn_key.ip_proto, IpProtocol::TCP);
        assert_eq!(conn_key.local_l4_port, 443);
        assert_eq!(conn_key.remote_l4_port, 123);
        assert_eq!(conn_key.local_ip, IpAddr::V6(dst));
        assert_eq!(conn_key.remote_ip, IpAddr::V6(src));

        // Neither IP is local
        let local_addrs = HashSet::from_iter([IpAddr::from_str("2001:0db8::123:456").unwrap()]);
        assert_eq!(
            pkt.to_connection_key(&local_addrs),
            Err(ConnectionKeyError::NoLocalAddr)
        );
    }

    /**
     * Build an icmp4 echo request/reply pair of packets, sanity check their ConnectionKeys and make sure they match
     */
    #[test]
    fn test_icmp4_ping() {
        let source_ip = IpAddr::from([1, 1, 1, 1]);
        let remote_ip = IpAddr::from([2, 2, 2, 2]);
        let local_addrs = HashSet::from([source_ip]);
        let builder = etherparse::PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([1, 1, 1, 1], [2, 2, 2, 2], 64)
            .icmpv4_echo_request(10, 2);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let mut echo_request = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut echo_request, &payload).unwrap();
        let echo_request_pkt = OwnedParsedPacket::try_from_fake_time(echo_request).unwrap();
        let (echo_request_key, src_is_local) =
            echo_request_pkt.to_connection_key(&local_addrs).unwrap();
        assert!(src_is_local);
        assert_eq!(echo_request_key.local_ip, source_ip);
        assert_eq!(echo_request_key.remote_ip, remote_ip);

        let builder = etherparse::PacketBuilder::ethernet2([2, 2, 2, 2, 2, 2], [1, 1, 1, 1, 1, 1])
            .ipv4([2, 2, 2, 2], [1, 1, 1, 1], 64)
            .icmpv4_echo_reply(10, 2);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        assert_eq!(echo_request_pkt.get_icmp_echo_info().unwrap().id, 10);
        assert_eq!(echo_request_pkt.get_icmp_echo_info().unwrap().seq, 2);
        assert!(!echo_request_pkt.get_icmp_echo_info().unwrap().is_reply,);
        assert_eq!(
            echo_request_pkt.get_icmp_echo_info().unwrap().payload,
            (1u8..=10).collect_vec()
        );

        // now build the reply
        let mut echo_reply = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut echo_reply, &payload).unwrap();
        let echo_reply_pkt = OwnedParsedPacket::try_from_fake_time(echo_reply).unwrap();
        let (echo_reply_key, src_is_local) =
            echo_reply_pkt.to_connection_key(&local_addrs).unwrap();
        assert!(!src_is_local);
        assert_eq!(echo_reply_key, echo_request_key);

        assert_eq!(echo_reply_pkt.get_icmp_echo_info().unwrap().id, 10);
        assert_eq!(echo_reply_pkt.get_icmp_echo_info().unwrap().seq, 2);
        assert!(echo_reply_pkt.get_icmp_echo_info().unwrap().is_reply,);
        assert_eq!(
            echo_reply_pkt.get_icmp_echo_info().unwrap().payload,
            (1u8..=10).collect_vec()
        );
    }

    /**
     * Build an icmp6 echo request/reply pair of packets, sanity check their ConnectionKeys and make sure they match
     */
    #[test]
    fn test_icmp6_ping() {
        let source_ip_raw = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let remote_ip_raw = [
            100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
        ];
        let source_ip = IpAddr::from(source_ip_raw);
        let remote_ip = IpAddr::from(remote_ip_raw);
        let local_addrs = HashSet::from([source_ip]);
        let builder = etherparse::PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv6(source_ip_raw, remote_ip_raw, 64)
            .icmpv6_echo_request(10, 2);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let mut echo_request = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut echo_request, &payload).unwrap();
        let echo_request_pkt = OwnedParsedPacket::try_from_fake_time(echo_request).unwrap();
        let (echo_request_key, src_is_local) =
            echo_request_pkt.to_connection_key(&local_addrs).unwrap();
        assert!(src_is_local);
        assert_eq!(echo_request_key.local_ip, source_ip);
        assert_eq!(echo_request_key.remote_ip, remote_ip);

        let builder = etherparse::PacketBuilder::ethernet2([2, 2, 2, 2, 2, 2], [1, 1, 1, 1, 1, 1])
            .ipv6(remote_ip_raw, source_ip_raw, 64)
            .icmpv6_echo_reply(10, 2);
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // now build the reply
        let mut echo_reply = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut echo_reply, &payload).unwrap();
        let echo_reply_pkt = OwnedParsedPacket::try_from_fake_time(echo_reply).unwrap();
        let (echo_reply_key, src_is_local) =
            echo_reply_pkt.to_connection_key(&local_addrs).unwrap();
        assert!(!src_is_local);
        assert_eq!(echo_reply_key, echo_request_key);
    }

    #[test]
    fn test_get_icmp_info_from_non_ping() {
        let mut pkt_bytes: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
            .udp(1, 1)
            .write(&mut pkt_bytes, &[])
            .unwrap();
        let pkt = OwnedParsedPacket::try_from_fake_time(pkt_bytes).unwrap();
        assert!(pkt.get_icmp_echo_info().is_none());
    }
}
