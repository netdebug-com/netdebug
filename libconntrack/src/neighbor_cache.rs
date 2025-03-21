use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Utc};
use etherparse::icmpv6::{TYPE_NEIGHBOR_ADVERTISEMENT, TYPE_NEIGHBOR_SOLICITATION};
use libconntrack_wasm::ExportedNeighborState;
use log::warn;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::net::IpAddr;
use tokio::sync::mpsc::Sender;

use common_wasm::evicting_hash_map::EvictingHashMap;
use etherparse::{ether_type, EtherType, TransportHeader};
use mac_address::MacAddress;

use crate::owned_packet::OwnedParsedPacket;
use crate::system_tracker::BROADCAST_MAC_ADDR;

/**
 * A cache of all of the information we've learned about our neighbors
 * (v4 and v6) that we've learned on our local network.  For now this is
 * just an IP to MAC address mapping but for the future we can support
 * mDNS and Bonjour craziness.
 */

pub type NeighborCacheSender = Sender<(IpAddr, MacAddress)>;

#[derive(Clone, Debug, PartialEq)]
pub enum LookupMacByIpResult {
    Found,
    NotFound,
}

#[derive(Clone, Debug)]
pub struct NeighborState {
    pub mac: MacAddress,
    pub learn_time: DateTime<Utc>,
}

// NOTE: can't derive Clone/Debug/Default due to EvictingHashMap
pub struct NeighborCache<'a> {
    pub ip2mac: EvictingHashMap<'a, IpAddr, NeighborState>,
    /// Keep a list of agents that want to get updates about each IP to Mac address binding
    /// The 'String' is a human-readible identifier for who is listening; needs to be unique across
    /// the program ]
    ///
    /// Would love to use HashSet() but tokio::sync::mpsc::Sender() doesn't implement Eq or PartialEq :-(
    pub pending_lookups: EvictingHashMap<'a, IpAddr, HashMap<String, NeighborCacheSender>>,
    pub oui_db: Option<mac_oui::Oui>,
}

impl<'a> NeighborCache<'a> {
    pub fn new(max_elements: usize) -> NeighborCache<'a> {
        // initialize the MAC Vendor OUI DB from the online URL
        // NOTE: there is a "load from file" version we could move to if this proves unhappy
        let oui_db = match mac_oui::Oui::default() {
            Ok(oui) => Some(oui),
            Err(e) => {
                warn!(
                    "Failed to initialize the remote OUI MAC Vendor DB - not filling them in:{}",
                    e
                );
                None
            }
        };
        NeighborCache {
            ip2mac: EvictingHashMap::new(max_elements, |_, _| {
                // TODO: add a counter here
            }),
            pending_lookups: EvictingHashMap::new(max_elements, |_, _| {}),
            oui_db,
        }
    }

    /// Lookup this IP in our cache; no magic
    ///
    /// Reminder: internally EvictHashMap is modifying its state to track
    /// LRU info, so this function needs to be mutable even though the
    /// returned value is immutable
    pub fn lookup_mac_by_ip(&mut self, ip: &IpAddr) -> Option<MacAddress> {
        self.ip2mac
            .get_mut(ip)
            .map(|neighbor_state| neighbor_state.mac)
    }

    /// Try to lookup this IP: if it's there, send it on the tx queue.
    /// If it's not, add it to the pending queue in case we learn it later
    /// If we fail to look this up, we expect the caller to actually send a
    /// neighbor lookup out
    pub fn lookup_mac_by_ip_pending(
        &mut self,
        identifier: String,
        ip: &IpAddr,
        tx: NeighborCacheSender,
    ) -> LookupMacByIpResult {
        if let Some(mac) = self.lookup_mac_by_ip(ip) {
            if let Err(e) = tx.try_send((*ip, mac)) {
                warn!(
                    "Tried to send lookup_mac_by_ip_pending() back to caller but got: {}",
                    e
                );
            }
            LookupMacByIpResult::Found
        } else {
            // TODO: would be nice if EvictingHashMap supported the entry() API
            if let Some(map) = self.pending_lookups.get_mut(ip) {
                map.insert(identifier, tx);
            } else {
                self.pending_lookups
                    .insert(*ip, HashMap::from([(identifier, tx)]));
            }
            LookupMacByIpResult::NotFound
        }
    }

    /**
     * Parse this packet as an ARP.
     * - if it's a request, record the info of the sender
     * - if it's a reply, record the info of the sender and receiver
     */
    pub fn process_arp_packet(
        &mut self,
        packet: Box<OwnedParsedPacket>,
    ) -> Result<(), NeighborParseError> {
        // make sure this is an ARP packet (reply or request)
        if let Some(ethheader) = &packet.link {
            if ethheader.ether_type != EtherType::Arp as u16 {
                return Err(NeighborParseError::NotArp {
                    ether_type: ethheader.ether_type,
                });
            }
        } else {
            return Err(NeighborParseError::NotEthernet);
        }
        // parse it
        let arp = ArpPacket::from_wire(&packet.payload)?;
        // and learn all of the addresses we can
        self.learn(
            &arp.get_sender_ip(),
            &arp.get_sender_mac(),
            packet.timestamp,
        );
        self.learn(
            &arp.get_target_ip(),
            &arp.get_target_mac(),
            packet.timestamp,
        );

        Ok(())
    }

    /// if both IP and Mac are defined, add them to our mapping
    /// Gracefully handles 're'learning of IPs we've already learned
    pub(crate) fn learn(
        &mut self,
        ip: &Option<IpAddr>,
        mac: &Option<MacAddress>,
        learn_time: DateTime<Utc>,
    ) {
        if let (Some(ip), Some(mac)) = (ip, mac) {
            self.ip2mac.insert(
                *ip,
                NeighborState {
                    mac: *mac,
                    learn_time,
                },
            );
            if let Some(list) = self.pending_lookups.get_mut(ip) {
                // updated anyone waiting for this ip --> mac mapping
                for (identifier, tx) in list {
                    if let Err(e) = tx.try_send((*ip, *mac)) {
                        warn!(
                            "Tried to updated pending ip to mac for {}'s tx but got:{}",
                            identifier, e
                        );
                    }
                }
                // clear the list
                self.pending_lookups.remove(ip);
            }
        }
        // else do nothing
    }

    pub fn lookup_mac_vendor(&self, mac: &MacAddress) -> Option<String> {
        if let Some(oui_db) = &self.oui_db {
            match oui_db.lookup_by_mac(mac.to_string().as_str()) {
                // TODO: there's a lot more info here - think about if we want to include it
                /* Entry{
                    oui: "70:B3:D5",
                    is_private: false,
                    company_name: "Ieee Registration Authority",
                    company_address: "445 Hoes Lane Piscataway NJ 08554 US",
                    country_code: "US",
                    assignment_block_size: "MA-L",
                    date_created: "2014-01-12",
                    date_updated: "2016-04-27",
                } */
                Ok(Some(info)) => Some(info.company_name.clone()),
                // this means db lookup worked, but not in DB
                Ok(None) => None,
                Err(e) => {
                    warn!("Failed to lookup MacAddress Vendor: {}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    /// Write out a snapshot of our neighbor table when asked, probably for GUI
    pub(crate) fn export_neighbors(&self) -> Vec<libconntrack_wasm::ExportedNeighborState> {
        self.ip2mac
            .iter()
            .map(|(ip, neighbor_state)| ExportedNeighborState {
                ip: *ip,
                mac: neighbor_state.mac.to_string(),
                learn_time: neighbor_state.learn_time,
                vendor_oui: self.lookup_mac_vendor(&neighbor_state.mac),
            })
            .collect()
    }

    /// Parse the NDP solitiation msg to record the Mac and IPv6 address of the sender
    /// or the NDP advertisment msg to record the Mac and IPv6 address of the sender
    ///
    /// See https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol#Messages_formats for format
    /// but it's basically: first 4 bytes are reserved, second 16 bytes at the target address
    pub fn process_ndp_packet(
        &mut self,
        packet: Box<OwnedParsedPacket>,
    ) -> Result<(), NeighborParseError> {
        use etherparse::Icmpv6Type::*;
        // make sure we've really got the right kind of packet
        if packet.link.is_none() {
            return Err(NeighborParseError::NoIpv6);
        }
        // Always learn that the src ip maps to the src mac
        let (src_ip, _dst_ip) = packet.as_ref().get_src_dst_ips().unwrap();
        let is_advertisement = match packet.transport {
            Some(TransportHeader::Icmpv6(icmpv6)) => match icmpv6.icmp_type {
                Unknown { type_u8, .. } if type_u8 == TYPE_NEIGHBOR_ADVERTISEMENT => true,
                Unknown { type_u8, .. } if type_u8 == TYPE_NEIGHBOR_SOLICITATION => false,
                _ => return Err(NeighborParseError::NotNDP),
            },
            _ => return Err(NeighborParseError::NotNDP),
        };

        if packet.payload.len() < MIN_NDP_SIZE {
            return Err(NeighborParseError::PacketTooShort {
                size: packet.payload.len(),
                min_size: MIN_NDP_SIZE,
            });
        }
        // .unwrap() ok b/c we checked it's not None above
        let src_mac = MacAddress::from(packet.link.unwrap().source);
        self.learn(&Some(src_ip), &Some(src_mac), packet.timestamp);
        // For our purposes, the ADVERTISEMENT and SOLICITATION packets can be parsed the same way.
        // Technically, with ADVERTISEMENT packets, the first 3 bytes of the reserved bytes5to8
        // have been allocated/have meaning, but we don't care about that meaning for now so just ignore
        // TODO: look through the myriad (!) options that could follow this and decide if there's useful
        // data that we can use; ignore it all for now
        if is_advertisement {
            let mut cursor = Cursor::new(packet.payload);
            let mut ip_buf = [0; 16];
            cursor.read_exact(&mut ip_buf)?;
            let ip = IpAddr::from(ip_buf);
            // NOTE: I've not see a case where 'target_ip' is not the same as 'src_ip' and thus this
            // is redundant with the IP learned above, but this is my
            // understanding of the spec, so let's record this just in case they're different
            self.learn(&Some(ip), &Some(src_mac), packet.timestamp);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NeighborParseError {
    #[error("Can't parse as Arp: Not an Ethernet packet")]
    NotEthernet,
    #[error("Can't parse as Arp: Ethertype is {}", ether_type)]
    NotArp { ether_type: u16 },
    #[error("Can't parse as Arp: packet too short: {} < {}", size, min_size)]
    PacketTooShort { size: usize, min_size: usize },
    #[error("Can't parse as Arp: variable length inconistently short")]
    ShortRead(#[from] std::io::Error),
    #[error("Can't make an Arp: use NDP instead of Arp for IPv6")]
    NoIpv6,
    #[error("Can't make an NDP packet: transport not ICMP6")]
    NotNDP,
}

/// full description of Arp at : https://en.wikipedia.org/wiki/Address_Resolution_Protocol
/// A complete Arp packet; no attempt is made to optimize copying - they just
/// don't happen that often
///
/// Admittedly, this is a little over-engineered in anticipation of trying to land this
/// in the etherparse crate
#[derive(Clone, Debug)]
pub struct ArpPacket {
    pub htype: ArpHardwareType,
    pub ptype: ArpProtocolType,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    pub operation: ArpOperation,
    pub sender_hardware_address: Vec<u8>,
    pub sender_protocol_address: Vec<u8>,
    /// This will be all zeros if ArVec::from_iter(buffer[offset..next_offset].iter().cloned());pOperation is Request
    pub target_hardware_address: Vec<u8>,
    pub target_protocol_address: Vec<u8>,
}

pub const MIN_NDP_SIZE: usize = 16; // 16 bytes of IPv6 target address
const ARP_MIN_SIZE: usize = 28; // for a normal ethernet + IPv4 packet
const ARP_FIXED_SIZE: usize = 8; // just the part of the Arp packet that's fixed length
impl ArpPacket {
    pub fn from_wire(buffer: &Vec<u8>) -> Result<ArpPacket, NeighborParseError> {
        if buffer.len() < ARP_MIN_SIZE {
            return Err(NeighborParseError::PacketTooShort {
                size: buffer.len(),
                min_size: ARP_MIN_SIZE,
            });
        }
        let mut reader = Cursor::new(buffer);
        let htype = ArpHardwareType::from_wire(reader.read_u16::<BigEndian>().unwrap());
        let ptype = ArpProtocolType::from_wire(reader.read_u16::<BigEndian>().unwrap());
        let hw_addr_len = reader.read_u8().unwrap();
        let proto_addr_len = reader.read_u8().unwrap();
        let operation = ArpOperation::from_wire(reader.read_u16::<BigEndian>().unwrap());
        // parse out the variable parts of the packet
        let mut sender_hardware_address = vec![0; hw_addr_len as usize];
        reader.read_exact(&mut sender_hardware_address)?;
        let mut sender_protocol_address = vec![0; proto_addr_len as usize];
        reader.read_exact(&mut sender_protocol_address)?;
        let mut target_hardware_address = vec![0; hw_addr_len as usize];
        reader.read_exact(&mut target_hardware_address)?;
        let mut target_protocol_address = vec![0; proto_addr_len as usize];
        reader.read_exact(&mut target_protocol_address)?;
        // done!

        Ok(ArpPacket {
            htype,
            ptype,
            hw_addr_len,
            proto_addr_len,
            operation,
            sender_hardware_address,
            sender_protocol_address,
            target_hardware_address,
            target_protocol_address,
        })
    }

    /**
     * Create an ethernet packet from this Arp without a VLAN tag
     *
     * Assume the src mac is the sender_hardware_address
     * If the Operation is Request, then dst mac is broadcast else use target_hardware_address
     *
     * panic if called on a non-ethernet packet
     */
    pub fn to_ethernet_pkt(&self) -> Result<Vec<u8>, std::io::Error> {
        assert_eq!(self.htype, ArpHardwareType::Ethernet);
        let pkt_size = ARP_FIXED_SIZE + (self.hw_addr_len * 2 + self.proto_addr_len * 2) as usize;
        let pkt = Vec::with_capacity(pkt_size);
        let mut writer = Cursor::new(pkt);
        // dst mac first
        if self.operation == ArpOperation::Reply {
            writer.write_all(&self.target_hardware_address)?;
        } else {
            writer.write_all(&BROADCAST_MAC_ADDR)?;
        }
        // src mac
        writer.write_all(&self.sender_hardware_address)?;
        writer.write_u16::<BigEndian>(ether_type::ARP)?;
        // now the rest of the arp packet
        writer.write_u16::<BigEndian>(self.htype.into())?;
        writer.write_u16::<BigEndian>(self.ptype.into())?;
        writer.write_u8(self.hw_addr_len)?;
        writer.write_u8(self.proto_addr_len)?;
        writer.write_u16::<BigEndian>(self.operation.into())?;
        writer.write_all(&self.sender_hardware_address)?;
        writer.write_all(&self.sender_protocol_address)?;
        writer.write_all(&self.target_hardware_address)?;
        writer.write_all(&self.target_protocol_address)?;

        Ok(writer.into_inner())
    }

    pub fn new_request(
        local_mac: [u8; 6],
        local_ip: IpAddr,
        target_ip: IpAddr,
    ) -> Result<ArpPacket, NeighborParseError> {
        match (local_ip, target_ip) {
            (IpAddr::V4(local_ip), IpAddr::V4(target_ip)) => Ok(ArpPacket {
                htype: ArpHardwareType::Ethernet,
                ptype: ArpProtocolType::IPv4,
                hw_addr_len: 6,
                proto_addr_len: 4,
                operation: ArpOperation::Request,
                sender_hardware_address: Vec::from(local_mac),
                sender_protocol_address: Vec::from(local_ip.octets()),
                target_hardware_address: vec![0; 6],
                target_protocol_address: Vec::from(target_ip.octets()),
            }),
            _ => Err(NeighborParseError::NoIpv6),
        }
    }

    /// If the htype is Ethernet and the hlen is 6, return the sender's hardware address as a MacAddress
    pub fn get_sender_mac(&self) -> Option<MacAddress> {
        self.helper_as_mac_address(&self.sender_hardware_address)
    }

    /// If the htype is Ethernet and the hlen is 6, return the sender's hardware address as a MacAddress
    /// AND the ArpOperation is Reply
    pub fn get_target_mac(&self) -> Option<MacAddress> {
        match self.operation {
            ArpOperation::Reply => self.helper_as_mac_address(&self.target_hardware_address),
            _ => None,
        }
    }

    /// If the ptype is Ipv4 and the plen is 4, return the protocol address as an IpAddr
    pub fn get_sender_ip(&self) -> Option<IpAddr> {
        self.helper_as_ipv4_address(&self.sender_protocol_address)
    }

    /// If the ptype is Ipv4 and the plen is 4, return the protocol address as an IpAddr
    pub fn get_target_ip(&self) -> Option<IpAddr> {
        self.helper_as_ipv4_address(&self.target_protocol_address)
    }

    pub fn helper_as_mac_address(&self, buffer: &[u8]) -> Option<MacAddress> {
        match (&self.htype, self.hw_addr_len) {
            (ArpHardwareType::Ethernet, 6) if buffer.len() == 6 => Some(MacAddress::from(
                TryInto::<[u8; 6]>::try_into(buffer).unwrap(),
            )),
            _ => None,
        }
    }
    pub fn helper_as_ipv4_address(&self, buffer: &[u8]) -> Option<IpAddr> {
        match (&self.ptype, self.proto_addr_len) {
            (ArpProtocolType::IPv4, 4) if buffer.len() == 4 => {
                Some(IpAddr::from(TryInto::<[u8; 4]>::try_into(buffer).unwrap()))
            }
            _ => None,
        }
    }
}

const ARP_HTYPE_ETHERNET: u16 = 1;
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u16)]
pub enum ArpHardwareType {
    Ethernet = ARP_HTYPE_ETHERNET,
    Unknown(u16),
}

// seems like this shouldn't be necessary but the 'as u16' wasn't working
impl From<ArpHardwareType> for u16 {
    fn from(value: ArpHardwareType) -> Self {
        match value {
            ArpHardwareType::Ethernet => ARP_HTYPE_ETHERNET,
            ArpHardwareType::Unknown(t) => t,
        }
    }
}

impl ArpHardwareType {
    /// Convert from host byte order to ArpHardwareType
    pub fn from_wire(htype: u16) -> ArpHardwareType {
        use ArpHardwareType::*;
        match htype {
            ARP_HTYPE_ETHERNET => Ethernet,
            _unknown => Unknown(_unknown),
        }
    }
}

/// shares the same namespace with ethertypes, but is ostensibly different
const ARP_PROTOCOL_IPV4: u16 = etherparse::ether_type::IPV4;
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u16)]
pub enum ArpProtocolType {
    IPv4 = ARP_PROTOCOL_IPV4,
    Unknown(u16),
}

impl From<ArpProtocolType> for u16 {
    fn from(value: ArpProtocolType) -> Self {
        match value {
            ArpProtocolType::IPv4 => ARP_PROTOCOL_IPV4,
            ArpProtocolType::Unknown(p) => p,
        }
    }
}
impl ArpProtocolType {
    /// Convert from host byte order to ArpProtocolType
    pub fn from_wire(ptype: u16) -> ArpProtocolType {
        use ArpProtocolType::*;
        match ptype {
            ARP_PROTOCOL_IPV4 => IPv4,
            _unknown => Unknown(_unknown),
        }
    }
}

const ARP_OPERATION_REQUEST: u16 = 1;
const ARP_OPERATION_REPLY: u16 = 2;
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u16)]
pub enum ArpOperation {
    Request = ARP_OPERATION_REQUEST,
    Reply = ARP_OPERATION_REPLY,
    Unknown(u16),
}

impl From<ArpOperation> for u16 {
    fn from(value: ArpOperation) -> Self {
        match value {
            ArpOperation::Request => ARP_OPERATION_REQUEST,
            ArpOperation::Reply => ARP_OPERATION_REPLY,
            ArpOperation::Unknown(o) => o,
        }
    }
}

impl ArpOperation {
    pub fn from_wire(op: u16) -> ArpOperation {
        use ArpOperation::*;
        match op {
            ARP_OPERATION_REQUEST => Request,
            ARP_OPERATION_REPLY => Reply,
            _unknown => Unknown(_unknown),
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::{net::IpAddr, str::FromStr};

    use common::test_utils::test_dir;
    use mac_address::MacAddress;

    use crate::{neighbor_cache::ArpOperation, owned_packet::OwnedParsedPacket};

    use super::{ArpPacket, NeighborCache};

    #[test]
    fn test_arp_parse() {
        let mut capture =
            pcap::Capture::from_file(test_dir("libconntrack", "tests/arp_capture.pcap")).unwrap();
        // from the trace, the first arp we see is an unresolved request
        let arp_request_random =
            OwnedParsedPacket::try_from_pcap(capture.next_packet().unwrap()).unwrap();
        // the second is a proper request....
        let arp_request = OwnedParsedPacket::try_from_pcap(capture.next_packet().unwrap()).unwrap();
        // with a proper reply
        let arp_reply = OwnedParsedPacket::try_from_pcap(capture.next_packet().unwrap()).unwrap();

        let sender_mac = MacAddress::from([0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82]);
        let sender_ip = IpAddr::from_str("192.168.1.34").unwrap();
        let target_ip = IpAddr::from_str("192.168.1.222").unwrap();

        let test_arp_random = ArpPacket::from_wire(&arp_request_random.payload).unwrap();
        assert_eq!(test_arp_random.get_sender_mac().unwrap(), sender_mac);
        assert_eq!(test_arp_random.get_sender_ip().unwrap(), sender_ip);
        assert_eq!(test_arp_random.get_target_ip().unwrap(), target_ip);
        assert_eq!(test_arp_random.get_target_mac(), None);
        assert_eq!(test_arp_random.operation, ArpOperation::Request);

        // next arp, sender mac and ip are unchanged, but the target is new
        let target_ip = IpAddr::from_str("192.168.1.1").unwrap();
        let sender_mac = MacAddress::from([0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82]);
        let sender_ip = IpAddr::from_str("192.168.1.34").unwrap();
        let test_arp_request = ArpPacket::from_wire(&arp_request.payload).unwrap();
        assert_eq!(test_arp_request.get_sender_mac().unwrap(), sender_mac);
        assert_eq!(test_arp_request.get_sender_ip().unwrap(), sender_ip);
        assert_eq!(test_arp_request.get_target_ip().unwrap(), target_ip);
        assert_eq!(test_arp_request.get_target_mac(), None);
        assert_eq!(test_arp_request.operation, ArpOperation::Request);

        // last, parse the reply; everything the same as before but we have an answer!
        // but the target and sender are swapped
        let sender_mac = MacAddress::from([0xc8, 0x54, 0x4b, 0x43, 0xda, 0x3e]);
        let sender_ip = IpAddr::from_str("192.168.1.1").unwrap();
        let target_mac = MacAddress::from([0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82]);
        let target_ip = IpAddr::from_str("192.168.1.34").unwrap();

        let test_arp_reply = ArpPacket::from_wire(&arp_reply.payload).unwrap();
        assert_eq!(test_arp_reply.get_sender_mac().unwrap(), sender_mac);
        assert_eq!(test_arp_reply.get_sender_ip().unwrap(), sender_ip);
        assert_eq!(test_arp_reply.get_target_ip().unwrap(), target_ip);
        assert_eq!(test_arp_reply.get_target_mac(), Some(target_mac));
        assert_eq!(test_arp_reply.operation, ArpOperation::Reply);
    }

    /**
     * Pull captured Arps from pcap, parse them to an Arp then write them back to the wire
     * and make sure they match where they came from
     *
     * This test assumes that Arp parsing/reading works properly; if not both tests will fail
     */
    #[test]
    fn test_arp_writing() {
        let mut capture =
            pcap::Capture::from_file(test_dir("libconntrack", "tests/arp_capture.pcap")).unwrap();

        while let Ok(raw_pkt) = capture.next_packet() {
            let parsed_pkt = OwnedParsedPacket::try_from_pcap(raw_pkt.clone()).unwrap();
            let arp = ArpPacket::from_wire(&parsed_pkt.payload).unwrap();
            let test_writen_packet = arp.to_ethernet_pkt().unwrap();
            assert_eq!(test_writen_packet, raw_pkt.data);
        }
    }

    #[test]
    fn test_ip_mac_learning() {
        let mut neighbors = NeighborCache::new(4098);
        let mut capture =
            pcap::Capture::from_file(test_dir("libconntrack", "tests/arp_capture.pcap")).unwrap();
        // from the trace, the first arp we see is an unresolved request
        let arp_request_random =
            OwnedParsedPacket::try_from_pcap(capture.next_packet().unwrap()).unwrap();
        // the second is a proper request....
        let arp_request = OwnedParsedPacket::try_from_pcap(capture.next_packet().unwrap()).unwrap();
        // with a proper reply
        let arp_reply = OwnedParsedPacket::try_from_pcap(capture.next_packet().unwrap()).unwrap();

        neighbors.process_arp_packet(arp_request_random).unwrap();
        neighbors.process_arp_packet(arp_request).unwrap();
        neighbors.process_arp_packet(arp_reply).unwrap();

        let router_mac = MacAddress::from([0xc8, 0x54, 0x4b, 0x43, 0xda, 0x3e]);
        let router_ip = IpAddr::from_str("192.168.1.1").unwrap();
        let laptop_mac = MacAddress::from([0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82]);
        let laptop_ip = IpAddr::from_str("192.168.1.34").unwrap();

        assert_eq!(neighbors.ip2mac.len(), 2); // trace only has two different hosts
        assert_eq!(neighbors.lookup_mac_by_ip(&router_ip), Some(router_mac));
        assert_eq!(neighbors.lookup_mac_by_ip(&laptop_ip), Some(laptop_mac));
    }

    #[test]
    fn test_ndp_parsing() {
        // pulled from wireshark
        let target_ip = IpAddr::from([
            0x26, 0x00, 0x17, 0x00, 0x5b, 0x20, 0x4e, 0x10, 0x78, 0xeb, 0xea, 0x4d, 0x7d, 0x28,
            0x08, 0xd7,
        ]);
        let mut capture =
            pcap::Capture::from_file(test_dir("libconntrack", "tests/ndp_solicit_advert.pcapng"))
                .unwrap();
        // from the trace, the first arp we see is an unresolved request
        let solicit = OwnedParsedPacket::try_from_pcap(capture.next_packet().unwrap()).unwrap();
        let advert = OwnedParsedPacket::try_from_pcap(capture.next_packet().unwrap()).unwrap();
        let mut neighbor_cache = NeighborCache::new(4096);
        assert_eq!(neighbor_cache.ip2mac.len(), 0);
        // learn what we can from the solicitation
        neighbor_cache.process_ndp_packet(solicit.clone()).unwrap();
        assert_eq!(neighbor_cache.ip2mac.len(), 1);
        let (expected_src_ip, _dst_ip) = solicit.get_src_dst_ips().unwrap();
        let (expected_src_mac, _dst_mac) = solicit.get_src_dst_mac_addresses().unwrap();
        assert_learned(&mut neighbor_cache, expected_src_ip, expected_src_mac);

        // learn what we can from the reply advertisement: two different IPs to the same MacAddress
        neighbor_cache.process_ndp_packet(advert.clone()).unwrap();
        let (expected_src_ip, _dst_ip) = advert.get_src_dst_ips().unwrap();
        let (expected_src_mac, _dst_mac) = advert.get_src_dst_mac_addresses().unwrap();
        assert_eq!(neighbor_cache.ip2mac.len(), 2);
        // these are actually identical ips, in this capture; are they ever different?
        assert_learned(&mut neighbor_cache, expected_src_ip, expected_src_mac);
        assert_learned(&mut neighbor_cache, target_ip, expected_src_mac);
    }

    pub fn assert_learned(neighbor_cache: &mut NeighborCache, ip: IpAddr, mac: MacAddress) {
        let state = neighbor_cache.ip2mac.get_mut(&ip).unwrap();
        assert_eq!(state.mac, mac);
    }
}
