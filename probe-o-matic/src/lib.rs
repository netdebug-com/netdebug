use etherparse::{IpHeader, Ipv4Extensions, Ipv6Extensions};
use libconntrack::{connection::ConnectionTrackerMsg, pcap::RawSocketWriter};
use log::{info, warn};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::sync::mpsc;

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

#[derive(Clone, Debug)]
pub struct OutgoingAddressConfig {
    pub gateway_mac: mac_address::MacAddress,
    pub src_mac: mac_address::MacAddress,
    pub v4_src_addr: SocketAddrV4,
    pub v6_src_addr: SocketAddrV6,
    pub if_name: String,
}

pub enum ProbeOMaticMsg {
    ProbeAddr(IpAddr),
}

#[allow(unused)] // TODO: raw_sock and addr_config are unused for now
pub struct ProbeOMatic {
    pkt_rx: mpsc::UnboundedReceiver<ConnectionTrackerMsg>,
    probe_rx: mpsc::UnboundedReceiver<ProbeOMaticMsg>,
    raw_sock: Box<dyn RawSocketWriter>,
    addr_config: OutgoingAddressConfig,
}

impl ProbeOMatic {
    pub fn spawn(
        pkt_rx: mpsc::UnboundedReceiver<ConnectionTrackerMsg>,
        probe_rx: mpsc::UnboundedReceiver<ProbeOMaticMsg>,
        raw_sock: Box<dyn RawSocketWriter>,
        addr_config: OutgoingAddressConfig,
    ) -> tokio::task::JoinHandle<()> {
        let mut pom = ProbeOMatic {
            pkt_rx,
            probe_rx,
            raw_sock,
            addr_config,
        };
        tokio::spawn(async move {
            pom.rx_loop().await;
        })
    }

    pub async fn rx_loop(&mut self) {
        loop {
            tokio::select! {
                Some(conn_msg) = self.pkt_rx.recv() => self.handle_conn_msg(conn_msg),
                Some(probe_msg) = self.probe_rx.recv() => self.handle_probe_msg(probe_msg),
                else => break

            }
        }
        info!("Exiting rx_loop");
    }

    fn handle_conn_msg(&self, msg: ConnectionTrackerMsg) {
        use ConnectionTrackerMsg::*;
        match msg {
            Pkt(_pkt) => info!("Got a packet"),
            _ => warn!("We can only handle `Pkt` messages, but got: {:?}", msg),
        }
    }

    fn handle_probe_msg(&self, msg: ProbeOMaticMsg) {
        use ProbeOMaticMsg::*;
        match msg {
            ProbeAddr(_ip) => info!("Got a probe_rx msg"),
        }
    }
}

pub fn create_probe_packet(
    addr_config: &OutgoingAddressConfig,
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
    use etherparse::{PacketHeaders, TransportHeader};
    use mac_address::MacAddress;
    use std::{net::Ipv6Addr, str::FromStr};

    fn mk_addr_config() -> OutgoingAddressConfig {
        OutgoingAddressConfig {
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
}
