extern crate prost_types;

include!(concat!(env!("OUT_DIR"), "/conntrack.rs"));

fn ipv4_octets_to_pb_v4(octets: &[u8; 4]) -> ip_addr::Ip {
    let mut res = 0u32;
    for octet in octets {
        res = (res << 8) | (*octet as u32);
    }
    ip_addr::Ip::V4(res)
}

impl From<std::net::IpAddr> for IpAddr {
    fn from(net_ip: std::net::IpAddr) -> Self {
        match net_ip {
            std::net::IpAddr::V4(v4) => IpAddr {
                ip: Some(ipv4_octets_to_pb_v4(&v4.octets())),
            },
            std::net::IpAddr::V6(v6) => IpAddr {
                ip: Some(ip_addr::Ip::V6(v6.octets().into_iter().collect())),
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn use_symbols_from_protobuf() {
        let _ = IpAddr::default();
        let _ = ConnectionStorageEntry::default();
    }

    #[test]
    fn test_ipv4_octets_to_pb_v4() {
        use ip_addr::Ip::V4;
        let mut octets: [u8; 4] = [127, 0, 0, 1];
        assert_eq!(ipv4_octets_to_pb_v4(&octets), V4(0x7F00_0001));

        octets = [0xaa, 0x42, 0x23, 0];
        assert_eq!(ipv4_octets_to_pb_v4(&octets), V4(0xaa42_2300));
    }

    #[test]
    fn test_ip_conversion_from_std_to_pb() {
        use ip_addr::Ip;
        use std::net::Ipv4Addr;
        use std::net::Ipv6Addr;
        let mut net_ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            IpAddr::from(net_ip),
            IpAddr {
                ip: Some(Ip::V4(0x7F00_0001))
            }
        );

        net_ip = std::net::IpAddr::V6(Ipv6Addr::from_str("aa42:2300::0102").unwrap());
        assert_eq!(
            IpAddr::from(net_ip),
            IpAddr {
                ip: Some(Ip::V6(vec![
                    0xaa, 0x42, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x01, 0x02,
                ]))
            }
        );
    }
}
