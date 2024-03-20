use chrono::SecondsFormat;
use etherparse::{IpHeader, TcpHeader, TransportHeader};
use libconntrack::owned_packet::OwnedParsedPacket;
use libconntrack_wasm::IpProtocol;

use crate::open_pcap_or_die;

#[derive(Debug, Clone, clap::ValueEnum, strum_macros::Display)]
#[strum(serialize_all = "kebab-case")]
pub enum PacketField {
    /// Packet timestamp as floating point since epoch
    Time,
    /// Packet timestamp as ISO formatted string
    Isotime,
    /// Source IP
    Sip,
    /// Destination IP
    Dip,
    /// Source Port
    Sport,
    /// Destination Port
    Dport,
    /// The length of the packet as reported by libpcap
    Len,
    /// The length of the packet from the IP header
    Iplen,
    /// The IP protocol / next header. String for some well known ones,
    /// raw number otherwise
    Proto,
    /// The IP ID for IPv4, 0 for IPv6
    Ipid,
    /// TTL
    Ttl,
    // Length of the payload (w/o IP and transport headers)
    // PayloadLen,
    /// TCP sequence number
    TcpSeqNo,
    /// TCP ack number
    TcpAckNo,

    /// Syn Flag. 'S' if set, else '-'
    TcpSyn,
    /// Fin Flag. 'F' if set, else '-'
    TcpFin,
    /// Rst Flag. 'R' if set, else '-'
    TcpRst,
    /// Ack Flag. 'A' if set, else '-'
    TcpAck,
    /// Push Flag. 'P' if set, else '-'
    TcpPsh,
}

/// Print selected fields for each packet in the trace. One line per
/// packet. Like ipsumdump.
#[derive(clap::Parser, Debug)]
pub struct SumdumpCmdArgs {
    /// Comma separated list of packet header fields to display
    #[arg(long, value_delimiter = ',')]
    fields: Vec<PacketField>,
    #[arg(long, default_value_t = false)]
    no_header: bool,
    pcap_file: String,
}

pub fn sumdump_command(pcap_filter: Option<String>, args: SumdumpCmdArgs) {
    let mut capture = open_pcap_or_die(&args.pcap_file);
    if let Some(pcap_filter) = pcap_filter {
        capture.filter(&pcap_filter, true).unwrap_or_else(|err| {
            panic!(
                "Failed to compile and apply filter `{}`: {}",
                pcap_filter, err
            )
        });
    }
    if !args.no_header {
        println!(
            "{}",
            args.fields
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<String>>()
                .join(" ")
        );
    }
    while let Ok(pcap_pkt) = capture.next_packet() {
        let pkt = OwnedParsedPacket::try_from_pcap(pcap_pkt).expect("Failed to parse packet");
        let res = handle_packet(&pkt, &args.fields);
        println!("{}", res.join(" "));
    }
}

fn get_tcp_header(pkt: &OwnedParsedPacket) -> Option<&TcpHeader> {
    match &pkt.transport {
        Some(TransportHeader::Tcp(tcph)) => Some(tcph),
        _ => None,
    }
}

fn tcp_flags(is_set: bool, symbol: char) -> Option<String> {
    if is_set {
        Some(symbol.to_string())
    } else {
        None
    }
}

fn ip_proto_to_string(proto: u8) -> String {
    let nice_proto = IpProtocol::from_wire(proto);
    match nice_proto {
        IpProtocol::Other(p) => p.to_string(),
        named_proto => named_proto.to_string(),
    }
}

fn handle_packet(pkt: &OwnedParsedPacket, fields: &Vec<PacketField>) -> Vec<String> {
    let mut ret = Vec::new();
    for field in fields {
        use PacketField::*;
        let field_value = match field {
            Time => {
                let unixtime = pkt.timestamp.timestamp() as f64
                    + pkt.timestamp.timestamp_subsec_nanos() as f64 / 1e9;
                Some(unixtime.to_string())
            }
            Isotime => Some(pkt.timestamp.to_rfc3339_opts(SecondsFormat::Micros, true)),
            Sip => pkt.get_src_dst_ips().map(|(src, _dst)| src.to_string()),
            Dip => pkt.get_src_dst_ips().map(|(_src, dst)| dst.to_string()),
            Sport => pkt.get_src_dst_ports().map(|(src, _dst)| src.to_string()),
            Dport => pkt.get_src_dst_ports().map(|(_src, dst)| dst.to_string()),
            Len => Some(pkt.len.to_string()),
            Iplen => match &pkt.ip {
                Some(IpHeader::Version4(iph, _)) => Some(iph.total_len().to_string()),
                Some(IpHeader::Version6(iph, _)) => {
                    Some((iph.header_len() as u16 + iph.payload_length).to_string())
                }
                None => None,
            },
            Proto => match &pkt.ip {
                Some(IpHeader::Version4(iph, _)) => Some(ip_proto_to_string(iph.protocol)),
                Some(IpHeader::Version6(iph, _)) => Some(ip_proto_to_string(iph.next_header)),
                None => None,
            },
            Ipid => match &pkt.ip {
                Some(IpHeader::Version4(iph, _)) => Some(iph.identification.to_string()),
                _ => None,
            },
            Ttl => match &pkt.ip {
                Some(IpHeader::Version4(iph, _)) => Some(iph.time_to_live.to_string()),
                Some(IpHeader::Version6(iph, _)) => Some(iph.hop_limit.to_string()),
                None => None,
            },
            TcpSeqNo => get_tcp_header(pkt).map(|tcph| tcph.sequence_number.to_string()),
            TcpAckNo => get_tcp_header(pkt).map(|tcph| tcph.acknowledgment_number.to_string()),
            TcpSyn => get_tcp_header(pkt).and_then(|tcph| tcp_flags(tcph.syn, 'S')),
            TcpFin => get_tcp_header(pkt).and_then(|tcph| tcp_flags(tcph.fin, 'F')),
            TcpRst => get_tcp_header(pkt).and_then(|tcph| tcp_flags(tcph.rst, 'R')),
            TcpAck => get_tcp_header(pkt).and_then(|tcph| tcp_flags(tcph.ack, 'A')),
            TcpPsh => get_tcp_header(pkt).and_then(|tcph| tcp_flags(tcph.psh, 'P')),
        };
        ret.push(field_value.unwrap_or("-".to_string()));
    }
    ret
}

#[cfg(test)]
mod test {
    use std::{net::Ipv6Addr, str::FromStr};

    use chrono::DateTime;

    use super::*;

    #[test]
    fn test_handle_packet_v4_udp() {
        let mut pkt_bytes: Vec<u8> = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 64)
            .udp(123, 443)
            .write(&mut pkt_bytes, &[])
            .unwrap();
        let ts = DateTime::from_timestamp(1710896033, 123_456_000).unwrap(); // Wed Mar 20 00:53:53.123456 UTC 2024
        let pkt = OwnedParsedPacket::from_headers_and_ts(
            etherparse::PacketHeaders::from_ethernet_slice(&pkt_bytes).unwrap(),
            ts,
            pkt_bytes.len() as u32,
        );

        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Time]),
            vec!["1710896033.123456"],
        );
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Isotime]),
            vec!["2024-03-20T00:53:53.123456Z"],
        );
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Sip]),
            vec!["192.168.1.1"],
        );
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Dip]),
            vec!["192.168.1.2"],
        );
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Sport]), vec!["123"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Dport]), vec!["443"]);
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Len]),
            vec![pkt_bytes.len().to_string()],
        );
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Iplen]), vec!["28"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Proto]), vec!["UDP"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Ipid]), vec!["0"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Ttl]), vec!["64"],);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpSeqNo]), vec!["-"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpAckNo]), vec!["-"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpSyn]), vec!["-"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpFin]), vec!["-"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpRst]), vec!["-"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpAck]), vec!["-"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpPsh]), vec!["-"]);
    }

    #[test]
    fn test_handle_packet_v6_tcp() {
        let mut pkt_bytes: Vec<u8> = Vec::new();
        let src = Ipv6Addr::from_str("2001:0db8::1").unwrap();
        let dst = Ipv6Addr::from_str("2001:0db8::4242").unwrap();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv6(src.octets(), dst.octets(), 111)
            .tcp(8080, 23023, 4242 /* seq_no */, 65535 /* window */)
            .ack(555_000_555)
            .write(&mut pkt_bytes, &[1, 2, 3, 4, 5])
            .unwrap();
        let ts = DateTime::from_timestamp(1710896033, 123_456_000).unwrap(); // Wed Mar 20 00:53:53.123456 UTC 2024
        let pkt = OwnedParsedPacket::from_headers_and_ts(
            etherparse::PacketHeaders::from_ethernet_slice(&pkt_bytes).unwrap(),
            ts,
            pkt_bytes.len() as u32,
        );

        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Time]),
            vec!["1710896033.123456"],
        );
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Isotime]),
            vec!["2024-03-20T00:53:53.123456Z"],
        );
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Sip]),
            vec!["2001:db8::1"],
        );
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Dip]),
            vec!["2001:db8::4242"],
        );
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Sport]), vec!["8080"]);
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Dport]),
            vec!["23023"]
        );
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::Len]),
            vec![pkt_bytes.len().to_string()],
        );
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Iplen]), vec!["65"]); // 40 ipv6header + 20 tcp hdr + 5 p/l
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Proto]), vec!["TCP"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Ipid]), vec!["-"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::Ttl]), vec!["111"]);
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::TcpSeqNo]),
            vec!["4242"]
        );
        assert_eq!(
            handle_packet(&pkt, &vec![PacketField::TcpAckNo]),
            vec!["555000555"]
        );
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpSyn]), vec!["-"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpFin]), vec!["-"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpRst]), vec!["-"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpAck]), vec!["A"]);
        assert_eq!(handle_packet(&pkt, &vec![PacketField::TcpPsh]), vec!["-"]);

        // Test multiple fields to make sure the order is correct
        let fields = vec![
            PacketField::Proto,
            PacketField::Time,
            PacketField::TcpAck,
            PacketField::Sip,
            PacketField::Dport,
        ];
        assert_eq!(
            handle_packet(&pkt, &fields),
            vec!["TCP", "1710896033.123456", "A", "2001:db8::1", "23023"]
        );
    }

    #[test]
    fn test_handle_packet_tcp_flags() {
        // we've already tested the ACK flag in the previous test
        for flag in ["S", "F", "R", "P"] {
            let mut pkt_bytes: Vec<u8> = Vec::new();
            let src = Ipv6Addr::from_str("2001:0db8::1").unwrap();
            let dst = Ipv6Addr::from_str("2001:0db8::4242").unwrap();
            let mut tcp_builder =
                etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
                    .ipv6(src.octets(), dst.octets(), 111)
                    .tcp(8080, 23023, 4242 /* seq_no */, 65535 /* window */);
            tcp_builder = match flag {
                "S" => tcp_builder.syn(),
                "F" => tcp_builder.fin(),
                "R" => tcp_builder.rst(),
                "P" => tcp_builder.psh(),
                _ => panic!("So such flag"),
            };
            tcp_builder.write(&mut pkt_bytes, &[1, 2, 3, 4, 5]).unwrap();
            let ts = DateTime::from_timestamp(1710896033, 123_456_000).unwrap(); // Wed Mar 20 00:53:53.123456 UTC 2024
            let pkt = OwnedParsedPacket::from_headers_and_ts(
                etherparse::PacketHeaders::from_ethernet_slice(&pkt_bytes).unwrap(),
                ts,
                pkt_bytes.len() as u32,
            );
            let fields = vec![match flag {
                "S" => PacketField::TcpSyn,
                "F" => PacketField::TcpFin,
                "R" => PacketField::TcpRst,
                "P" => PacketField::TcpPsh,
                _ => panic!("So such flag"),
            }];
            assert_eq!(handle_packet(&pkt, &fields), vec![flag]);
        }
    }
}
