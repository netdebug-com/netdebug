use std::net::IpAddr;

use etherparse::IpHeader;

pub fn etherparse_ipheaders2ipaddr(ip: Option<IpHeader>) -> Result<(IpAddr, IpAddr), pcap::Error> {
    match ip {
        Some(IpHeader::Version4(ip4, _)) => {
            Ok((IpAddr::from(ip4.source), IpAddr::from(ip4.destination)))
        }
        Some(IpHeader::Version6(ip6, _)) => {
            Ok((IpAddr::from(ip6.source), IpAddr::from(ip6.destination)))
        }
        None => Err(pcap::Error::PcapError("No IP address to parse".to_string())),
    }
}
