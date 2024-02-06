use super::NetworkInterface;
use nix::{ifaddrs::getifaddrs, net::if_::if_nametoindex};

pub(crate) fn pcap_ifname_to_ifindex(ifname: String) -> Result<u32, std::io::Error> {
    // rough code - need to fixup from Linux
    match if_nametoindex(ifname.as_str()) {
        Ok(if_index_c_uint) => Ok(if_index_c_uint),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }
}

pub(crate) fn list_network_interfaces() -> Result<Vec<NetworkInterface>, std::io::Error> {
    Ok(getifaddrs()?
        .map(|intf| {
            let name = intf.interface_name.clone();
            // silent error if we can't figure out if_index - think about if this is a good idea
            let ifindex = pcap_ifname_to_ifindex(name.clone()).unwrap_or(0);
            NetworkInterface {
                name,
                ifindex,
                desc: None,
            }
        })
        .collect::<Vec<NetworkInterface>>())
}
