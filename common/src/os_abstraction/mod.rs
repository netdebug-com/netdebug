/// A grab bag place to put cross-operating system abstractions

#[cfg(windows)]
#[path = "windows.rs"]
mod os;

#[cfg(not(windows))]
#[path = "unix.rs"]
mod os;

pub type IfIndex = u32;
pub fn pcap_ifname_to_ifindex(ifname: String) -> Result<IfIndex, std::io::Error> {
    os::pcap_ifname_to_ifindex(ifname)
}

#[derive(Debug, Clone)]
/// An OS-abstracted view of a network interface
pub struct NetworkInterface {
    pub name: String,
    pub ifindex: IfIndex,
    pub desc: Option<String>,
}

pub fn list_network_interfaces() -> Result<Vec<NetworkInterface>, std::io::Error> {
    os::list_network_interfaces()
}
