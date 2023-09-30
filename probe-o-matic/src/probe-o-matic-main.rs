use clap::Parser;
use lib_probe_o_matic::*;
use libconntrack::connection::ConnectionTrackerMsg;
use libconntrack::pcap::{find_interesting_pcap_interfaces, run_blocking_pcap_loop_in_thread};
use log::info;
use std::str::FromStr;

/// Probe-o-matic: for probing router IPs
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "udp or icmp or icmp6")]
    pub pcap_filter: String,

    /// The MAC address of the default gateway.
    #[arg(long)]
    pub gateway_mac: String,

    /// which pcap device to listen on (and send probes on); default is autodetect
    #[arg(long, default_value = None)]
    pub pcap_device: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    utils::init::netdebug_init();
    let args = Args::parse();

    let gateway_mac = mac_address::MacAddress::from_str(&args.gateway_mac)
        .expect("Failed to parse default gateway Mac");

    // reserver local UDP port for sending probes.
    let v4_sock = std::net::UdpSocket::bind("0.0.0.0:0").expect("Unable to bind v4 socket");
    let v6_sock = std::net::UdpSocket::bind("[::]:0").expect("Unable to bind v6 socket");

    v4_sock.connect(("8.8.8.8", 53))?;
    v6_sock.connect(("2001:4860:4860::8888", 53))?;
    info!("Local addr {}", v4_sock.local_addr()?);
    info!("Local addr {}", v6_sock.local_addr()?);

    let devices = find_interesting_pcap_interfaces(&args.pcap_device)?;
    assert_eq!(devices.len(), 1);
    let dev = devices.first().unwrap();
    let src_mac = mac_address::mac_address_by_name(&dev.name)?.unwrap();
    info!("Got pcap device: {}, mac address {} ", dev.name, src_mac);
    // TODO: can check that the src IPs are actually IPs on the pcap_device
    let outgoing_addr_config = OutgoingAddressConfig {
        gateway_mac,
        src_mac,
        v4_src_addr: to_socket_addr_v4(v4_sock.local_addr()?).unwrap(),
        v6_src_addr: to_socket_addr_v6(v6_sock.local_addr()?).unwrap(),
        if_name: dev.name.clone(),
    };

    let (pkt_tx, pkt_rx) = tokio::sync::mpsc::unbounded_channel::<ConnectionTrackerMsg>();
    let (_probe_tx, probe_rx) = tokio::sync::mpsc::unbounded_channel::<ProbeOMaticMsg>();
    let _handle = run_blocking_pcap_loop_in_thread(
        dev.name.clone(),
        Some(args.pcap_filter.clone()),
        pkt_tx.clone(),
        None,
    );
    let raw_sock = Box::new(libconntrack::pcap::bind_writable_pcap_by_name(
        dev.name.clone(),
    )?);

    ProbeOMatic::spawn(pkt_rx, probe_rx, raw_sock, outgoing_addr_config).await?;
    Ok(())
}
