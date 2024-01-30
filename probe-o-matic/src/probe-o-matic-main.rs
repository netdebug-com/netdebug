use clap::Parser;
use lib_probe_o_matic::*;
use libconntrack::connection_tracker::ConnectionTrackerMsg;
use libconntrack::pcap::{find_interesting_pcap_interfaces, run_blocking_pcap_loop_in_thread};
use libconntrack::utils::PerfMsgCheck;
use log::{error, info, warn};
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::Duration;

const NON_DNS_PAYLOAD_LEN: usize = 64;

/// Probe-o-matic: for probing router IPs
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "udp or icmp or icmp6")]
    pub pcap_filter: String,

    /// The MAC address of the default gateway.
    #[arg(long)]
    pub gateway_mac: String,

    /// The MAC address of the egress interface; default is autodetect
    #[arg(long)]
    pub egress_mac: Option<String>,

    /// Maximum number of IPs that will be probed in parallel
    #[arg(long, default_value_t = 5)]
    pub max_parallel_probes: usize,

    /// which pcap device to listen on (and send probes on); default is autodetect
    #[arg(long, default_value = None)]
    pub pcap_device: Option<String>,

    /// Whether to read IPs to probe from stdin (one per line) or
    /// from the commandline
    #[arg(long, default_value_t = false)]
    pub ips_from_stdin: bool,

    /// List of IPs to probe, unless --ips-from-stdin is given
    #[arg(name = "ip")]
    pub ips: Vec<String>,
}

const GOOGLE_DNS_IPV6: &str = "2001:4860:4860::8888";
const MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE: usize = 4096;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    common::init::netdebug_init();
    let args = Args::parse();

    let gateway_mac = mac_address::MacAddress::from_str(&args.gateway_mac)
        .expect("Failed to parse default gateway Mac");

    // reserver local UDP port for sending probes.
    let v4_sock = std::net::UdpSocket::bind("0.0.0.0:0").expect("Unable to bind v4 socket");
    let v6_sock = std::net::UdpSocket::bind("[::]:0").expect("Unable to bind v6 socket");

    v4_sock
        .connect(("8.8.8.8", 53))
        .expect("Failed to bind v4 socket");
    let v6_disabled = if v6_sock.connect((GOOGLE_DNS_IPV6, 53)).is_err() {
        warn!("No IPv6 route found. Ignoring IPv6");
        true
    } else {
        false
    };

    info!("Local addr {}", v4_sock.local_addr()?);
    info!("Local addr {}", v6_sock.local_addr()?);

    let devices = find_interesting_pcap_interfaces(&args.pcap_device)?;
    assert_eq!(devices.len(), 1);
    let dev = devices.first().unwrap();
    info!("Binding pcap interface {}", dev.name);
    let src_mac = if let Some(src_mac) = args.egress_mac {
        mac_address::MacAddress::from_str(&src_mac).expect("Valid egress MAC address")
    } else if let Some(src_mac) = mac_address::mac_address_by_name(&dev.name)? {
        src_mac
    } else {
        error!("Couldn't auto-detect the egress src mac; must specify with --egress-mac");
        std::process::exit(1);
    };
    info!("Got pcap device: {}, mac address {} ", dev.name, src_mac);
    // TODO: can check that the src IPs are actually IPs on the pcap_device
    let outgoing_addr_config = LocalAddressConfig {
        gateway_mac,
        src_mac,
        v4_src_addr: to_socket_addr_v4(v4_sock.local_addr()?).unwrap(),
        v6_src_addr: to_socket_addr_v6(v6_sock.local_addr()?).unwrap(),
        if_name: dev.name.clone(),
    };

    let (pkt_tx, pkt_rx) = tokio::sync::mpsc::channel::<PerfMsgCheck<ConnectionTrackerMsg>>(
        MAX_MSGS_PER_CONNECTION_TRACKER_QUEUE,
    );
    let _handle = run_blocking_pcap_loop_in_thread(
        dev.name.clone(),
        Some(args.pcap_filter.clone()),
        pkt_tx.clone(),
        NON_DNS_PAYLOAD_LEN,
        None,
    );
    // It appears we have a race between the pcap actually starting and us sending
    // the first probe. So lets simply wait a bit after starting the pcap polling
    // loop to ensure we won't miss the very first probe
    tokio::time::sleep(Duration::from_millis(400)).await;
    let raw_sock = Box::new(libconntrack::pcap::bind_writable_pcap());

    let ips_to_probe: Vec<String> = if args.ips_from_stdin {
        io::stdin().lines().map_while(Result::ok).collect()
    } else {
        args.ips
    };

    let (probe_req_tx, probe_resp_rx) = tokio::sync::mpsc::unbounded_channel::<ProbeOMaticMsg>();
    let _input_reader_handle = tokio::spawn(async move {
        let parallel_probe_meter = Arc::new(Semaphore::new(args.max_parallel_probes));
        for ip_str in ips_to_probe {
            match IpAddr::from_str(&ip_str) {
                Ok(ip) => {
                    if v6_disabled && ip.is_ipv6() {
                        info!("Skipping IPv6 address {}", ip);
                        continue;
                    }
                    let permit = parallel_probe_meter.clone().acquire_owned().await.unwrap();
                    let _ignore_result = probe_req_tx.send(ProbeOMaticMsg::ProbeAddr(ip, permit));
                    // We don't want to generate periodic bursts of outgoing probe packets. So as
                    // quick-and-dirty way to mitigate this, we simply wait a small amount of
                    // time between enqueueing IPs. This won't reduce our throughput since it takes
                    // many seconds for all probes belonging to an IP to be sent
                    tokio::time::sleep(Duration::from_millis(3)).await;
                }
                Err(e) => warn!("Could not parse {} as IP: {}", ip_str, e),
            }
        }
        let _ignore_result = probe_req_tx.send(ProbeOMaticMsg::TheEnd);
    });
    ProbeOMatic::spawn(pkt_rx, probe_resp_rx, raw_sock, outgoing_addr_config).await?;
    Ok(())
}
