use anyhow::anyhow;
use clap::Parser;
use common_wasm::timeseries_stats::{StatType, SuperRegistry, Units};

use log::{info, warn};

use std::{
    collections::HashSet,
    error::Error,
    fs::File,
    io::{BufRead, BufReader, Read},
    net::IpAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::sync::mpsc::Receiver;

use libconntrack::{
    connection_tracker::{ConnectionTracker, ConnectionTrackerMsg},
    neighbor_cache::NeighborCache,
    owned_packet::ConnectionKeyError,
    pcap::{pcap_find_all_local_addrs, run_blocking_pcap_loop_in_thread},
    pingtree::{run_pingtree, GatewayLookup, PingTreeConfig},
    prober::spawn_raw_prober,
    system_tracker::SystemTracker,
    utils::PerfMsgCheck,
};

const NON_DNS_PAYLOAD_LEN: usize = 65_535;

/// Execute a PingTree. Given a list of (router) IPs and
/// their hop distance (optional) we send a periodic ping to
/// all IPs at the same time. Analyzing the RTTs we receive
/// we can identify links with large RTTs and/or RTT variance
/// indicating congestion.
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The time between individual probe rounds in seconds. Accepts floating point numbers.
    #[arg(long, default_value_t = 0.5)]
    pub time_between_rounds_secs: f64,

    /// After the final probe round has been sent: How long to wait for responses.
    #[arg(long, default_value_t = 2.5)]
    pub final_timeout_secs: f64,

    /// The number of probe rounds to send. Every IP in the input is probed that many times.
    #[arg(long, default_value_t = 5)]
    pub num_rounds: u16,

    /// The input filename containing the list of IPs and their hop distances.
    /// One entry per line: `<HOP-DISTANCE> <IP>`
    /// Can also handle the output of `traceroute -n <IP>` where we have
    /// leading spaces, stuff after the IP (RTT), and at least on MacOS the hop count
    /// can be omitted if its the same as the previous line.
    #[arg(name = "input_file")]
    pub file: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    common::init::netdebug_init();

    let args = Args::parse();
    let hop_and_ips = read_input_file(args.file)?;
    println!("Got: {:#?}", hop_and_ips);

    let system_epoch = std::time::Instant::now();

    let network_state = SystemTracker::snapshot_current_network_state().await;
    println!(
        "Got network interface state. Egress iface `{:?}`, gateways: {:?}",
        network_state.interface_name, network_state.gateways
    );
    let mut counter_registries = SuperRegistry::new(system_epoch);

    let local_addrs = pcap_find_all_local_addrs()?;
    let raw_sock = libconntrack::pcap::bind_writable_pcap(local_addrs.clone());
    let prober_tx = spawn_raw_prober(raw_sock, 4096);

    // create a channel for the ConnectionTracker
    let (connection_tracker_tx, rx) =
        tokio::sync::mpsc::channel::<PerfMsgCheck<ConnectionTrackerMsg>>(4096);
    let connection_tracker_tx_clone = connection_tracker_tx.clone();
    let prober_tx_clone = prober_tx.clone();
    let local_addrs_clone = local_addrs.clone();
    let conn_track_stat_registry = counter_registries.new_registry("conn_tracker");
    let _connection_tracker_task = tokio::spawn(async move {
        // Spawn a ConnectionTracker task
        let mut connection_tracker = ConnectionTracker::new(
            None,
            4096, // max connections
            local_addrs_clone,
            prober_tx_clone,
            4096, // queue size
            conn_track_stat_registry,
            false, // doesn't matter. We're not sending TCP probes.
        );
        connection_tracker.set_tx_rx(connection_tracker_tx_clone, rx);
        info!("Starting ConnectionTracker loop");
        // loop forever tracking messages sent on the channel
        connection_tracker.rx_loop().await;
        info!("Starting ConnectionTracker loop terminated");
    });

    let _handle = run_blocking_pcap_loop_in_thread(
        network_state.interface_name.clone().unwrap(),
        Some("icmp or icmp6 or arp".to_owned()),
        connection_tracker_tx.clone(),
        NON_DNS_PAYLOAD_LEN,
        None,
        None,
    );

    let mut gw_lookup = GatewayLookup::new(connection_tracker_tx.clone(), network_state);
    gw_lookup.do_lookup().await;

    info!(
        "V4 gateway: {}",
        gw_lookup
            .v4_egress_info
            .as_ref()
            .map(|info| info.to_string())
            .unwrap_or("None".to_owned()),
    );
    info!(
        "V6 gateway: {}",
        gw_lookup
            .v6_egress_info
            .as_ref()
            .map(|info| info.to_string())
            .unwrap_or("None".to_owned()),
    );

    let echo_reply_without_request = counter_registries.new_registry("pingtree").add_stat(
        "echo_reply_without_request",
        Units::None,
        [StatType::COUNT],
    );
    let ips: HashSet<IpAddr> = hop_and_ips.iter().map(|(_hop, ip)| *ip).collect();
    let pingtree_res = run_pingtree(PingTreeConfig {
        ips,
        v4_egress_info: gw_lookup.v4_egress_info,
        v6_egress_info: gw_lookup.v6_egress_info,
        num_rounds: args.num_rounds,
        time_between_rounds: Duration::from_secs_f64(args.time_between_rounds_secs),
        final_probe_wait: Duration::from_secs_f64(args.final_timeout_secs),
        connection_tracker_tx,
        prober_tx,
        ping_id: std::process::id() as u16,
        echo_reply_without_request: echo_reply_without_request.clone(),
    })
    .await;

    println!("PingTree is done: Results:");
    for (hop, ip) in &hop_and_ips {
        println!("{:3} {} {:?}", hop, ip, pingtree_res.get(ip).unwrap());
    }

    Ok(())
}

pub async fn rx_loop(
    mut pkt_rx: Receiver<PerfMsgCheck<ConnectionTrackerMsg>>,
    local_addrs: HashSet<IpAddr>,
    neighbor_cache: Arc<Mutex<NeighborCache<'_>>>,
) {
    while let Some(msg) = pkt_rx
        .recv()
        .await
        .map(|msg| msg.perf_check_get("from pkt_rx"))
    {
        match msg {
            ConnectionTrackerMsg::Pkt(pkt) => match pkt.to_connection_key(&local_addrs) {
                Ok((_key, _src_is_local)) => todo!(),
                Err(ConnectionKeyError::Arp) => {
                    if let Err(e) = neighbor_cache.lock().unwrap().process_arp_packet(pkt) {
                        warn!("Ignoring failed to parse Arp packet: {}", e);
                    }
                }
                Err(ConnectionKeyError::NdpNeighbor) => {
                    if let Err(e) = neighbor_cache.lock().unwrap().process_ndp_packet(pkt) {
                        warn!("Ignoring failed to parse NDP packet: {}", e);
                    }
                }
                _ => (),
            },
            _ => panic!("Unexpected Message"),
        }
    }
}

pub fn read_input_file(fname: String) -> anyhow::Result<Vec<(u8, IpAddr)>> {
    let reader: Box<dyn Read> = if fname == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(fname)?)
    };
    let mut buf_reader = BufReader::new(reader);
    let mut ret = Vec::new();
    let mut line = String::new();
    let mut prev_hop_count = 1;
    while buf_reader.read_line(&mut line)? > 0 {
        let parts: Vec<&str> = line.trim().split_ascii_whitespace().collect();
        if parts.len() < 2 {
            return Err(anyhow!("Invalid line in input: `{}`", line));
        }
        let (hop, ip_str) = match u8::from_str(parts[0]) {
            Ok(hop) => (hop, parts[1]),
            Err(_) => (prev_hop_count, parts[0]),
        };
        prev_hop_count = hop;
        if ip_str == "*" {
            continue;
        }
        let ip = IpAddr::from_str(ip_str)?;
        ret.push((hop, ip));
        line.clear();
    }
    Ok(ret)
}
