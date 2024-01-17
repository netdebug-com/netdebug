use std::{collections::HashSet, net::IpAddr, path::Path, str::FromStr, time::Instant};

use clap::Parser;
use common_wasm::timeseries_stats::ExportedStatRegistry;
use libconntrack::{
    connection_tracker::{ConnectionTracker, ConnectionTrackerMsg, TimeMode},
    dns_tracker::DnsTrackerMessage,
    owned_packet::OwnedParsedPacket,
};
use libconntrack_wasm::{pretty_print_si_units, ConnectionMeasurements, TrafficStatsSummary};
use tokio::sync::mpsc;

#[derive(clap::Parser, Debug)]
struct Args {
    pcap_file: String,
}

pub fn stats_to_string(stats: &TrafficStatsSummary) -> String {
    let loss_precent = if let Some(lost_bytes) = stats.lost_bytes {
        100. * lost_bytes as f64 / stats.bytes as f64
    } else {
        0.0
    };
    format!(
        "bytes: {}, lost_bytes: {:?} => {:.2}%",
        stats.bytes, stats.lost_bytes, loss_precent
    )
}

pub fn handle_conn_measurement(m: &ConnectionMeasurements) {
    println!(
        "{}\n>>> rx: {:?}\n>>> tx: {:?}",
        m.key,
        stats_to_string(&m.rx_stats),
        stats_to_string(&m.tx_stats),
    );
}

pub fn handle_dns_msg(
    dns_rx: &mut mpsc::Receiver<DnsTrackerMessage>,
    conn_tracker: &mut ConnectionTracker,
) {
    if let Ok(DnsTrackerMessage::Lookup { key, .. }) = dns_rx.try_recv() {
        conn_tracker.set_connection_remote_hostname_dns(
            &vec![key],
            Some("topology.netdebug.com".to_string()),
        );
    }
}

pub fn main() {
    // if RUST_LOG isn't set explicitly, set RUST_LOG=debug as a default
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "debug");
    }
    common::init::netdebug_init();
    let args = Args::parse();

    let mut capture = pcap::Capture::from_file(Path::new(&args.pcap_file))
        .expect("Error trying to open pcap file");

    let local_addr = HashSet::from([
        IpAddr::from_str("192.168.1.238").unwrap(),
        IpAddr::from_str("192.168.1.136").unwrap(),
    ]);
    let stats_registry = ExportedStatRegistry::new("", Instant::now());

    let (prober_tx, mut prober_rx) = mpsc::channel(100);
    let mut conn_track = ConnectionTracker::new(
        None,
        2 << 16,
        local_addr.clone(),
        prober_tx,
        4096,
        stats_registry,
        false,
    );
    let (conn_measurements_tx, mut conn_measurements_rx) = mpsc::channel(100);
    conn_track.set_all_evicted_connections_listener(conn_measurements_tx);
    let (dns_tx, mut dns_rx) = mpsc::channel(4096);
    conn_track.set_dns_tracker(dns_tx);

    let mut pkts: u64 = 0;
    let mut bytes: u64 = 0;
    // take all of the packets in the capture and pipe them into the connection tracker
    while let Ok(pkt) = capture.next_packet() {
        let owned_pkt = OwnedParsedPacket::try_from_pcap(pkt).unwrap();
        pkts += 1;
        bytes += owned_pkt.len as u64;
        conn_track.add(owned_pkt);
        let _ = prober_rx.try_recv();
        if let Ok(measurement) = conn_measurements_rx.try_recv() {
            handle_conn_measurement(&measurement);
        }
        handle_dns_msg(&mut dns_rx, &mut conn_track);
    }
    // Query conn_tracker for all remaining connections
    let (tx, mut rx) = mpsc::channel(10);
    conn_track.handle_one_msg(ConnectionTrackerMsg::GetConnectionMeasurements {
        tx,
        time_mode: TimeMode::PacketTime,
    });
    if let Ok(measurements) = rx.try_recv() {
        for m in &measurements {
            handle_conn_measurement(m);
        }
    }
    // Query for per domain counters
    let (agg_counter_dns_tx, mut agg_counter_dns_rx) = mpsc::channel(100);
    conn_track.handle_one_msg(ConnectionTrackerMsg::GetDnsTrafficCounters {
        tx: agg_counter_dns_tx,
        time_mode: TimeMode::PacketTime,
    });
    let dns_agg_counters = agg_counter_dns_rx.try_recv().unwrap();
    for stat_entry in &dns_agg_counters {
        println!(
            "{:?} => {}",
            stat_entry.kind,
            stats_to_string(&stat_entry.summary.tx)
        );
    }
    println!(
        "Done. Read {} packets, {}",
        pretty_print_si_units(Some(pkts as f64), ""),
        pretty_print_si_units(Some(bytes as f64), "B")
    );
}
