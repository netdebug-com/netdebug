use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use axum::extract::State;
use axum::response;
use common_wasm::timeseries_stats::{CounterProvider, CounterProviderWithTimeUpdate};
use desktop_common::CongestedLinksReply;
use libconntrack::{
    connection_tracker::{ConnectionTrackerMsg, TimeMode},
    dns_tracker::DnsTrackerMessage,
    topology_client::TopologyServerMessage,
    utils::{channel_rpc, channel_rpc_perf},
};
use libconntrack_wasm::{
    bidir_bandwidth_to_chartjs, AggregateStatEntry, ChartJsBandwidth, ConnectionMeasurements,
    DnsTrackerEntry, ExportedNeighborState, NetworkInterfaceState,
};
use tokio::sync::mpsc::channel;

use crate::Trackers;

pub async fn handle_get_counters(State(trackers): State<Arc<Trackers>>) -> String {
    // IndexMap iterates over entries in insertion order
    let mut map = indexmap::IndexMap::<String, u64>::new();
    {
        let locked_registries = trackers
            .counter_registries
            .as_ref()
            .unwrap()
            .lock()
            .unwrap();
        locked_registries.update_time();
        locked_registries.append_counters(&mut map);
    }
    serde_json::to_string_pretty(&map).unwrap()
}

// TODO: for all teh handle_FOO handlers. Instead of returning empty on an error, we should
// actually propagate an proper error back to the UI.
// TODO: our usagae of SLA logging is inconsistent. Some have SLAs, some don't for now, I'm
// simply copying what we used for websocket

pub(crate) async fn handle_get_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<ConnectionMeasurements>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetConnectionMeasurements {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetConnectionMeasurements",
            Some(tokio::time::Duration::from_millis(200)),
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_dns_cache(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<HashMap<IpAddr, DnsTrackerEntry>> {
    let (tx, mut rx) = channel(1);
    let req = DnsTrackerMessage::DumpReverseMap { tx };
    response::Json(
        channel_rpc(
            trackers.dns_tracker.clone().unwrap(),
            req,
            &mut rx,
            "dns_tracker/DumpReverseMap",
            None,
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_aggregate_bandwidth(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<ChartJsBandwidth>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetTrafficCounter",
            Some(tokio::time::Duration::from_millis(50)),
        )
        .await
        .map(bidir_bandwidth_to_chartjs)
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_dns_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<AggregateStatEntry>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetDnsTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetDnsTrafficCounters",
            Some(tokio::time::Duration::from_millis(100)),
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_app_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<AggregateStatEntry>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetAppTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetAppTrafficCounters",
            Some(tokio::time::Duration::from_millis(100)),
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_host_flows(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<AggregateStatEntry>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetHostTrafficCounters {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "connection_tracker/GetHostTrafficCounters",
            Some(tokio::time::Duration::from_millis(100)),
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_my_ip(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<IpAddr> {
    // TODO: should return a list of IPs or a pair of v4/v6.
    let (tx, mut rx) = channel(1);
    let req = TopologyServerMessage::GetMyIpAndUserAgent { reply_tx: tx };
    response::Json(
        channel_rpc_perf(
            trackers.topology_client.clone().unwrap(),
            req,
            &mut rx,
            "topology_server/GetMyIp",
            None,
        )
        .await
        .map(|perf_msg| {
            let (ip, _) = perf_msg.perf_check_get("handle_get_my_ip");
            ip
        })
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    )
}

pub(crate) async fn handle_get_devices(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<ExportedNeighborState>> {
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetCachedNeighbors { tx };
    response::Json(
        channel_rpc_perf(
            trackers.connection_tracker.clone().unwrap(),
            req,
            &mut rx,
            "ConnectionTracker/GetNeighborState",
            None,
        )
        .await
        .unwrap_or_default(),
    )
}

pub(crate) async fn handle_get_congested_links(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<CongestedLinksReply> {
    // 1. request connection measurements from conntracker
    let (tx, mut rx) = channel(1);
    let req = ConnectionTrackerMsg::GetConnectionMeasurements {
        tx,
        time_mode: TimeMode::Wallclock,
    };
    let conn_measurements = match channel_rpc_perf(
        trackers.connection_tracker.clone().unwrap(),
        req,
        &mut rx,
        "congested links -- connection_tracker/GetConnectionMeasurements",
        None,
    )
    .await
    {
        Ok(m) => m,
        Err(_) => return response::Json(CongestedLinksReply::default()),
    };

    // 2. send the measurements to the topology server for analysis
    let (tx, mut rx) = channel(1);
    let req = TopologyServerMessage::InferCongestion {
        connection_measurements: conn_measurements.clone(),
        reply_tx: tx,
    };
    let congestion_summary = channel_rpc_perf(
        trackers.topology_client.clone().unwrap(),
        req,
        &mut rx,
        "congested links -- topology_server/InferCongestion",
        None,
    )
    .await
    .map(|perf_msg| perf_msg.perf_check_get("handle_congested_links"))
    .unwrap_or_default();
    response::Json(CongestedLinksReply {
        congestion_summary,
        connection_measurements: conn_measurements,
    })
}

pub(crate) async fn handle_get_system_network_history(
    State(trackers): State<Arc<Trackers>>,
) -> response::Json<Vec<NetworkInterfaceState>> {
    response::Json(
        trackers
            .system_tracker
            .clone()
            .unwrap()
            .read()
            .await
            .get_network_interface_histories(),
    )
}
