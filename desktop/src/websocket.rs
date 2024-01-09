use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use common_wasm::timeseries_stats::{
    CounterProvider, CounterProviderWithTimeUpdate, SharedExportedStatRegistries,
};
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use libconntrack::{
    connection_tracker::{ConnectionTrackerMsg, ConnectionTrackerSender, TimeMode},
    dns_tracker::DnsTrackerMessage,
    perf_check,
    process_tracker::ProcessTrackerSender,
    send_or_log_async, send_or_log_sync,
    utils::PerfMsgCheck,
};
use libconntrack_wasm::{bidir_bandwidth_to_chartjs, topology_server_messages::CongestionSummary};
use log::{debug, info, warn};
use tokio::sync::mpsc::{self, channel, unbounded_channel, UnboundedSender};
use warp::ws::{self, Message, WebSocket};

use desktop_common::{DesktopToGuiMessages, GuiToDesktopMessages};

use crate::topology_client::{TopologyServerMessage, TopologyServerSender};

/**
 * We have a lot of different threads that want to send from the desktop server to the GUI client,
 * but the websocket SplitSink doesn't allow multiple senders at the same time.  To fix this,
 * spawn a task that listens on a channel and just resends anything we get on that channel
 * to the websocket.  At the same time, do the JSON encoding here to simplify the rest of the code.
 *
 * If you want to send something to the GUI, get a clone of the tx that's returned here
 */

pub async fn websocket_sender(
    mut ws_tx: SplitSink<WebSocket, Message>,
) -> UnboundedSender<DesktopToGuiMessages> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let json_str = match serde_json::to_string(&msg) {
                Ok(json) => json,
                Err(e) => {
                    warn!("Failed to json marshall/serde msg!? {} :: {:?}", e, &msg);
                    continue;
                }
            };
            if let Err(e) = ws_tx.send(ws::Message::text(json_str.as_str())).await {
                warn!("Error sending on websocket channel : {}", e);
            }
        }
    });

    tx
}

/**
 * Loop until closed, reading websocket GuiToServer messages off of the wire
 * (after converting from JSON) and dispatch to the relevant handlers.
 */
async fn handle_websocket_rx_messages(
    mut ws_rx: SplitStream<WebSocket>,
    tx: UnboundedSender<DesktopToGuiMessages>,
    connection_tracker: ConnectionTrackerSender,
    dns_tracker: UnboundedSender<DnsTrackerMessage>,
    _process_tracker: ProcessTrackerSender,
    topology_client: TopologyServerSender,
    counter_registries: SharedExportedStatRegistries,
) {
    while let Some(msg_result) = ws_rx.next().await {
        match msg_result {
            Ok(msg) => {
                if msg.is_text() {
                    let json = msg.to_str().expect("msg.is_text() lies!");
                    match serde_json::from_str::<GuiToDesktopMessages>(json) {
                        Ok(msg) => {
                            handle_gui_to_server_msg(
                                msg,
                                &tx,
                                &connection_tracker,
                                &dns_tracker,
                                &topology_client,
                                &counter_registries,
                            )
                            .await
                        }
                        Err(e) => {
                            warn!("Failed to parse JSON websocket msg: {:?}", e);
                        }
                    }
                } else {
                    info!("Ignoring websocket non-text message {:?}", msg);
                }
            }
            Err(e) => warn!("Error from Websocket message queue: {}", e),
        }
    }
}

async fn handle_gui_to_server_msg(
    msg: GuiToDesktopMessages,
    tx: &UnboundedSender<DesktopToGuiMessages>,
    connection_tracker: &ConnectionTrackerSender,
    dns_tracker: &UnboundedSender<DnsTrackerMessage>,
    topology_client: &TopologyServerSender,
    counter_registries: &SharedExportedStatRegistries,
) {
    let start = std::time::Instant::now();
    use GuiToDesktopMessages::*;
    match &msg {
        DumpFlows => {
            debug!("Got DumpFlows request");
            handle_gui_dumpflows(tx, connection_tracker).await;
        }
        DumpDnsCache => handle_gui_dump_dns_cache(tx, connection_tracker, dns_tracker).await,
        DumpAggregateCounters => {
            handle_dump_aggregate_connection_tracker_counters(tx, connection_tracker).await
        }
        DumpStatCounters => handle_dump_stat_counters(tx, counter_registries).await,
        DumpDnsAggregateCounters => handle_gui_dump_dns_flows(tx, connection_tracker).await,
        WhatsMyIp => handle_get_my_ip(tx, topology_client).await,
        CongestedLinksRequest => {
            handle_congested_links_request(tx, topology_client, connection_tracker).await
        }
    }
    perf_check!("process gui message", start, Duration::from_millis(200));
}

/**
 * The GUI asked for congested links: pull the ConnectionMeasurements from the connection tracker
 * and ship them off to the topology server, wait for the reply, and send it back
 */
async fn handle_congested_links_request(
    tx: &UnboundedSender<DesktopToGuiMessages>,
    topology_client: &TopologyServerSender,
    connection_tracker: &ConnectionTrackerSender,
) {
    // 1. request connection measurements from conntracker
    let (reply_tx, mut reply_rx) = unbounded_channel();
    send_or_log_async!(
        connection_tracker,
        "handle_congested_links_request() - conntracker",
        ConnectionTrackerMsg::GetConnectionMeasurements {
            tx: reply_tx,
            time_mode: TimeMode::Wallclock
        }
    )
    .await;
    let connection_measurements = match reply_rx.recv().await {
        Some(m) => m,
        None => {
            warn!("ConnectionTracker::GetConnectionMeasurements returned None!?");
            // UI is stateful; send them back an empty message just so they don't wait indefinitely...
            if let Err(e) = tx.send(DesktopToGuiMessages::CongestedLinksReply {
                congestion_summary: CongestionSummary { links: Vec::new() },
                connection_measurements: Vec::new(),
            }) {
                warn!("Writing to GUI failed: {}", e);
            }
            return;
        }
    };
    // 2. send the measurements to the topology server for analysis
    let (reply_tx, mut reply_rx) = channel(1);
    send_or_log_async!(
        topology_client,
        "handle_congestion_links_request() topology",
        TopologyServerMessage::InferCongestion {
            connection_measurements: connection_measurements.clone(),
            reply_tx
        }
    )
    .await;
    let congestion_summary = match reply_rx.recv().await {
        Some(c) => c.perf_check_get("handle_congested_links_request"),
        None => {
            warn!("TopologyClient::InferCongestion returned None!?");
            // UI is stateful; send them back an empty message just so they don't wait indefinitely...
            CongestionSummary { links: Vec::new() }
        }
    };
    // 3. send the congestion summary back to the GUI
    if let Err(e) = tx.send(DesktopToGuiMessages::CongestedLinksReply {
        congestion_summary,
        connection_measurements,
    }) {
        warn!("Failed to send CongestedLinksReply back to GUI: {}", e);
    }
}

async fn handle_get_my_ip(
    tx: &UnboundedSender<DesktopToGuiMessages>,
    topology_client: &mpsc::Sender<PerfMsgCheck<crate::topology_client::TopologyServerMessage>>,
) {
    let (reply_tx, mut reply_rx) = channel(1);
    use TopologyServerMessage::*;
    send_or_log_async!(
        topology_client,
        "handle_get_my_ip",
        GetMyIpAndUserAgent { reply_tx }
    )
    .await;
    match reply_rx.recv().await {
        Some(perf_msg) => {
            let (ip, _) = perf_msg.perf_check_get("handle_get_my_ip");
            if let Err(e) = tx.send(DesktopToGuiMessages::WhatsMyIpReply { ip }) {
                warn!("Failed to send WhatsMyIpReply to GUI: {}", e);
            }
        }
        None => todo!(),
    }
}

async fn handle_dump_stat_counters(
    tx: &UnboundedSender<DesktopToGuiMessages>,
    counter_registries: &SharedExportedStatRegistries,
) {
    counter_registries.lock().unwrap().update_time();
    let msg = DesktopToGuiMessages::DumpStatCountersReply(
        counter_registries.lock().unwrap().get_counter_map(),
    );
    if let Err(e) = tx.send(msg) {
        warn!("Failed to send the DNS cache back to the GUI!?: {}", e);
    }
}

async fn handle_dump_aggregate_connection_tracker_counters(
    tx: &UnboundedSender<DesktopToGuiMessages>,
    connection_tracker: &ConnectionTrackerSender,
) {
    let start = std::time::Instant::now();
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel();
    if let Err(e) = connection_tracker.try_send(PerfMsgCheck::new(
        ConnectionTrackerMsg::GetTrafficCounters {
            tx: reply_tx,
            time_mode: TimeMode::Wallclock,
        },
    )) {
        warn!(
            "Failed to send GetAggregateCounters to the connection tracker!?: {}",
            e
        );
    }
    if let Some(counters) = reply_rx.recv().await {
        let chartjs_bandwidth = bidir_bandwidth_to_chartjs(counters);
        if let Err(e) = tx.send(DesktopToGuiMessages::DumpAggregateCountersReply(
            chartjs_bandwidth,
        )) {
            warn!("Error talking to GUI: {}", e);
        }
    } else {
        warn!("Got None from ConnectionTrackerMsg::GetAggregateCounters !?");
    }
    perf_check!(
        "handle_dump_aggregate_connection_tracker_counters",
        start,
        Duration::from_millis(50)
    );
}

/**
 * Gui has asked for a copy of the DNS cache - poke the dns_tracker and send it to them
 */
async fn handle_gui_dump_dns_cache(
    tx: &UnboundedSender<DesktopToGuiMessages>,
    _connection_tracker: &ConnectionTrackerSender,
    dns_tracker: &UnboundedSender<DnsTrackerMessage>,
) {
    let (dns_tx, mut dns_rx) = tokio::sync::mpsc::unbounded_channel();
    let cache = if let Err(e) = dns_tracker.send(DnsTrackerMessage::DumpReverseMap { tx: dns_tx }) {
        warn!("Failed to send message to dns_tracker: {}", e);
        HashMap::new() // just send back an empty map so the gui isn't confused
                       // TODO: find a way to better signal errors back to the GUI?
                       // TODO: do we need transcation IDs?
    } else {
        dns_rx.recv().await.expect("valid dns_cache")
    };
    if let Err(e) = tx.send(DesktopToGuiMessages::DumpDnsCache(cache)) {
        warn!("Failed to send the DNS cache back to the GUI!?: {}", e);
    }
}

async fn handle_gui_dump_dns_flows(
    tx: &UnboundedSender<DesktopToGuiMessages>,
    connection_tracker: &ConnectionTrackerSender,
) {
    let func_start = Instant::now();
    // get the cache of current dns and process tracking
    let (reply_tx, mut reply_rx) = channel(128);
    use ConnectionTrackerMsg::*;
    send_or_log_sync!(
        connection_tracker,
        "connection_tracker",
        GetDnsTrafficCounters {
            tx: reply_tx,
            time_mode: TimeMode::Wallclock,
        }
    );
    let stat_entries = match reply_rx.recv().await {
        Some(entries) => entries,
        None => {
            warn!("ConnectionTracker GetDnsTrafficCounters returned null!?");
            Vec::new() // just pretend it returned nothing as a hack
        }
    };
    perf_check!(
        "handle_gui_dump_dns_flows",
        func_start,
        Duration::from_millis(100)
    );
    if let Err(e) = tx.send(DesktopToGuiMessages::DumpDnsAggregateCountersReply(
        stat_entries,
    )) {
        warn!("Sending to GUI trigged: {}", e);
    }
}

async fn handle_gui_dumpflows(
    tx: &UnboundedSender<DesktopToGuiMessages>,
    connection_tracker: &ConnectionTrackerSender,
) {
    let func_start = Instant::now();

    // get the cache of current connections
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::unbounded_channel();
    let request = ConnectionTrackerMsg::GetConnectionMeasurements {
        tx: reply_tx,
        time_mode: TimeMode::Wallclock,
    };
    if let Err(e) = connection_tracker.try_send(PerfMsgCheck::new(request)) {
        warn!("Connection Tracker queue problem: {}", e);
    }
    let measurements = match reply_rx.recv().await {
        Some(keys) => keys,
        None => {
            warn!("ConnectionTracker GetConnectionsKeys returned null!?");
            Vec::new() // just pretend it returned nothing as a hack
        }
    };
    perf_check!(
        "ConnTracker::get connection measurements",
        func_start,
        Duration::from_millis(200)
    );
    // TODO: think about whether we can implement PerfMsgCheck over to the WASM/JS side of things
    if let Err(e) = tx.send(DesktopToGuiMessages::DumpFlowsReply(measurements)) {
        warn!("Sending to GUI trigged: {}", e);
    }
}

/**
 * Top-level websocket handler
 */
pub async fn websocket_handler(
    connection_tracker: ConnectionTrackerSender,
    dns_tracker: UnboundedSender<DnsTrackerMessage>,
    process_tracker: ProcessTrackerSender,
    topology_client: TopologyServerSender,
    counter_registries: SharedExportedStatRegistries,
    ws: WebSocket,
) {
    info!("Got a websocket connection! ");

    let (ws_tx, ws_rx) = ws.split();
    // wrap the ws_tx in a clone()able channel
    let tx = websocket_sender(ws_tx).await;

    let tx_clone = tx.clone();
    let connection_tracker_clone = connection_tracker.clone();
    let _rx_handler = tokio::spawn(async move {
        handle_websocket_rx_messages(
            ws_rx,
            tx_clone,
            connection_tracker_clone,
            dns_tracker,
            process_tracker,
            topology_client,
            counter_registries,
        )
        .await;
    });

    if let Err(e) = tx.send(DesktopToGuiMessages::VersionCheck(
        desktop_common::get_git_hash_version(),
    )) {
        warn!("Error sending version check: {}", e);
    }
}
