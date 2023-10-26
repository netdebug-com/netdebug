use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use libconntrack::{
    connection::{ConnectionTrackerMsg, ConnectionTrackerSender},
    dns_tracker::DnsTrackerMessage,
    perf_check,
    process_tracker::ProcessTrackerSender,
    utils::PerfMsgCheck,
};
use log::{debug, info, warn};
use tokio::sync::mpsc::{self, UnboundedSender};
use warp::ws::{self, Message, WebSocket};

use desktop_common::{GuiToServerMessages, ServerToGuiMessages};

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
) -> UnboundedSender<ServerToGuiMessages> {
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
    tx: UnboundedSender<ServerToGuiMessages>,
    connection_tracker: ConnectionTrackerSender,
    dns_tracker: UnboundedSender<DnsTrackerMessage>,
    _process_tracker: ProcessTrackerSender,
) {
    while let Some(msg_result) = ws_rx.next().await {
        match msg_result {
            Ok(msg) => {
                if msg.is_text() {
                    let json = msg.to_str().expect("msg.is_text() lies!");
                    match serde_json::from_str::<GuiToServerMessages>(&json) {
                        Ok(msg) => {
                            handle_gui_to_server_msg(msg, &tx, &connection_tracker, &dns_tracker)
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
    msg: GuiToServerMessages,
    tx: &UnboundedSender<ServerToGuiMessages>,
    connection_tracker: &ConnectionTrackerSender,
    dns_tracker: &UnboundedSender<DnsTrackerMessage>,
) {
    let start = std::time::Instant::now();
    match &msg {
        GuiToServerMessages::DumpFlows() => {
            debug!("Got DumpFlows request");
            handle_gui_dumpflows(tx, connection_tracker).await;
        }
        GuiToServerMessages::DumpDnsCache() => {
            handle_gui_dump_dns_cache(tx, connection_tracker, dns_tracker).await
        }
        GuiToServerMessages::DumpAggregateCounters {} => {
            handle_dump_aggregate_connection_tracker_counters(tx, connection_tracker).await
        }
    }
    perf_check!("process gui message", start, Duration::from_millis(200));
}

async fn handle_dump_aggregate_connection_tracker_counters(
    tx: &UnboundedSender<ServerToGuiMessages>,
    connection_tracker: &ConnectionTrackerSender,
) {
    let start = std::time::Instant::now();
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel();
    if let Err(e) = connection_tracker.try_send(PerfMsgCheck::new(
        ConnectionTrackerMsg::GetTrafficCounters { tx: reply_tx },
    )) {
        warn!(
            "Failed to send GetAggregateCounters to the connection tracker!?: {}",
            e
        );
    }
    if let Some(counters) = reply_rx.recv().await {
        if let Err(e) = tx.send(ServerToGuiMessages::DumpAggregateCountersReply(counters)) {
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
    tx: &UnboundedSender<ServerToGuiMessages>,
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
    if let Err(e) = tx.send(ServerToGuiMessages::DumpDnsCache(cache)) {
        warn!("Failed to send the DNS cache back to the GUI!?: {}", e);
    }
}

async fn handle_gui_dumpflows(
    tx: &UnboundedSender<ServerToGuiMessages>,
    connection_tracker: &ConnectionTrackerSender,
) {
    let func_start = Instant::now();
    // get the cache of current connections
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::unbounded_channel();
    let request = ConnectionTrackerMsg::GetConnectionMeasurements { tx: reply_tx };
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
    if let Err(e) = tx.send(ServerToGuiMessages::DumpFlowsReply(measurements)) {
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
        )
        .await;
    });

    if let Err(e) = tx.send(ServerToGuiMessages::VersionCheck(
        desktop_common::get_git_hash_version(),
    )) {
        warn!("Error sending version check: {}", e);
    }
}
