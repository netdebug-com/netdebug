use std::net::SocketAddr;

use axum::extract::ws::{self, WebSocket};
use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use libconntrack::{
    send_or_log_async,
    topology_client::{TopologyServerMessage, TopologyServerSender},
    utils::PerfMsgCheck,
};
use libconntrack_wasm::topology_server_messages::{
    DesktopLogLevel, DesktopToTopologyServer, TopologyServerToDesktop,
};
use log::{debug, info, warn};
use tokio::sync::mpsc::{channel, Sender};
use uuid::Uuid;

use crate::{
    context::Context,
    remotedb_client::{RemoteDBClientMessages, RemoteDBClientSender},
};

const DEFAULT_CHANNEL_BUFFER_SIZE: usize = 4096;
pub async fn handle_desktop_websocket(
    websocket: WebSocket,
    context: Context,
    user_agent: String,
    addr: SocketAddr,
) {
    info!("DesktopWebsocket connection from {}", addr);
    let (ws_tx, mut ws_rx) = websocket.split();
    let ws_tx = spawn_websocket_writer(ws_tx, DEFAULT_CHANNEL_BUFFER_SIZE, addr.to_string()).await;
    let (topology_server, remotedb_client) = {
        let lock = context.read().await;
        (lock.topology_server.clone(), lock.remotedb_client.clone())
    };

    // TODO(Gregor): put the real/persistent client's UUID here that we get from the authentication
    let client_uuid = Uuid::new_v3(&Uuid::NAMESPACE_DNS, addr.ip().to_string().as_bytes());
    /*
     * Unwrap the layering here:
     * 1. WebSockets has it's own Message Type
     * 2. If it's text, unwrap the json
     * 3. If it's json, convert to a DesktopToTopology message
     */
    while let Some(ws_msg_result) = ws_rx.next().await {
        match ws_msg_result {
            Ok(ws_msg) => match ws_msg {
                ws::Message::Text(text) => match serde_json::from_str(&text) {
                    Ok(desktop_to_topo_msg) => {
                        handle_desktop_message(
                            &topology_server,
                            &remotedb_client,
                            desktop_to_topo_msg,
                            &ws_tx,
                            &user_agent,
                            &addr,
                            client_uuid,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!("Cannot parse text message from websocket. Error: {}", e);
                        break;
                    }
                },
                ws::Message::Binary(_) => {
                    warn!("Got non-text message from websocket!? {:?}", ws_msg);
                }
                ws::Message::Ping(_) | ws::Message::Pong(_) | ws::Message::Close(_) => {
                    // ignore
                }
            },
            Err(e) => warn!("Error processing connection {} :: {}", e, addr),
        }
    }
    info!("DesktopWebsocket connection from {} closing", addr);
}

async fn handle_desktop_message(
    topology_server: &TopologyServerSender,
    remotedb_client: &Option<RemoteDBClientSender>,
    msg: DesktopToTopologyServer,
    ws_tx: &Sender<TopologyServerToDesktop>,
    user_agent: &str,
    addr: &SocketAddr,
    client_uuid: Uuid,
) {
    use DesktopToTopologyServer::*;
    match msg {
        Hello => handle_hello(ws_tx, user_agent, addr).await,
        StoreConnectionMeasurement {
            connection_measurements: connection_measurement,
            // TODO: put client Info (OS, version, etc.) in the message
        } => handle_store_measurements(connection_measurement, client_uuid, remotedb_client).await,
        InferCongestion {
            connection_measurements,
        } => handle_infer_congestion(ws_tx, connection_measurements, topology_server).await,
        PushCounters {
            timestamp,
            counters,
            os,
            version,
            .. // TODO: use client_id
        } => handle_push_counters(remotedb_client, timestamp, counters, addr, os, version).await,
        PushLog {
            timestamp,
            msg,
            level,
            os,
            version,
            .. // TODO: replace the addr.to_string() with the client id from the message
        } => handle_push_log(remotedb_client, timestamp, msg, level, os, version, addr.to_string()).await,
        Ping => {
            warn!("Received a DesktopToTopologyServer::Ping as JSON which should never be sent over the wire");
        }
    }
}

async fn handle_push_log(
    remotedb_client: &Option<RemoteDBClientSender>,
    time: chrono::DateTime<chrono::Utc>,
    msg: String,
    level: DesktopLogLevel,
    os: String,
    version: String,
    client_id: String,
) {
    if let Some(remotedb_client) = remotedb_client {
        send_or_log_async!(
            remotedb_client,
            "handle_push_log",
            RemoteDBClientMessages::StoreLog {
                msg,
                level,
                os,
                version,
                client_id,
                time,
            }
        )
        .await;
    } else {
        debug!(
            "Storage not configured:: not storing log from {} :: {:?} :: {} :: {} :: {} :: {} :: ",
            client_id, level, time, os, version, msg
        );
    }
}

async fn handle_push_counters(
    remotedb_client: &Option<RemoteDBClientSender>,
    timestamp: chrono::DateTime<chrono::Utc>,
    counters: indexmap::IndexMap<String, u64>,
    addr: &SocketAddr,
    os: String,
    version: String,
) {
    if let Some(remotedb_client) = remotedb_client {
        debug!(
            "Got {} counters from {}  at {} - OS {} version {} : TODO - store them!",
            counters.len(),
            addr,
            timestamp,
            os,
            version
        );
        send_or_log_async!(
            remotedb_client,
            "handle_push_counters",
            RemoteDBClientMessages::StoreCounters {
                counters,
                source: addr.to_string(), // TODO: replace this with an obfuscated client identifier!
                time: timestamp,
                os,
                version
            }
        )
        .await;
    } else {
        debug!(
            "Got {} counters from {}. NOT STORING THEM -- NO REMOTE DB CONFIGURED",
            counters.len(),
            addr,
        );
    }
}

async fn handle_infer_congestion(
    ws_tx: &Sender<TopologyServerToDesktop>,
    connection_measurements: Vec<libconntrack_wasm::ConnectionMeasurements>,
    topology_server: &Sender<PerfMsgCheck<TopologyServerMessage>>,
) {
    // spawn this request off to a dedicated task as it might take a while to process
    // and the client is completely async
    let topology_server = topology_server.clone();
    let ws_tx = ws_tx.clone();
    tokio::spawn(async move {
        let (reply_tx, mut reply_rx) = channel(1);
        send_or_log_async!(
            topology_server,
            "handle_infer_congestion",
            TopologyServerMessage::InferCongestion {
                connection_measurements,
                reply_tx
            }
        )
        .await;
        let congestion_summary = match reply_rx.recv().await {
            Some(c) => c.perf_check_get("handle_infer_congstion"),
            None => {
                warn!("TopologyServer returned None!?");
                return;
            }
        };
        if let Err(e) = ws_tx
            .send(TopologyServerToDesktop::InferCongestionReply { congestion_summary })
            .await
        {
            warn!("Tried to write to websocket to desktop but got: {}", e);
        }
    });
}

/**
 * Just forward on to the RemoteDBClient for storage
 */
async fn handle_store_measurements(
    connection_measurements: Box<libconntrack_wasm::ConnectionMeasurements>,
    client_uuid: Uuid,
    remotedb_client: &Option<RemoteDBClientSender>,
) {
    if let Some(remotedb_client) = remotedb_client {
        send_or_log_async!(
            remotedb_client,
            "handle_store",
            RemoteDBClientMessages::StoreConnectionMeasurements {
                connection_measurements,
                client_uuid
            }
        )
        .await
    } else {
        debug!(
            "Would have stored connection_measurement, but no remotedb_client specified: {:?}",
            connection_measurements
        );
    }
}

async fn handle_hello(
    ws_tx: &Sender<TopologyServerToDesktop>,
    user_agent: &str,
    addr: &SocketAddr,
) {
    info!("Handling HELLO message from {:?}", addr);
    if let Err(e) = ws_tx
        .send(TopologyServerToDesktop::Hello {
            client_ip: addr.ip(),
            user_agent: user_agent.to_string(),
        })
        .await
    {
        warn!("Problem sending HELLO reply to {:?}:: {}", addr, e);
    }
}

/**
 * The ws_tx from websocket doesn't support .clone() so if we want to
 * write to it from multiple places, we need to spawn a task off to send
 * messages to it via the standard tokio::sync::mpsc::channel method.
 */
pub async fn spawn_websocket_writer(
    mut ws_tx: SplitSink<WebSocket, ws::Message>,
    channel_buffer_size: usize,
    addr_str: String,
) -> Sender<TopologyServerToDesktop> {
    let (tx, mut rx) = channel::<
        libconntrack_wasm::topology_server_messages::TopologyServerToDesktop,
    >(channel_buffer_size);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = ws_tx
                .send(ws::Message::Text(serde_json::to_string(&msg).unwrap()))
                .await
            {
                warn!("Error sending on websocket {} : {}", &addr_str, e);
            }
        }
    });

    tx
}
