use std::net::SocketAddr;

use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use libconntrack::{
    send_or_log_async,
    topology_client::{TopologyServerMessage, TopologyServerSender},
    utils::PerfMsgCheck,
};
use libconntrack_wasm::topology_server_messages::{
    DesktopToTopologyServer, TopologyServerToDesktop,
};
use log::{info, warn};
use tokio::sync::mpsc::{channel, Sender};
use warp::filters::ws::{self, Message, WebSocket};

use crate::context::Context;

const DEFAULT_CHANNEL_BUFFER_SIZE: usize = 4096;
pub async fn handle_desktop_websocket(
    context: Context,
    user_agent: String,
    websocket: warp::ws::WebSocket,
    addr: Option<SocketAddr>,
) {
    let addr = addr.expect("Missing connection!?");
    info!("DesktopWebsocket connection from {}", addr);
    let (ws_tx, mut ws_rx) = websocket.split();
    let ws_tx = spawn_websocket_writer(ws_tx, DEFAULT_CHANNEL_BUFFER_SIZE, addr.to_string()).await;
    let topology_server = context.read().await.topology_server.clone();
    /*
     * Unwrap the layering here:
     * 1. WebSockets has it's own Message Type
     * 2. If it's text, unwrap the json
     * 3. If it's json, convert to a DesktopToTopology message
     */
    while let Some(ws_msg_result) = ws_rx.next().await {
        match ws_msg_result {
            Ok(ws_msg) => {
                let json_msg = match ws_msg.to_str() {
                    Ok(text) => text,
                    Err(_) => {
                        warn!("Got non-text message from websocket!? {:?}", ws_msg);
                        break;
                    }
                };
                match serde_json::from_str(json_msg) {
                    Ok(msg) => {
                        handle_desktop_message(&topology_server, msg, &ws_tx, &user_agent, &addr)
                            .await;
                    }
                    Err(e) => {
                        warn!("Failed to parse json message {}", e);
                    }
                }
            }
            Err(e) => warn!("Error processing connection {} :: {}", e, addr),
        }
    }
    info!("DesktopWebsocket connection from {} closing", addr);
}

async fn handle_desktop_message(
    topology_server: &TopologyServerSender,
    msg: DesktopToTopologyServer,
    ws_tx: &Sender<TopologyServerToDesktop>,
    user_agent: &str,
    addr: &SocketAddr,
) {
    use DesktopToTopologyServer::*;
    match msg {
        Hello => handle_hello(ws_tx, user_agent, addr).await,
        StoreConnectionMeasurement {
            connection_measurements: connection_measurement,
        } => handle_store(connection_measurement, topology_server).await,
    }
}

/**
 * Just forward on to the TopologyServer for storage
 */
async fn handle_store(
    connection_measurements: libconntrack_wasm::ConnectionMeasurements,
    topology_server: &TopologyServerSender,
) {
    send_or_log_async!(
        topology_server,
        "handle_store",
        TopologyServerMessage::StoreConnectionMeasurements {
            connection_measurements
        }
    )
    .await
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
    mut ws_tx: SplitSink<WebSocket, Message>,
    channel_buffer_size: usize,
    addr_str: String,
) -> Sender<TopologyServerToDesktop> {
    let (tx, mut rx) = channel::<
        libconntrack_wasm::topology_server_messages::TopologyServerToDesktop,
    >(channel_buffer_size);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = ws_tx
                .send(ws::Message::text(
                    serde_json::to_string(&msg).unwrap().as_str(),
                ))
                .await
            {
                warn!("Error sending on websocket {} : {}", &addr_str, e);
            }
        }
    });

    tx
}
