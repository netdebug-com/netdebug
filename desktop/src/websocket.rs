use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use libconntrack::connection::ConnectionTrackerMsg;
use log::{info, warn, debug};
use tokio::sync::mpsc::UnboundedSender;
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
            if let Err(e) = ws_tx
                .send(ws::Message::text(
                    serde_json::to_string(&msg).unwrap().as_str(),
                ))
                .await
            {
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
    connection_tracker: UnboundedSender<ConnectionTrackerMsg>,
) {
    while let Some(msg_result) = ws_rx.next().await {
        match msg_result {
            Ok(msg) => {
                if msg.is_text() {
                    let json = msg.to_str().expect("msg.is_text() lies!");
                    match serde_json::from_str::<GuiToServerMessages>(&json) {
                        Ok(msg) => handle_gui_to_server_msg(msg, &tx, &connection_tracker).await,
                        Err(e) => {
                            warn!("Failed to parse JSON websocket msg: {:?}", e);
                        }
                    }
                } else {
                    info!("Ignoring websocket non-text message {:?}", msg);
                }
            }
            Err(_) => todo!(),
        }
    }
}

async fn handle_gui_to_server_msg(
    msg: GuiToServerMessages,
    tx: &UnboundedSender<ServerToGuiMessages>,
    connection_tracker: &UnboundedSender<ConnectionTrackerMsg>,
) {
    match msg {
        GuiToServerMessages::DumpFlows() => {
            debug!("Got DumpFlows request");
            handle_gui_dumpflows(tx, connection_tracker).await;
        },
    }
}

async fn handle_gui_dumpflows(
    tx: &UnboundedSender<ServerToGuiMessages>,
    connection_tracker: &UnboundedSender<ConnectionTrackerMsg>,
) {
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel(10);
    let request = ConnectionTrackerMsg::GetConnectionKeys { tx: reply_tx };
    connection_tracker
        .send(request)
        .expect("connection tracker down?");
    let keys = match reply_rx.recv().await {
        Some(keys) => keys,
        None => {
            warn!("ConnectionTracker GetConnectionsKeys returned null!?");
            Vec::new() // just pretend it returned nothing as a hack
        }
    };
    let key_strings: Vec<String> = keys.iter().map(|k| format!("{}", k)).collect();
    if let Err(e) = tx.send(ServerToGuiMessages::DumpFlowsReply(key_strings)) {
        warn!("Sending to GUI trigged: {}", e);
    }

}

/**
 * Top-level websocket handler
 */
pub async fn websocket_handler(
    connection_tracker: UnboundedSender<ConnectionTrackerMsg>,
    ws: WebSocket,
) {
    info!("Got a websocket connection! ");

    let (ws_tx, ws_rx) = ws.split();
    // wrap the ws_tx in a clone()able channel
    let tx = websocket_sender(ws_tx).await;

    let tx_clone = tx.clone();
    let connection_tracker_clone = connection_tracker.clone();
    let _rx_handler = tokio::spawn(async move {
        handle_websocket_rx_messages(ws_rx, tx_clone, connection_tracker_clone).await;
    });

    if let Err(e) = tx.send(ServerToGuiMessages::VersionCheck(
        desktop_common::get_git_hash_version(),
    )) {
        warn!("Error sending version check: {}", e);
    }
}
