use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use libconntrack::connection::ConnectionTrackerMsg;
use log::{info, warn};
use tokio::sync::mpsc::UnboundedSender;
use warp::ws::{self, Message, WebSocket};

use desktop_common::ServerToGuiMessages;

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
 * Top-level websocket handler
 */
pub async fn websocket_handler(
    _connection_tracker: UnboundedSender<ConnectionTrackerMsg>,
    ws: WebSocket,
) {
    info!("Got a websocket connection! ");

    let (ws_tx, _ws_rx) = ws.split();
    let tx = websocket_sender(ws_tx).await;

    if let Err(e) = tx.send(ServerToGuiMessages::VersionCheck(
        desktop_common::get_git_hash_version(),
    )) {
        warn!("Error sending version check: {}", e);
    }
}
