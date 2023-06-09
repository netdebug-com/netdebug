use chrono::Utc;
use std::{net::SocketAddr, time::Duration};
use warp::ws::{self, WebSocket};

use crate::context::Context;
use futures_util::{stream::SplitStream, SinkExt, StreamExt, TryFutureExt};
use log::{info, warn};

pub async fn handle_websocket(
    context: Context,
    websocket: warp::ws::WebSocket,
    addr: Option<SocketAddr>,
) {
    let addr_str = match addr {
        None => {
            if cfg!(tests) {
                "unknown  - but ok for tests".to_string()
            } else {
                warn!("Rejecting websocket from client where remote addr=None");
                return;
            }
        }
        Some(a) => a.to_string(),
    };
    info!("New websocket connection from {}", addr_str);
    let (mut ws_tx, ws_rx) = websocket.split();

    tokio::spawn(async move { handle_ws_message(context, ws_rx) });

    // send 10 rounds of pings to the client
    for _i in 1..10 {
        let t = Utc::now().timestamp_millis() as f64;
        let msg = common::Message::Ping1FromServer {
            server_timestamp_us: t,
        };
        let json = serde_json::to_string(&msg).unwrap();
        ws_tx
            .send(ws::Message::text(json))
            .unwrap_or_else(|e| {
                warn!(
                    "Closing connection: Failed to send message to {}: {}",
                    addr_str, e
                );
            })
            .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/*
 * A ws::Message wraps our common::Message; unpack it from JSON and pass
 * on to the real handle_message() handler
 */
async fn handle_ws_message(context: Context, mut rx: SplitStream<WebSocket>) {
    while let Some(msg) = rx.next().await {
        match msg {
            Ok(msg) => {
                // TODO: figure out if this unwrap is bad!
                if let Ok(msg) = serde_json::from_str(msg.to_str().unwrap()) {
                    handle_message(&context, msg).await;
                }
            }
            Err(e) => {
                // TODO: break the connection after some number of errors
                warn!("Error reading ws message: {}", e);
            }
        }
    }
}

async fn handle_message(_context: &Context, _msg: common::Message) {
    todo!()
}
