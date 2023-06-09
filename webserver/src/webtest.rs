use chrono::Utc;
use std::{net::SocketAddr, time::Duration};
use warp::ws::Message;

use crate::context::Context;
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use log::{info, warn};

pub async fn handle_websocket(
    _context: Context,
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
    let (mut ws_tx, mut _ws_rx) = websocket.split();

    for _i in 0..10 {
        let msg = format!("Hello {} : the UTC time is {}", addr_str, Utc::now());
        ws_tx
            .send(Message::text(msg))
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
