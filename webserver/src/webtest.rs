/**
 * This is the main test logic.  Currently the WASM client connects
 * to the server with a websocket and we setup a ping/pong message
 * back and forth ~100 times.  With each ping/pong round, we send a
 * burst of TCP restransmits as inband probes.
 *
 * We use three different mpsc channels which
 * can get confusing:
 * 1) tx/rx : the ws_tx function does not allow itself to be cloned
 *     so we set up a special thread to wrap the ws_tx with a standard tokio mspc channel
 *     so that multiple senders can independently send to the ws_tx channel, e.g.,
 *     the main handle_websocket() and the response handles
 * 2) connection_tracker: this is the tx side of talking to the connection tracker
 * 3) barrier: this is used to single between the handle_websocket and handle_ws_message
 *    to mark when a ping/pong test is done and we should start another one
 *
 * More tests to be added with time
 */
use chrono::Utc;
use common::Message;
use std::{net::SocketAddr, time::Duration};
use tokio::sync::mpsc;
use warp::ws::{self, WebSocket};

use crate::{
    connection::{ConnectionKey, ConnectionTrackerMsg},
    context::Context,
};
use futures_util::{stream::SplitStream, SinkExt, StreamExt};
use log::{debug, info, warn};

pub async fn handle_websocket(
    context: Context,
    websocket: warp::ws::WebSocket,
    addr: Option<SocketAddr>,
) {
    let (addr_str, connection_key) = match &addr {
        None => {
            if cfg!(tests) {
                ("unknown  - but ok for tests".to_string(), None)
            } else {
                warn!("Rejecting websocket from client where remote addr=None");
                return;
            }
        }
        Some(a) => (
            a.to_string(),
            Some(ConnectionKey::new(&context, a, etherparse::ip_number::TCP).await),
        ),
    };
    info!("New websocket connection from {}", &addr_str);
    let (mut ws_tx, ws_rx) = websocket.split();

    let connection_tracker = context.read().await.connection_tracker.clone();

    // wrap the ws_tx with an unbounded mpsc channel because we can't clone it...
    let (tx, mut rx) = mpsc::unbounded_channel::<common::Message>();
    let (barrier_tx, mut barrier_rx) = mpsc::unbounded_channel::<()>();
    let tx_clone = tx.clone();
    let addr_str_clone = addr_str.clone();
    let _sender_wrapper_handle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = ws_tx
                .send(ws::Message::text(
                    serde_json::to_string(&msg).unwrap().as_str(),
                ))
                .await
            {
                warn!("Error sending on websocket {} : {}", &addr_str_clone, e);
            }
        }
    });

    let _ws_msg_handler_handle =
        tokio::spawn(async move { handle_ws_message(context, ws_rx, tx_clone, barrier_tx).await });

    // send 100 rounds of pings to the client
    for probe_round in 1..100 {
        let t = make_time_ms();
        let msg = common::Message::Ping1FromServer {
            server_timestamp_ms: t,
        };
        tx.send(msg).unwrap_or_else(|e| {
            warn!(
                "Closing connection: Failed to send message to {}: {}",
                addr_str, e
            );
        });
        if let None = barrier_rx.recv().await {
            warn!("barrier_rx returned none? channel closed!?");
            break;
        }
        // the application-to-application ping is done; wait a little longer
        // just to make sure any out-of-order probes are flushed/processed from the network
        // This may sound pedantic as the application ping should take longer than the in-band
        // network probes, but with CPU processing delays on routers, this may not always be the
        // case.  10ms should be ok?!
        tokio::time::sleep(Duration::from_millis(10)).await;
        // now that time has passed, collect the ProbeReport from the connection tracker
        debug!(
            "Collecting probe report for {} :: {}",
            addr_str, probe_round
        );
        if let Some(key) = &connection_key {
            let key = key.clone();
            let (report_tx, mut report_rx) = tokio::sync::mpsc::channel(1);
            if let Err(e) = connection_tracker.send(ConnectionTrackerMsg::ProbeReport {
                key,
                clear_state: true,
                tx: report_tx,
            }) {
                warn!("Error talking to connection tracker: {}", e);
            } else {
                match report_rx.recv().await {
                    Some(report) => tx
                        .send(common::Message::ProbeReport {
                            report,
                            probe_round,
                        })
                        .unwrap_or_else(|e| {
                            warn!(
                                "Error while sending ProbeReport to client: {} :: {}",
                                addr_str, e
                            );
                        }),
                    None => warn!("Got 'None' back from report_tx for {}", addr_str),
                }
            }
        }
    }
}

/*
 * A ws::Message wraps our common::Message; unpack it from JSON and pass
 * on to the real handle_message() handler
 */
async fn handle_ws_message(
    context: Context,
    mut rx: SplitStream<WebSocket>,
    tx: mpsc::UnboundedSender<Message>,
    barrier_tx: mpsc::UnboundedSender<()>,
) {
    debug!("In handle_ws_message()");
    while let Some(raw_msg) = rx.next().await {
        match raw_msg {
            Ok(msg) => {
                let msg = match msg.to_str() {
                    Ok(text) => text,
                    Err(_) => {
                        warn!("Got non-text message from websocket!? {:?}", msg);
                        break;
                    }
                };
                match serde_json::from_str(msg) {
                    Ok(msg) => {
                        handle_message(&context, msg, &tx, &barrier_tx).await;
                    }
                    Err(e) => {
                        warn!("Failed to parse json message {}", e);
                    }
                }
            }
            Err(e) => {
                // TODO: break the connection after some number of errors
                warn!("Error reading ws message: {}", e);
            }
        }
    }
}

async fn handle_message(
    _context: &Context,
    msg: Message,
    tx: &mpsc::UnboundedSender<Message>,
    barrier_tx: &mpsc::UnboundedSender<()>,
) {
    use Message::*;
    match msg {
        VersionCheck { git_hash } => handle_version_check(git_hash, tx),
        ProbeReport {
            report: _,
            probe_round: _,
        }
        | Ping1FromServer {
            server_timestamp_ms: _,
        }
        | Ping3FromServer {
            server_rtt: _,
            client_timestamp_ms: _,
        } => {
            warn!("Got Server messages from the client: ignoing {:?}", msg);
        }
        Ping2FromClient {
            server_timestamp_ms,
            client_timestamp_ms,
        } => {
            handle_ping2(server_timestamp_ms, client_timestamp_ms, tx);
            // tell the handle_websocket() that we're done with this probe round
            if let Err(e) = barrier_tx.send(()) {
                warn!("barrier_tx.send() produced :: {}", e);
            }
        }
    }
}

fn make_time_ms() -> f64 {
    Utc::now().timestamp_micros() as f64 / 1000.0
}

fn handle_ping2(
    server_timestamp_ms: f64,
    client_timestamp_ms: f64,
    tx: &mpsc::UnboundedSender<Message>,
) {
    debug!("Got ping2 from client");
    let rtt = make_time_ms() - server_timestamp_ms;
    let reply = Message::Ping3FromServer {
        server_rtt: rtt,
        client_timestamp_ms: client_timestamp_ms,
    };
    if let Err(e) = tx.send(reply) {
        warn!("Websocket write failed: {}", e);
    }
}

fn handle_version_check(git_hash: String, _tx: &mpsc::UnboundedSender<Message>) {
    // this is an ack message from the client and they should only send
    // it if they have the same version, but just sanity check it anyway
    // NOTE that if a client hass a different version, they will reload
    if !Message::check_version(&git_hash) {
        warn!(
            "Weird: client has differnt version than server but thinks it's the same: 
        {} != {}",
            &git_hash,
            env!("GIT_HASH")
        );
    }
}
