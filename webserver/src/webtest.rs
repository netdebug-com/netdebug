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
 *    to mark when a ping/pong test is done and we should start another one.
 *    It returns the most recent RTT from the ping/pong scheme
 *
 * More tests to be added with time
 */
use chrono::Utc;
use common::{Message, ProbeReport};
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
    let _addr = addr.expect("We weren't passed a valid SocketAddr!?");
    info!("New websocket connection from {}", &addr_str);
    let (mut ws_tx, ws_rx) = websocket.split();

    let connection_tracker = context.read().await.connection_tracker.clone();

    // wrap the ws_tx with an unbounded mpsc channel because we can't clone it...
    let (tx, mut rx) = mpsc::unbounded_channel::<common::Message>();
    let (barrier_tx, mut barrier_rx) = mpsc::unbounded_channel::<f64>();
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
    // Version check - is the client build from the same git hash as the server?
    tx.send(common::Message::make_version_check())
        .unwrap_or_else(|e| {
            warn!("Sending version check: {} got {}", addr_str, e);
        });

    // send 100 rounds of pings to the client
    for probe_round in 1..100 {
        run_probe_round(
            probe_round,
            &tx,
            &mut barrier_rx,
            &connection_key,
            &connection_tracker,
            &addr_str,
        )
        .await;
    }
}

async fn run_probe_round(
    probe_round: u32,
    tx: &mpsc::UnboundedSender<Message>,
    barrier_rx: &mut mpsc::UnboundedReceiver<f64>,
    connection_key: &Option<ConnectionKey>,
    connection_tracker: &mpsc::UnboundedSender<ConnectionTrackerMsg>,
    addr_str: &String,
) {
    use common::Message::*;
    tx.send(Ping1FromServer {
        server_timestamp_ms: make_time_ms(),
    })
    .unwrap_or_else(|e| {
        warn!(
            "Closing connection: Failed to send message to {}: {}",
            addr_str, e
        );
    });
    // wait for Ping1-->Ping2-->Ping3 sequence to finish
    let rtt_estimate = barrier_rx.recv().await.unwrap_or_else(|| {
        warn!("barrier_rx returned none? channel closed!?");
        500.0 // guess 500 but should prob just die
    });
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
    // first report we get, don't clear state b/c the idle probes need that state
    match get_probe_report(connection_tracker, connection_key, false).await {
        // TODO: also log the report centrally - useful data!
        // if we got the report, send it to the remote WASM client
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
    // next, set for idle probes to get the endhost pings
    connection_tracker
        .send(ConnectionTrackerMsg::ProbeOnIdle {
            key: connection_key.clone().unwrap(),
        })
        .unwrap_or_else(|e| {
            warn!("connection_tracker::send() returned {}", e);
            return;
        });
    // TODO: do a smarter RTT estimate
    tokio::time::sleep(Duration::from_millis(rtt_estimate.round() as u64)).await;
    // second report we get, do clear state
    // TODO refactor duplicate code! signal idle report?
    match get_probe_report(connection_tracker, connection_key, true).await {
        // TODO: also log the report centrally - useful data!
        // if we got the report, send it to the remote WASM client
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

async fn get_probe_report(
    connection_tracker: &mpsc::UnboundedSender<ConnectionTrackerMsg>,
    connection_key: &Option<ConnectionKey>,
    clear_state: bool,
) -> Option<ProbeReport> {
    if let Some(key) = &connection_key {
        let key = key.clone();
        // create an async channel for the connection tracker to send us back the report on
        let (report_tx, mut report_rx) = tokio::sync::mpsc::channel(1);
        if let Err(e) = connection_tracker.send(ConnectionTrackerMsg::ProbeReport {
            key,
            clear_state,
            tx: report_tx,
        }) {
            warn!("Error talking to connection tracker: {}", e);
            None
        } else {
            // wait for the report to come on the channel
            report_rx.recv().await
        }
    } else {
        None // keylookup failed, just return None
             // TODO: this may need to be a panic!() - think about it
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
    barrier_tx: mpsc::UnboundedSender<f64>,
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
    barrier_tx: &mpsc::UnboundedSender<f64>,
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
            handle_ping2(server_timestamp_ms, client_timestamp_ms, tx, barrier_tx);
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
    barrier_tx: &mpsc::UnboundedSender<f64>,
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
    // tell the handle_websocket() that we're done with this probe round
    if let Err(e) = barrier_tx.send(rtt) {
        warn!("barrier_tx.send() produced :: {}", e);
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
            common::get_git_hash_version(),
        );
    }
}
