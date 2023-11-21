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
use common_wasm::{analysis_messages::AnalysisInsights, Message, ProbeRoundReport};
use libconntrack_wasm::ConnectionKey;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::sync::mpsc::{self, UnboundedSender};
use warp::ws::{self, WebSocket};

use crate::context::Context;
use futures_util::{stream::SplitStream, SinkExt, StreamExt};
use libconntrack::{
    connection::connection_key_from_remote_sockaddr,
    connection_tracker::{ConnectionTrackerMsg, ConnectionTrackerSender},
    utils::PerfMsgCheck,
};
use log::{debug, info, warn};

fn unmap_mapped_v4(addr: &SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => *addr,
        SocketAddr::V6(sa6) => {
            let unmapped = sa6.ip().to_ipv4_mapped();
            if let Some(unmapped) = unmapped {
                SocketAddr::new(IpAddr::V4(unmapped), sa6.port())
            } else {
                *addr
            }
        }
    }
}

pub async fn handle_websocket(
    context: Context,
    user_agent: String,
    websocket: warp::ws::WebSocket,
    addr: Option<SocketAddr>,
) {
    let local_l4_port = context.read().await.local_tcp_listen_port;
    let (addr_str, connection_key) = match &addr {
        None => {
            if cfg!(tests) {
                ("unknown  - but ok for tests".to_string(), None)
            } else {
                warn!("Rejecting websocket from client where remote addr=None");
                return;
            }
        }
        Some(a) => {
            let a = unmap_mapped_v4(a);
            (
                a.to_string(),
                Some(
                    connection_key_from_remote_sockaddr(
                        local_l4_port,
                        &a,
                        etherparse::ip_number::TCP,
                    )
                    .await,
                ),
            )
        }
    };
    let _addr = addr.expect("We weren't passed a valid SocketAddr!?");
    info!(
        "New websocket connection from {} ; user agent {} ",
        &addr_str, &user_agent
    );
    let (mut ws_tx, ws_rx) = websocket.split();

    let connection_tracker = {
        let ctx = context.read().await;
        ctx.connection_tracker.clone()
    };

    // wrap the ws_tx with an unbounded mpsc channel because we can't clone it...
    let (tx, mut rx) = mpsc::unbounded_channel::<common_wasm::Message>();
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
    let key_clone = connection_key.clone().unwrap();
    let _ws_msg_handler_handle = tokio::spawn(async move {
        handle_ws_message(context, ws_rx, tx_clone, barrier_tx, key_clone).await
    });
    // set the user agent
    if let Some(key) = &connection_key {
        if let Err(e) =
            connection_tracker.try_send(PerfMsgCheck::new(ConnectionTrackerMsg::SetUserAgent {
                user_agent,
                key: key.clone(),
            }))
        {
            warn!("SetUserAgent failed for {}: {}", key, e);
        }
    }
    // Version check - is the client build from the same git hash as the server?
    tx.send(common_wasm::Message::make_version_check())
        .unwrap_or_else(|e| {
            warn!("Sending version check: {} got {}", addr_str, e);
        });

    // send 100 rounds of pings to the client
    let max_rounds = 100;
    for probe_round in 1..=max_rounds {
        run_probe_round(
            probe_round,
            &tx,
            &mut barrier_rx,
            &connection_key,
            &connection_tracker,
            &addr_str,
            max_rounds,
        )
        .await;
    }
    if let Some(connection_key) = connection_key {
        send_insights(connection_key, tx, connection_tracker).await;
    }
}

async fn send_insights(
    connection_key: ConnectionKey,
    tx: UnboundedSender<Message>,
    connection_tracker: ConnectionTrackerSender,
) {
    let (insights_tx, mut insights_rx) = tokio::sync::mpsc::channel::<Vec<AnalysisInsights>>(10);
    if let Err(e) =
        connection_tracker.try_send(PerfMsgCheck::new(ConnectionTrackerMsg::GetInsights {
            key: connection_key.clone(),
            tx: insights_tx,
        }))
    {
        warn!(
            "Error sending to connection tracker: {}:: {}",
            connection_key, e
        );
    }

    match insights_rx.recv().await {
        Some(insights) => {
            if let Err(e) = tx.send(Message::Insights { insights }) {
                warn!("Error sending to webclient: {}", e);
            }
        }
        None => warn!(
            "Connection lookup failed for insights connection {}",
            connection_key
        ),
    }
}

async fn run_probe_round(
    probe_round: u32,
    tx: &UnboundedSender<Message>,
    barrier_rx: &mut mpsc::UnboundedReceiver<f64>,
    connection_key: &Option<ConnectionKey>,
    connection_tracker: &ConnectionTrackerSender,
    addr_str: &String,
    max_rounds: u32,
) {
    use common_wasm::Message::*;
    tx.send(Ping1FromServer {
        server_timestamp_ms: make_time_ms(),
        probe_round,
        max_rounds,
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
    // first report we get, don't clear state if send_idle_probes is set
    match get_probe_report(
        connection_tracker,
        connection_key,
        probe_round,
        rtt_estimate,
        true,
    )
    .await
    {
        // TODO: also log the report centrally - useful data!
        // if we got the report, send it to the remote WASM client
        Some(report) => {
            tx.send(common_wasm::Message::ProbeReport {
                report,
                probe_round,
            })
            .unwrap_or_else(|e| {
                warn!(
                    "Error while sending ProbeReport to client: {} :: {}",
                    addr_str, e
                );
            });
        }
        None => warn!("Got 'None' back from report_tx for {}", addr_str),
    }
}

async fn get_probe_report(
    connection_tracker: &ConnectionTrackerSender,
    connection_key: &Option<ConnectionKey>,
    probe_round: u32,
    application_rtt: f64,
    clear_state: bool,
) -> Option<ProbeRoundReport> {
    if let Some(key) = &connection_key {
        let key = key.clone();
        // create an async channel for the connection tracker to send us back the report on
        let (report_tx, mut report_rx) = tokio::sync::mpsc::channel(1);
        if let Err(e) =
            connection_tracker.try_send(PerfMsgCheck::new(ConnectionTrackerMsg::ProbeReport {
                key,
                clear_state,
                tx: report_tx,
                probe_round,
                application_rtt: Some(application_rtt),
            }))
        {
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
 * A ws::Message wraps our common_wasm::Message; unpack it from JSON and pass
 * on to the real handle_message() handler
 */
async fn handle_ws_message(
    context: Context,
    mut rx: SplitStream<WebSocket>,
    tx: mpsc::UnboundedSender<Message>,
    barrier_tx: mpsc::UnboundedSender<f64>,
    connection_key: ConnectionKey,
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
                        handle_message(&context, msg, &tx, &barrier_tx, &connection_key).await;
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
    context: &Context,
    msg: Message,
    tx: &mpsc::UnboundedSender<Message>,
    barrier_tx: &mpsc::UnboundedSender<f64>,
    connection_key: &ConnectionKey,
) {
    use Message::*;
    match msg {
        VersionCheck { git_hash } => handle_version_check(git_hash, tx),
        Insights { .. } | ProbeReport { .. } | Ping1FromServer { .. } | Ping3FromServer { .. } => {
            warn!("Got Server messages from the client: ignoing {:?}", msg);
        }
        Ping2FromClient {
            server_timestamp_ms,
            client_timestamp_ms,
            probe_round,
            max_rounds,
        } => {
            handle_ping2(
                server_timestamp_ms,
                client_timestamp_ms,
                tx,
                barrier_tx,
                probe_round,
                max_rounds,
            );
        }
        SetUserAnnotation { annotation } => {
            set_user_annotation(context, annotation, connection_key).await;
        }
    }
}

async fn set_user_annotation(
    context: &Context,
    annotation: String,
    connection_key: &ConnectionKey,
) {
    let connection_tracker = context.read().await.connection_tracker.clone();
    let connection_msg = ConnectionTrackerMsg::SetUserAnnotation {
        annotation,
        key: connection_key.clone(),
    };
    if let Err(e) = connection_tracker.try_send(PerfMsgCheck::new(connection_msg)) {
        warn!(
            "SetUserAnnotation: for connection {} - got {}",
            connection_key, e
        );
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
    probe_round: u32,
    max_rounds: u32,
) {
    debug!("Got ping2 from client");
    let rtt = make_time_ms() - server_timestamp_ms;
    let reply = Message::Ping3FromServer {
        server_rtt: rtt,
        client_timestamp_ms,
        probe_round,
        max_rounds,
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
            common_wasm::get_git_hash_version(),
        );
    }
}

#[cfg(test)]
mod test {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use super::*;
    #[test]
    fn test_unmapped_mapped_v4() {
        let ip4 = IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap());
        let sa = SocketAddr::new(ip4, 42);
        assert!(unmap_mapped_v4(&sa).is_ipv4());

        let ip4 = IpAddr::V4(Ipv4Addr::from_str("192.1.2.3").unwrap());
        let sa = SocketAddr::new(ip4, 42);
        assert!(unmap_mapped_v4(&sa).is_ipv4());

        let ip6 = IpAddr::V6(Ipv6Addr::from_str("::1").unwrap());
        let sa = SocketAddr::new(ip6, 42);
        assert!(unmap_mapped_v4(&sa).is_ipv6());
        assert_eq!(unmap_mapped_v4(&sa).ip(), ip6);

        let ip6 = IpAddr::V6(Ipv6Addr::from_str("2001:0db8::1").unwrap());
        let sa = SocketAddr::new(ip6, 42);
        assert!(unmap_mapped_v4(&sa).is_ipv6());
        assert_eq!(unmap_mapped_v4(&sa).ip(), ip6);

        let ip6 = IpAddr::V6(Ipv6Addr::from_str("::ffff:127.0.0.1").unwrap());
        assert_eq!(
            ip6,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x1)),
        );
        let sa = SocketAddr::new(ip6, 42);
        assert!(unmap_mapped_v4(&sa).is_ipv4());
        assert_eq!(
            unmap_mapped_v4(&sa).ip(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );

        let ip6 = IpAddr::V6(Ipv6Addr::from_str("::ffff:1.2.3.4").unwrap());
        assert_eq!(
            ip6,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x102, 0x304)),
        );
        let sa = SocketAddr::new(ip6, 42);
        assert!(unmap_mapped_v4(&sa).is_ipv4());
        assert_eq!(
            unmap_mapped_v4(&sa).ip(),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
    }
}
