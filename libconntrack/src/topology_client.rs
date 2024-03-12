use std::net::IpAddr;
use std::time::Duration;

// Workaround to use prinltn! for logs.
#[cfg(not(test))]
use log::{debug, info, warn};
#[cfg(test)]
use std::{println as debug, println as info, println as warn};

use crate::send_or_log_async;
use crate::utils::PerfMsgCheck;
use chrono::Utc;
use common_wasm::get_git_hash_version;
use common_wasm::timeseries_stats::{
    CounterProvider, CounterProviderWithTimeUpdate, ExportedStatRegistry,
    SharedExportedStatRegistries, StatHandle, StatType, Units,
};
use futures::sink::SinkExt;
use futures_util::stream::SplitSink;
use futures_util::StreamExt;
use libconntrack_wasm::topology_server_messages::{
    CongestionSummary, DesktopToTopologyServer, TopologyServerToDesktop,
};
use libconntrack_wasm::{ConnectionMeasurements, NetworkInterfaceState};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender, WeakSender};
use tokio_tungstenite::tungstenite::error::Error as TungsteniteError;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

const COUNTER_REMOTE_SYNC_INTERVAL_MS: u64 = 60_000;
const WS_KEEPALIVE_INTERVAL_MS: u64 = 1_000;
const X_NETDEBUG_CLIENT_UUID_HEADER: &str = "X-Netdebug-Client-Uuid";

/// TopologyServer RPC messages. Used inside the desktop binary to
/// send RPC requests from the UI facing rest endpoints to topology_client
/// and from there to the server via websocket
/// Also used inside the topology server between the websocket handler
/// (from the desktop) to the TopologyServer impl that implements the
/// actual business logic
#[derive(Clone, Debug)]
pub enum TopologyRpcMessage {
    GetMyIpAndUserAgent {
        reply_tx: Sender<PerfMsgCheck<(IpAddr, String)>>,
    },

    InferCongestion {
        connection_measurements: Vec<ConnectionMeasurements>,
        reply_tx: Sender<PerfMsgCheck<CongestionSummary>>,
    },
}

pub type TopologyRpcSender = Sender<PerfMsgCheck<TopologyRpcMessage>>;
pub type TopologyRpcReceiver = Receiver<PerfMsgCheck<TopologyRpcMessage>>;

/// Messages used to store data (ConnectionMeasurments, Pings, etc.) to a remote
/// backend. E.g., in the desktop it can be used to send a message to the topology_client
/// (which has the WS connection to the server). In the webserver it can be used for conn_tracker
/// to send measurements to the DB backend.
#[derive(Clone, Debug)]
pub enum DataStorageMessage {
    StoreConnectionMeasurements {
        connection_measurements: Box<ConnectionMeasurements>,
    },
    StoreNetworkInterfaceState {
        network_interface_state: NetworkInterfaceState,
    },
}

pub type DataStorageSender = Sender<PerfMsgCheck<DataStorageMessage>>;
pub type DataStorageReceiver = Receiver<PerfMsgCheck<DataStorageMessage>>;

/// A local agent to manage all of the state around talking to the topology server
const DEFAULT_FIRST_RETRY_TIME_MS: u64 = 100;
pub struct TopologyServerConnection {
    /// WebSocket url to topology server, e.g., ws://localhost:3030
    url: String,
    /// A copy of the tx queue to send to us, in case others need it
    rpc_tx: TopologyRpcSender,
    rpc_rx: TopologyRpcReceiver,
    /// A copy of the tx queue to send to us, in case others need it
    storage_tx: DataStorageSender,
    storage_rx: DataStorageReceiver,
    buffer_size: usize,
    /// If we fail to connect, when we next will try to connect; exponential back off
    retry_time: Duration,
    /// If we fail to connect, the max time we will wait between connections
    max_retry_time: Duration,
    /// A cache of the hello message from the server which includes
    /// The public IP of this machine (e.g., a MyIP service) and the user-agent
    server_hello: Option<(IpAddr, String)>,
    /// A list of local agents that are waiting for the hello message info, e.g., the local IP
    waiting_for_hello: Vec<Sender<PerfMsgCheck<(IpAddr, String)>>>,
    waiting_for_congestion_summary: Vec<Sender<PerfMsgCheck<CongestionSummary>>>,
    retry_stat: StatHandle,
    /// stats about msgs that go from us/the desktop to the remote topology servert
    desktop2server_msgs_stat: StatHandle,
    /// a subset of desktop2server_msgs: only the ones for the store operation
    desktop2server_store_msgs_stat: StatHandle,
    /// stats about msgs that come from the server back to us/the desktop
    server2desktop_msgs_stat: StatHandle,
    /// Maintain a pointer to the whole counters registry for remote export
    super_counters_registries: SharedExportedStatRegistries,
    /// Send a keepalive (ping) to the WS sender periodically
    ws_keepalive_interval: tokio::time::Duration,
    // The UUID of the client for identifying it to the server
    client_uuid: Uuid,
}

impl TopologyServerConnection {
    #[allow(clippy::too_many_arguments)]
    fn new(
        url: String,
        rpc_tx: TopologyRpcSender,
        rpc_rx: TopologyRpcReceiver,
        storage_tx: DataStorageSender,
        storage_rx: DataStorageReceiver,
        buffer_size: usize,
        max_retry_time: Duration,
        client_uuid: Uuid,
        super_counters_registry: SharedExportedStatRegistries,
        stats_registry: ExportedStatRegistry,
    ) -> TopologyServerConnection {
        TopologyServerConnection {
            url,
            rpc_tx,
            rpc_rx,
            storage_tx,
            storage_rx,
            buffer_size,
            retry_time: Duration::from_millis(DEFAULT_FIRST_RETRY_TIME_MS),
            max_retry_time,
            server_hello: None,
            waiting_for_hello: Vec::new(),
            waiting_for_congestion_summary: Vec::new(),
            retry_stat: stats_registry.add_stat(
                "connection_retries",
                Units::None,
                vec![StatType::SUM, StatType::RATE],
            ),
            server2desktop_msgs_stat: stats_registry.add_stat(
                "server2desktop_msgs",
                Units::None,
                vec![StatType::SUM, StatType::RATE],
            ),
            desktop2server_msgs_stat: stats_registry.add_stat(
                "desktop2server_msgs",
                Units::Bytes,
                vec![StatType::SUM, StatType::RATE],
            ),
            desktop2server_store_msgs_stat: stats_registry.add_stat(
                "desktop2server_store_msgs",
                Units::None,
                vec![StatType::SUM, StatType::COUNT, StatType::RATE],
            ),
            super_counters_registries: super_counters_registry,
            ws_keepalive_interval: tokio::time::Duration::from_millis(WS_KEEPALIVE_INTERVAL_MS),
            client_uuid,
        }
    }

    pub fn spawn(
        url: String,
        buffer_size: usize,
        max_retry_time: Duration,
        client_uuid: Uuid,
        super_counters_registry: SharedExportedStatRegistries,
        stats_registry: ExportedStatRegistry,
    ) -> (TopologyRpcSender, DataStorageSender) {
        let (rpc_tx, rpc_rx) = channel(buffer_size);
        let rpc_tx_clone = rpc_tx.clone();
        let (storage_tx, storage_rx) = channel(buffer_size);
        let storage_tx_clone = storage_tx.clone();
        tokio::spawn(async move {
            let topology_server = TopologyServerConnection::new(
                url,
                rpc_tx,
                rpc_rx,
                storage_tx,
                storage_rx,
                buffer_size,
                max_retry_time,
                client_uuid,
                super_counters_registry,
                stats_registry,
            );
            topology_server.rx_loop().await;
        });
        (rpc_tx_clone, storage_tx_clone)
    }

    /// Loop indefinitely over our inputs from the desktop and the
    /// remote server
    async fn rx_loop(mut self) {
        loop {
            self.rx_loop_one_connection().await;
        }
    }

    /// Connect to the topology server just one time and return when it fails/ends
    /// Split out from rx_loop() to simplify testing
    async fn rx_loop_one_connection(&mut self) {
        // connect ala https://github.com/snapview/tokio-tungstenite/blob/master/examples/client.rs
        // Intentionally panic here if we got a bad URL
        let url = url::Url::parse(&self.url).unwrap_or_else(|_| panic!("Bad url! {}", &self.url));

        // TODO: use a real token / shared secret here instead of the client_id
        let auth_header = "Bearer ".to_owned() + &self.client_uuid.as_hyphenated().to_string();
        let client_uuid_header = self.client_uuid.as_hyphenated().to_string();
        // need to generate a custom request because we need to set the User-Agent for our webserver
        let req = Request::builder()
            .method("GET")
            .header("Host", url.authority())
            .header("User-Agent", "NetDebug Desktop version x.y.z")
            .header(X_NETDEBUG_CLIENT_UUID_HEADER, client_uuid_header)
            .header("Authorization", auth_header)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .uri(self.url.clone())
            .body(())
            .unwrap();
        let (ws_write, mut ws_read) = match connect_async(req).await {
            Ok((ws_stream, response)) => {
                info!(
                    "Connected to the topology server {} :: {:?}",
                    self.url, response
                );
                self.retry_time = Duration::from_millis(DEFAULT_FIRST_RETRY_TIME_MS);
                ws_stream.split()
            }
            // From https://docs.rs/tungstenite/latest/tungstenite/error/enum.Error.html
            // none of the error types we can get back from this connection attempt are fatal, so
            // always retry.
            Err(e) => {
                self.retry_time = std::cmp::min(self.retry_time * 2, self.max_retry_time); // capped exponential backoff
                warn!(
                    "Failed to connect to TopologyServer {} : retrying in {:?} :: {}",
                    self.url, self.retry_time, e
                );
                self.retry_stat.bump();
                tokio::time::sleep(self.retry_time).await;
                return;
            }
        };
        // the writer task will exit once the writer is closed
        let ws_tx = self.spawn_ws_writer(ws_write).await;
        // respawn this with each new topology server connection
        self.spawn_periodic_write_counters_to_remote(
            // Only pass a WeakSender. This way the periodic writer task will exit once we drop `ws_tx`
            // in this function.
            ws_tx.clone().downgrade(),
            tokio::time::Duration::from_millis(COUNTER_REMOTE_SYNC_INTERVAL_MS),
        );
        // send an initial hello to start the connection
        if let Err(e) = ws_tx
            .send(PerfMsgCheck::new(DesktopToTopologyServer::Hello))
            .await
        {
            warn!("Failed to send hello to TopologyServer: {}", e);
            return;
        }
        let allowed_time_between_pongs = self.ws_keepalive_interval * 2;
        let mut last_ws_received_time = tokio::time::Instant::now();
        let mut keepalive_ticks = tokio::time::interval(self.ws_keepalive_interval);
        // if we are missing ticks (i.e., sending ping messages) skip over the missed ones.
        keepalive_ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // now wait for internal users to send traffic to us as well as the topology server to send us messages
        loop {
            tokio::select! {
                wrapped_ws_msg = ws_read.next() => {
                    if !self.handle_wrapped_ws_msg(wrapped_ws_msg).await {
                        break;
                    };
                    last_ws_received_time = tokio::time::Instant::now();
                }
                rpc_msg = self.rpc_rx.recv() => match rpc_msg {
                    Some(desktop_msg) => self.handle_desktop_rpc_msg(desktop_msg, &ws_tx).await,
                    None => warn!("Got None back from TopologyServerConnection rx!?"),
                },
                storage_msg = self.storage_rx.recv() => match storage_msg {
                    Some(desktop_msg) => self.handle_desktop_storage_msg(desktop_msg, &ws_tx).await,
                    None => warn!("Got None back from TopologyServerConnection rx!?"),
                },
                _ = keepalive_ticks.tick() => {
                    let _ = ws_tx.try_send(PerfMsgCheck::new(DesktopToTopologyServer::Ping));
                    if last_ws_received_time.elapsed() > allowed_time_between_pongs {
                        warn!("Timed out waiting for keepalive message from websocket. Reconnecting");
                        break;
                    }
                }
            }
        }
        self.server_hello = None;
    }

    // Helper function to deal with the convoluted type we get when trying to read from the
    // websocket reader with a timeout.
    async fn handle_wrapped_ws_msg(
        &mut self,
        wrapped_ws_msg: Option<Result<Message, TungsteniteError>>,
    ) -> bool {
        match wrapped_ws_msg {
            Some(Ok(ws_msg)) => self.handle_ws_msg(ws_msg).await,
            Some(Err(e)) => {
                warn!("Got an error from the TopologyServer: reconnecting {}", e);
                return false;
            }
            None => {
                warn!("Got None back from TopologyServer (connection dead?): reconnecting");
                return false;
            }
        }
        true
    }

    pub async fn handle_ws_msg(&mut self, ws_msg: Message) {
        self.server2desktop_msgs_stat.bump();
        let msg = match ws_msg {
            Message::Text(json_msg) => {
                match serde_json::from_str::<TopologyServerToDesktop>(&json_msg) {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!(
                            "Failed to parse websocket json message: {:?} :: {}",
                            json_msg, e
                        );
                        return;
                    }
                }
            }
            Message::Pong(_) => {
                // we can just ignore pongs.
                debug!("Received pong websocket message");
                return;
            }
            _other => {
                warn!("Ignoring non-text Websocket message: {:?}", _other);
                return;
            }
        };
        // we have a valid message
        use TopologyServerToDesktop::*;
        match msg {
            Hello {
                client_ip,
                user_agent,
            } => self.handle_topology_hello(client_ip, user_agent).await,
            InferCongestionReply { congestion_summary } => {
                self.handle_infer_congestion_reply(congestion_summary).await
            }
        }
    }

    #[allow(unused)] // for now, we'll eventually need this
    pub fn get_rpc_tx(&self) -> TopologyRpcSender {
        self.rpc_tx.clone()
    }

    #[allow(unused)] // for now, we'll eventually need this
    pub fn get_storage_tx(&self) -> DataStorageSender {
        self.storage_tx.clone()
    }

    pub async fn handle_desktop_rpc_msg(
        &mut self,
        desktop_msg: PerfMsgCheck<TopologyRpcMessage>,
        ws_tx: &Sender<PerfMsgCheck<DesktopToTopologyServer>>,
    ) {
        use TopologyRpcMessage::*;
        match desktop_msg.perf_check_get("TopologyServerConnection:: handle_desktop_msg()") {
            GetMyIpAndUserAgent { reply_tx } => {
                // if we have it cached, then reply right away, else queue them
                if let Some(hello) = &self.server_hello {
                    send_or_log_async!(reply_tx, "topology server hello", hello.clone()).await;
                } else {
                    info!("Request for topology server Hello/WhatsMyIp queued");
                    self.waiting_for_hello.push(reply_tx.clone());
                }
            }
            InferCongestion {
                connection_measurements,
                reply_tx,
            } => {
                self.handle_infer_congestion(ws_tx, connection_measurements, reply_tx)
                    .await
            }
        }
    }

    pub async fn handle_desktop_storage_msg(
        &mut self,
        desktop_msg: PerfMsgCheck<DataStorageMessage>,
        ws_tx: &Sender<PerfMsgCheck<DesktopToTopologyServer>>,
    ) {
        use DataStorageMessage::*;
        match desktop_msg.perf_check_get("TopologyServerConnection:: handle_desktop_msg()") {
            StoreConnectionMeasurements {
                connection_measurements,
            } => {
                send_or_log_async!(
                    ws_tx,
                    "handle_desktop_msg::StoreConnectionMeasurement",
                    DesktopToTopologyServer::StoreConnectionMeasurement {
                        connection_measurements,
                    },
                    self.desktop2server_store_msgs_stat
                )
                .await
            }
            StoreNetworkInterfaceState {
                network_interface_state,
            } => {
                send_or_log_async!(
                    ws_tx,
                    "handle_desktop_msg::StoreNetworkInterfaceState",
                    DesktopToTopologyServer::PushNetworkInterfaceState {
                        network_interface_state,
                    },
                    self.desktop2server_store_msgs_stat
                )
                .await
            }
        }
    }

    /**
     * Because the underlying SplitSink<...> writer doesn't support clone, we have to
     * spawn off a task to wrap it and use standard tokio::sync::mpsc::channel's to write to
     * it.  Don't get confused about the tx to this TopologyServerConnection vs. the tx from the
     * TopologyServerConnection to the actual remote TopologyServer
     */
    async fn spawn_ws_writer(
        &self,
        mut writer: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    ) -> Sender<PerfMsgCheck<DesktopToTopologyServer>> {
        // give the writer a private copy of the stats so it can update them
        // recall that the stats all have their own private locks so this is ok
        let desktop2server_stats_clone = self.desktop2server_msgs_stat.clone();
        let (tx, mut rx) = channel::<PerfMsgCheck<DesktopToTopologyServer>>(self.buffer_size);
        let url = self.url.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let msg = msg.perf_check_get("TopologyServerConnection::spawn_ws_writer");
                let outgoing_msg = if matches!(msg, DesktopToTopologyServer::Ping) {
                    Message::Ping(Vec::new())
                } else {
                    Message::Text(serde_json::to_string(&msg).unwrap())
                };
                // count the number and size of messages sent to the topology server
                desktop2server_stats_clone.add_value(outgoing_msg.len() as u64);
                if let Err(e) = writer.send(outgoing_msg).await {
                    warn!("Tried to send to the TopologyServer {}, but got {}", url, e);
                    break;
                }
            }
            info!(
                "TopologyServer: ws_writer exiting cleanly (happens on reconnect/network change)"
            );
        });
        tx
    }

    async fn handle_topology_hello(&mut self, client_ip: std::net::IpAddr, user_agent: String) {
        if self.server_hello.is_some() {
            debug!("Got duplicate!? Hello message for TopologyServer!? Ok on reconnect");
        }
        for tx in &self.waiting_for_hello {
            send_or_log_async!(tx, "handle_topology_hello", (client_ip, user_agent.clone())).await;
        }
        self.server_hello = Some((client_ip, user_agent));
        self.waiting_for_hello.clear();
    }

    async fn handle_infer_congestion(
        &mut self,
        ws_tx: &Sender<PerfMsgCheck<DesktopToTopologyServer>>,
        connection_measurements: Vec<ConnectionMeasurements>,
        reply_tx: Sender<PerfMsgCheck<CongestionSummary>>,
    ) {
        self.waiting_for_congestion_summary.push(reply_tx);
        send_or_log_async!(
            ws_tx,
            "handle_infer_congestion",
            DesktopToTopologyServer::InferCongestion {
                connection_measurements
            }
        )
        .await;
    }

    /**
     * Got a InferCongestionReply from server, send it to anyone waiting for it.
     */

    async fn handle_infer_congestion_reply(&mut self, congestion_summary: CongestionSummary) {
        if self.waiting_for_congestion_summary.len() == 1 {
            // common case, save some memcopies
            let reply_tx = self.waiting_for_congestion_summary.pop().unwrap();
            send_or_log_async!(
                reply_tx,
                "handle_infer_congestion_reply()",
                congestion_summary
            )
            .await;
        } else if self.waiting_for_congestion_summary.is_empty() {
            warn!("Weird: Got a InferCongestionReply from server, but no one was waiting for it?");
        } else {
            // hopefully less common case, use clone()
            for reply_tx in &self.waiting_for_congestion_summary {
                send_or_log_async!(
                    reply_tx,
                    "handle_infer_congestion_reply()",
                    congestion_summary.clone()
                )
                .await;
            }
            self.waiting_for_congestion_summary.clear();
        }
    }

    fn spawn_periodic_write_counters_to_remote(
        &self,
        ws_tx: WeakSender<PerfMsgCheck<DesktopToTopologyServer>>,
        interval: tokio::time::Duration,
    ) {
        let super_counter_registery = self.super_counters_registries.clone();
        tokio::spawn(async move {
            loop {
                // use 'tokio::time::sleep' instead of 'tokio::time::interval'
                // because we don't want multiple to run in parallel if this backsup
                tokio::time::sleep(interval).await;
                let mut counters = indexmap::IndexMap::<String, u64>::new();
                {
                    let lock = super_counter_registery.lock().unwrap();
                    lock.update_time();
                    lock.append_counters(&mut counters);
                }
                // need to (temporarily) upgrade to a full Sender so we can actually send.
                if let Some(ws_tx) = ws_tx.upgrade() {
                    // don't use send_or_log!() macro here b/c we want to break on error
                    if let Err(e) = ws_tx
                        .send(PerfMsgCheck::new(DesktopToTopologyServer::PushCounters {
                            timestamp: Utc::now(),
                            counters,
                            os: std::env::consts::OS.to_string(),
                            version: get_git_hash_version(),
                            client_id: Default::default(),
                        }))
                        .await
                    {
                        info!( "Error in sending periodic counters to topology server: exiting periodic counter writer task {}", e);
                        break;
                    }
                } else {
                    debug!("Webscoket to topology server apparently closed. Exiting periodic counter writer task");
                    break;
                }
            }
        });
    }
}

#[cfg(test)]
mod test {
    use axum::{
        extract::ws::{
            // Message as AxumMessage,
            WebSocket,
            WebSocketUpgrade,
        },
        routing::get,
        Router,
    };
    use common_wasm::timeseries_stats::SuperRegistry;
    use std::future::ready;

    use super::*;
    use std::{str::FromStr, time::Instant};

    /**
     * Uses most of the code but not the websocket marshalling/unmarshalling
     *
     * That seems harder to test... let's see if it's a problem
     */
    #[tokio::test]
    async fn test_get_my_ip() {
        let (rpc_tx, rpc_rx) = channel(10);
        let (storage_tx, storage_rx) = channel(10);
        let test_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let test_user_agent = "JoMama".to_string();
        let super_counters_registry = SuperRegistry::new(Instant::now()).registries(); // for testing
        let mut topology = TopologyServerConnection::new(
            "fake URL".to_string(),
            rpc_tx.clone(),
            rpc_rx,
            storage_tx,
            storage_rx,
            10,
            Duration::from_secs(10),
            Uuid::default(),
            super_counters_registry,
            ExportedStatRegistry::new("topo_server_conn", Instant::now()),
        );
        let (ws_tx, _ws_rx) = channel(10);
        // request the IP before it's ready
        let (reply_tx, mut reply_rx) = channel(10);
        topology
            .handle_desktop_rpc_msg(
                PerfMsgCheck::new(TopologyRpcMessage::GetMyIpAndUserAgent { reply_tx }),
                &ws_tx,
            )
            .await;
        assert!(reply_rx.try_recv().is_err()); // make sure we didn't get a reply
                                               // now send in the reply
        topology
            .handle_ws_msg(Message::Text(
                serde_json::to_string(&TopologyServerToDesktop::Hello {
                    client_ip: test_ip,
                    user_agent: test_user_agent.clone(),
                })
                .unwrap(),
            ))
            .await;
        // now we should have an answer
        // !!! Why can't this find .skip_perf_check()!?
        // let (ip, user_agent) = reply_rx.try_recv().unwrap().skip_perf_check();
        let (ip, user_agent) = reply_rx.try_recv().unwrap().perf_check_get("test");
        assert_eq!(ip, test_ip);
        assert_eq!(user_agent, test_user_agent);

        // request the IP after it's cached
        let (reply_tx, mut reply_rx) = channel(10);
        topology
            .handle_desktop_rpc_msg(
                PerfMsgCheck::new(TopologyRpcMessage::GetMyIpAndUserAgent { reply_tx }),
                &ws_tx,
            )
            .await;
        assert!(reply_rx.try_recv().is_ok()); // make sure we now DO get a reply right away

        // this passed on first try!! add a panic() to make sure the test ran!?
        // panic!("If at first you do succeed, try not to look surprised");
    }

    #[tokio::test]
    async fn test_websocket_timeout_reconnect_nice_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ephemeral_port = listener.local_addr().unwrap().port();
        println!("listening on {}", ephemeral_port);
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/test",
                    get(|ws: WebSocketUpgrade| {
                        ready(ws.on_upgrade(test_ws_handler_nice_close_on_ping))
                    }),
                ),
            )
            .await
            .unwrap();
        });
        println!("listening on {}", ephemeral_port);
        let url = format!("ws://127.0.0.1:{}/test", ephemeral_port);
        let (rpc_tx, rpc_rx) = channel::<PerfMsgCheck<TopologyRpcMessage>>(10);
        let (storage_tx, storage_rx) = channel(10);
        let super_counters_registry = SuperRegistry::new(Instant::now()).registries(); // for testing
        let mut topology_client = TopologyServerConnection::new(
            url,
            rpc_tx,
            rpc_rx,
            storage_tx,
            storage_rx,
            1024,
            Duration::from_millis(10),
            Uuid::default(),
            super_counters_registry,
            ExportedStatRegistry::new("topo_server_conn", Instant::now()),
        );
        // make sure we timeout in under 2 seconds
        tokio::time::timeout(
            Duration::from_secs(2),
            topology_client.rx_loop_one_connection(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_websocket_timeout_reconnect_silent_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ephemeral_port = listener.local_addr().unwrap().port();
        println!("listening on {}", ephemeral_port);
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/test",
                    get(|ws: WebSocketUpgrade| ready(ws.on_upgrade(test_ws_handler_silent_close))),
                ),
            )
            .await
            .unwrap();
        });
        println!("listening on {}", ephemeral_port);
        let url = format!("ws://127.0.0.1:{}/test", ephemeral_port);
        let (rpc_tx, rpc_rx) = channel::<PerfMsgCheck<TopologyRpcMessage>>(10);
        let (storage_tx, storage_rx) = channel(10);
        let super_counters_registry = SuperRegistry::new(Instant::now()).registries(); // for testing
        let mut topology_client = TopologyServerConnection::new(
            url,
            rpc_tx,
            rpc_rx,
            storage_tx,
            storage_rx,
            1024,
            Duration::from_millis(10),
            Uuid::default(),
            super_counters_registry,
            ExportedStatRegistry::new("topo_server_conn", Instant::now()),
        );
        // make sure we timeout in under 2 seconds
        tokio::time::timeout(
            Duration::from_secs(2),
            topology_client.rx_loop_one_connection(),
        )
        .await
        .unwrap();
    }

    /* SO close to working... just give up and copy the code...
    async fn spawn_test_websocket_server<C, Fut>(handler: C) -> u16
    where
        C: FnOnce(WebSocket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ephemeral_port = listener.local_addr().unwrap().port();
        println!("listening on {}", ephemeral_port);
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/test",
                    get(|ws: WebSocketUpgrade| {
                        ready(ws.on_upgrade(test_ws_handler_nice_close_on_ping))
                    }),
                ),
            )
            .await
            .unwrap();
        });
        ephemeral_port
    }
    */

    // Used for testing; don't send Pong's  if we get a Ping
    async fn test_ws_handler_nice_close_on_ping(mut socket: WebSocket) {
        while let Some(Ok(msg)) = socket.recv().await {
            use axum::extract::ws::Message::*;
            match msg {
                Ping(_payload) => {
                    // NOTE: if we don't handle explicitly pings like this, the underlying library STILL sends
                    // PONG messages.. which is annoying and complicates testing...
                    info!("Got ping request, closing...");
                    break;
                }
                _msg => println!("Ignoring msg {:?}", _msg),
            }
        }
        socket.close().await.unwrap();
    }
    // Used for testing; do send Pong's  if we get a Ping
    async fn test_ws_handler_silent_close(mut socket: WebSocket) {
        while let Some(Ok(msg)) = socket.recv().await {
            use axum::extract::ws::Message::*;
            match msg {
                Ping(_payload) => {
                    // NOTE: if we don't handle explicitly pings like this, the underlying library STILL sends
                    // PONG messages.. which is annoying and complicates testing...
                    info!("Got ping request, closing...");
                    break;
                }
                _msg => println!("Ignoring msg {:?}", _msg),
            }
        }
        // silently close
    }
}
