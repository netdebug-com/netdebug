use std::net::IpAddr;
use std::time::Duration;

use crate::send_or_log_async;
use crate::utils::PerfMsgCheck;
use common_wasm::timeseries_stats::{ExportedStatRegistry, StatHandle, StatType, Units};
use futures::sink::SinkExt;
use futures_util::stream::SplitSink;
use futures_util::StreamExt;
use libconntrack_wasm::topology_server_messages::{
    CongestionSummary, DesktopToTopologyServer, TopologyServerToDesktop,
};
use libconntrack_wasm::ConnectionMeasurements;
use log::{info, warn};
// use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

#[allow(dead_code)] // will fix in next PR
#[derive(Clone, Debug)]
pub enum TopologyServerMessage {
    GetMyIpAndUserAgent {
        reply_tx: Sender<PerfMsgCheck<(IpAddr, String)>>,
    },
    StoreConnectionMeasurements {
        connection_measurements: Box<ConnectionMeasurements>,
    },
    InferCongestion {
        connection_measurements: Vec<ConnectionMeasurements>,
        reply_tx: Sender<PerfMsgCheck<CongestionSummary>>,
    },
}

pub type TopologyServerSender = Sender<PerfMsgCheck<TopologyServerMessage>>;
pub type TopologyServerReceiver = Receiver<PerfMsgCheck<TopologyServerMessage>>;

/// A local agent to manage all of the state around talking to the topology server
const DEFAULT_FIRST_RETRY_TIME_MS: u64 = 100;
pub struct TopologyServerConnection {
    /// WebSocket url to topology server, e.g., ws://localhost:3030
    url: String,
    /// A copy of the tx queue to send to us, in case others need it
    tx: TopologyServerSender,
    rx: TopologyServerReceiver,
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
    retry_stat: StatHandle,
    desktop2server_msgs_stat: StatHandle,
    desktop2server_store_msgs_stat: StatHandle,
    server2desktop_msgs_stat: StatHandle,
}

impl TopologyServerConnection {
    pub fn new(
        url: String,
        tx: TopologyServerSender,
        rx: Receiver<PerfMsgCheck<TopologyServerMessage>>,
        buffer_size: usize,
        max_retry_time: Duration,
        mut stats_registry: ExportedStatRegistry,
    ) -> TopologyServerConnection {
        TopologyServerConnection {
            url,
            tx,
            rx,
            buffer_size,
            retry_time: Duration::from_millis(DEFAULT_FIRST_RETRY_TIME_MS),
            max_retry_time,
            server_hello: None,
            waiting_for_hello: Vec::new(),
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
                Units::None,
                vec![StatType::SUM, StatType::RATE],
            ),
            desktop2server_store_msgs_stat: stats_registry.add_stat(
                "desktop2server_store_msgs",
                Units::None,
                vec![StatType::SUM, StatType::COUNT, StatType::RATE],
            ),
        }
    }

    pub fn spawn(
        url: String,
        buffer_size: usize,
        max_retry_time: Duration,
        stats_registry: ExportedStatRegistry,
    ) -> Sender<PerfMsgCheck<TopologyServerMessage>> {
        let (tx, rx) = channel(buffer_size);
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let topology_server = TopologyServerConnection::new(
                url,
                tx,
                rx,
                buffer_size,
                max_retry_time,
                stats_registry,
            );
            topology_server.rx_loop().await;
        });
        tx_clone
    }

    async fn rx_loop(mut self) {
        // connect ala https://github.com/snapview/tokio-tungstenite/blob/master/examples/client.rs

        loop {
            // Intentionally panic here if we got a bad URL
            let url =
                url::Url::parse(&self.url).unwrap_or_else(|_| panic!("Bad url! {}", &self.url));
            // need to generate a custom request because we need to set the User-Agent for our webserver
            let req = Request::builder()
                .method("GET")
                .header("Host", url.authority())
                .header("User-Agent", "NetDebug Desktop version x.y.z")
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
                    continue;
                }
            };
            let ws_tx = self.spawn_ws_writer(ws_write).await;
            // send an initial hello to start the connection
            if let Err(e) = ws_tx
                .send(PerfMsgCheck::new(DesktopToTopologyServer::Hello))
                .await
            {
                warn!("Failed to send hello to TopologyServer: {}", e);
                continue;
            }
            // now wait for internal users to send traffic to us as well as the topology server to send us messages
            loop {
                tokio::select! {
                    ws_msg = ws_read.next() => {
                        match ws_msg {
                            Some(Ok(ws_msg)) => self.handle_ws_msg(ws_msg).await,
                            Some(Err(e)) => {
                                warn!("Got an error from the TopologyServer: reconnecting {}", e);
                                break;
                            },
                            None => {
                                warn!("Got None back from TopologyServer (connection dead?): reconnecting");
                                break;
                            }
                        }
                    }
                    desktop_msg = self.rx.recv() => match desktop_msg {
                        Some(desktop_msg) => self.handle_desktop_msg(desktop_msg, &ws_tx).await,
                        None => warn!("Got None back from TopologyServerConnection rx!?"),
                    }
                }
            }
        }
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
        }
    }

    #[allow(unused)] // for now, we'll eventually need this
    pub fn get_tx(&self) -> TopologyServerSender {
        self.tx.clone()
    }

    pub async fn handle_desktop_msg(
        &mut self,
        desktop_msg: PerfMsgCheck<TopologyServerMessage>,
        ws_tx: &Sender<PerfMsgCheck<DesktopToTopologyServer>>,
    ) {
        self.desktop2server_msgs_stat.bump();
        use TopologyServerMessage::*;
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
            StoreConnectionMeasurements {
                connection_measurements,
            } => {
                send_or_log_async!(
                    ws_tx,
                    "handle_desktop_msg::StoreConnectionMeasurement",
                    DesktopToTopologyServer::StoreConnectionMeasurement {
                        connection_measurements
                    },
                    self.desktop2server_store_msgs_stat
                )
                .await
            }
            InferCongestion {
                connection_measurements: _,
                reply_tx: _,
            } => todo!(),
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
        let (tx, mut rx) = channel::<PerfMsgCheck<DesktopToTopologyServer>>(self.buffer_size);
        let url = self.url.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let msg = msg.perf_check_get("TopologyServerClient::spawn_ws_writer");
                if let Err(e) = writer
                    .send(Message::Text(serde_json::to_string(&msg).unwrap()))
                    .await
                {
                    warn!("Tried to send to the TopologyServer {}, but got {}", url, e);
                }
            }
            info!("TopologyServer: ws_writer exiting cleanly (!? should never happen?)");
        });
        tx
    }

    async fn handle_topology_hello(&mut self, client_ip: std::net::IpAddr, user_agent: String) {
        if self.server_hello.is_some() {
            warn!("Got duplicate!? Hello message for TopologyServer!? Maybe reconnect");
        }
        for tx in &self.waiting_for_hello {
            send_or_log_async!(tx, "handle_topology_hello", (client_ip, user_agent.clone())).await;
        }
        self.server_hello = Some((client_ip, user_agent));
        self.waiting_for_hello.clear();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{str::FromStr, time::Instant};

    /**
     * Uses most of the code but not the websocket marshalling/unmarshalling
     *
     * That seems harder to test... let's see if it's a problem
     */
    #[tokio::test]
    async fn test_get_my_ip() {
        let (tx, rx) = channel(10);
        let test_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let test_user_agent = "JoMama".to_string();
        let mut topology = TopologyServerConnection::new(
            "fake URL".to_string(),
            tx.clone(),
            rx,
            10,
            Duration::from_secs(10),
            ExportedStatRegistry::new("topo_server_conn", Instant::now()),
        );
        let (ws_tx, _ws_rx) = channel(10);
        // request the IP before it's ready
        let (reply_tx, mut reply_rx) = channel(10);
        topology
            .handle_desktop_msg(
                PerfMsgCheck::new(TopologyServerMessage::GetMyIpAndUserAgent { reply_tx }),
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
            .handle_desktop_msg(
                PerfMsgCheck::new(TopologyServerMessage::GetMyIpAndUserAgent { reply_tx }),
                &ws_tx,
            )
            .await;
        assert!(reply_rx.try_recv().is_ok()); // make sure we now DO get a reply right away

        // this passed on first try!! add a panic() to make sure the test ran!?
        // panic!("If at first you do succeed, try not to look surprised");
    }
}
