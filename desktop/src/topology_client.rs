use std::net::IpAddr;
use std::time::Duration;

use common_wasm::topology_server_messages::{DesktopToTopologyServer, TopologyServerToDesktop};
use futures::sink::SinkExt;
use futures_util::stream::SplitSink;
use futures_util::StreamExt;
use libconntrack::try_send_async;
use libconntrack::utils::PerfMsgCheck;
use log::warn;
// use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

#[allow(dead_code)] // will fix in next PR
#[derive(Clone, Debug)]
pub enum TopologyServerMessage {
    GetMyIpAndUserAgent {
        reply_tx: Sender<PerfMsgCheck<(IpAddr, String)>>,
    },
}

pub type TopologyServerSender = Sender<PerfMsgCheck<TopologyServerMessage>>;

const DEFAULT_FIRST_RETRY_TIME_MS: u64 = 100;
pub struct TopologyServerConnection {
    url: String,
    tx: TopologyServerSender,
    rx: Receiver<PerfMsgCheck<TopologyServerMessage>>,
    buffer_size: usize,
    retry_time: Duration,
    max_retry_time: Duration,
    server_hello: Option<(IpAddr, String)>,
    waiting_for_hello: Vec<Sender<PerfMsgCheck<(IpAddr, String)>>>,
}

impl TopologyServerConnection {
    pub fn new(
        url: String,
        tx: TopologyServerSender,
        rx: Receiver<PerfMsgCheck<TopologyServerMessage>>,
        buffer_size: usize,
        max_retry_time: Duration,
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
        }
    }

    pub fn spawn(
        url: String,
        buffer_size: usize,
        max_retry_time: Duration,
    ) -> Sender<PerfMsgCheck<TopologyServerMessage>> {
        let (tx, rx) = channel(buffer_size);
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let topology_server =
                TopologyServerConnection::new(url, tx, rx, buffer_size, max_retry_time);
            topology_server.rx_loop().await;
        });
        tx_clone
    }

    async fn rx_loop(mut self) {
        // connect ala https://github.com/snapview/tokio-tungstenite/blob/master/examples/client.rs
        loop {
            let (write, mut read) = match connect_async(&self.url).await {
                Ok((ws_stream, _)) => {
                    self.retry_time = Duration::from_millis(DEFAULT_FIRST_RETRY_TIME_MS);
                    ws_stream.split()
                }
                Err(e) => {
                    self.retry_time = std::cmp::max(self.retry_time * 2, self.max_retry_time); // capped exponential backoff
                    warn!(
                        "Failed to connect to TopologyServer {} : retrying in {:?} :: {}",
                        self.url, self.retry_time, e
                    );
                    tokio::time::sleep(self.retry_time).await;
                    continue;
                }
            };
            let ws_tx = self.spawn_ws_writer(write).await;
            // send an initial hello to start the connection
            if let Err(e) = ws_tx.send(DesktopToTopologyServer::Hello).await {
                warn!("Failed to send hello to TopologyServer: {}", e);
            }
            // now wait for internal users to send traffic to us as well as the topology server to send us messages
            loop {
                tokio::select! {
                    ws_msg = read.next() => {
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
                        Some(desktop_msg) => self.handle_desktop_msg(desktop_msg).await,
                        None => warn!("Got None back from TopologyServerConnection rx!?"),
                    }
                }
            }
        }
    }

    pub async fn handle_ws_msg(&mut self, ws_msg: Message) {
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

    pub async fn handle_desktop_msg(&mut self, desktop_msg: PerfMsgCheck<TopologyServerMessage>) {
        match desktop_msg.perf_check_get("TopologyServerConnection:: handle_desktop_msg()") {
            TopologyServerMessage::GetMyIpAndUserAgent { reply_tx } => {
                // if we have it cached, then reply right away, else queue them
                if let Some(hello) = &self.server_hello {
                    try_send_async!(reply_tx, "topology server hello", hello.clone()).await;
                } else {
                    self.waiting_for_hello.push(reply_tx.clone());
                }
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
    ) -> Sender<DesktopToTopologyServer> {
        let (tx, mut rx) = channel::<DesktopToTopologyServer>(self.buffer_size);
        while let Some(msg) = rx.recv().await {
            if let Err(e) = writer
                .send(Message::Text(serde_json::to_string(&msg).unwrap()))
                .await
            {
                warn!(
                    "Tried to send to the TopologyServer {}, but got {}",
                    self.url, e
                );
            }
        }
        tx
    }

    async fn handle_topology_hello(&mut self, client_ip: std::net::IpAddr, user_agent: String) {
        if self.server_hello.is_some() {
            warn!("Got duplicate!? Hello message for TopologyServer!? Maybe reconnect");
        }
        for tx in &self.waiting_for_hello {
            try_send_async!(
                tx,
                "handle_topology_hello",
                (client_ip.clone(), user_agent.clone())
            )
            .await;
        }
        self.server_hello = Some((client_ip, user_agent));
        self.waiting_for_hello.clear();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

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
        );
        // request the IP before it's ready
        let (reply_tx, mut reply_rx) = channel(10);
        topology
            .handle_desktop_msg(PerfMsgCheck::new(
                TopologyServerMessage::GetMyIpAndUserAgent { reply_tx },
            ))
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
            .handle_desktop_msg(PerfMsgCheck::new(
                TopologyServerMessage::GetMyIpAndUserAgent { reply_tx },
            ))
            .await;
        assert!(reply_rx.try_recv().is_ok()); // make sure we now DO get a reply right away

        // this passed on first try!! add a panic() to make sure the test ran!?
        // panic!("If at first you do succeed, try not to look surprised");
    }
}
