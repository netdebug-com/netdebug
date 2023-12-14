use std::{net::SocketAddr, path::PathBuf};

use chrono::{DateTime, Utc};
use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use influxdb::{Client, InfluxDbWriteable};
use libconntrack::{
    send_or_log_async,
    topology_client::{TopologyServerMessage, TopologyServerSender},
    utils::PerfMsgCheck,
};
use libconntrack_wasm::topology_server_messages::{
    DesktopToTopologyServer, TopologyServerToDesktop,
};
#[cfg(not(test))]
use log::{debug, info, warn};
use tokio::sync::mpsc::{channel, Sender};
use warp::filters::ws::{self, Message, WebSocket};

use crate::context::Context;
#[cfg(test)]
use std::{println as debug, println as info, println as warn}; // Workaround to use prinltn! for logs.

const DEFAULT_CHANNEL_BUFFER_SIZE: usize = 4096;
pub async fn handle_desktop_websocket(
    context: Context,
    user_agent: String,
    websocket: warp::ws::WebSocket,
    addr: Option<SocketAddr>,
) {
    let addr = addr.expect("Missing connection!?");
    info!("DesktopWebsocket connection from {}", addr);
    let (ws_tx, mut ws_rx) = websocket.split();
    let ws_tx = spawn_websocket_writer(ws_tx, DEFAULT_CHANNEL_BUFFER_SIZE, addr.to_string()).await;
    let topology_server = context.read().await.topology_server.clone();
    let timeseriesdb_client = make_timeseriesdb_client(&context);
    /*
     * Unwrap the layering here:
     * 1. WebSockets has it's own Message Type
     * 2. If it's text, unwrap the json
     * 3. If it's json, convert to a DesktopToTopology message
     */
    while let Some(ws_msg_result) = ws_rx.next().await {
        match ws_msg_result {
            Ok(ws_msg) => {
                let json_msg = match ws_msg.to_str() {
                    Ok(text) => text,
                    Err(_) => {
                        warn!("Got non-text message from websocket!? {:?}", ws_msg);
                        break;
                    }
                };
                match serde_json::from_str(json_msg) {
                    Ok(msg) => {
                        handle_desktop_message(
                            &topology_server,
                            msg,
                            &ws_tx,
                            &user_agent,
                            &addr,
                            &timeseriesdb_client,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!("Failed to parse json message {}", e);
                    }
                }
            }
            Err(e) => warn!("Error processing connection {} :: {}", e, addr),
        }
    }
    info!("DesktopWebsocket connection from {} closing", addr);
}

fn make_timeseriesdb_client(_context: &Context) -> Client {
    // TODO: do we want to make this a cmdline arg?  seems not worth it
    // adding context: Context so we can un-hardcode anything we want here..
    const TIMESERIESDB_URL: &str = "https://us-east-1-1.aws.cloud2.influxdata.com";
    const API_TOKEN_FILE: &str = ".influxdb_api_token";
    const TIMESERIESDB_NAME: &str = "desktop-counters";
    let client = Client::new(TIMESERIESDB_URL, TIMESERIESDB_NAME);
    // unwrap is ok, b/c we're testing it
    #[allow(deprecated)] // probably fine if this breaks on windows
    let mut api_token_file = std::env::home_dir().unwrap_or(PathBuf::from("."));
    api_token_file.push(API_TOKEN_FILE);
    // Can create new/get existing auth tokens from
    // https://us-east-1-1.aws.cloud2.influxdata.com/orgs/bfbb1d8b5764843f/load-data/tokens
    let token = std::fs::read_to_string(&api_token_file).unwrap_or_else(|e| {
        panic!(
            "Critical auth token {} missing (CWD={}) ! panic!  {} ",
            api_token_file.display(),
            std::env::current_dir().unwrap().display(),
            e
        )
    });
    client.with_token(token)
}

async fn handle_desktop_message(
    topology_server: &TopologyServerSender,
    msg: DesktopToTopologyServer,
    ws_tx: &Sender<TopologyServerToDesktop>,
    user_agent: &str,
    addr: &SocketAddr,
    timeseriesdb_client: &Client,
) {
    use DesktopToTopologyServer::*;
    match msg {
        Hello => handle_hello(ws_tx, user_agent, addr).await,
        StoreConnectionMeasurement {
            connection_measurements: connection_measurement,
        } => handle_store(connection_measurement, topology_server).await,
        InferCongestion {
            connection_measurements,
        } => handle_infer_congestion(ws_tx, connection_measurements, topology_server).await,
        PushCounters {
            timestamp,
            counters,
        } => handle_push_counters(timestamp, counters, addr, timeseriesdb_client, "counters").await,
    }
}

#[derive(InfluxDbWriteable)]
struct TimeSeriesDesktopCounter {
    time: DateTime<Utc>,
    source: String,
    counter: String,
    value: u64,
}

async fn handle_push_counters(
    timestamp: DateTime<Utc>,
    counters: indexmap::IndexMap<String, u64>,
    addr: &SocketAddr,
    timeseriesdb_client: &Client,
    measurement_name: &str,
) {
    debug!(
        "Got {} counters from {}  at {} - storing to cloud timeseries db",
        counters.len(),
        addr,
        timestamp
    );
    let queries = &counters
        .iter()
        .map(|(c, v)| {
            TimeSeriesDesktopCounter {
                time: timestamp,
                source: addr.to_string(), // TODO: stop logging client IP and log ephemeral ID instead
                counter: c.clone(),
                value: *v,
            }
            .into_query(measurement_name)
        })
        .collect::<Vec<influxdb::WriteQuery>>();
    match timeseriesdb_client.query(queries).await {
        Ok(out) => warn!("Success writing to timeseriesdb_client {}", out),
        Err(e) => warn!("Error writing to timeseriesdb_client: {}", e),
    }
}

async fn handle_infer_congestion(
    ws_tx: &Sender<TopologyServerToDesktop>,
    connection_measurements: Vec<libconntrack_wasm::ConnectionMeasurements>,
    topology_server: &Sender<PerfMsgCheck<TopologyServerMessage>>,
) {
    // spawn this request off to a dedicated task as it might take a while to process
    // and the client is completely async
    let topology_server = topology_server.clone();
    let ws_tx = ws_tx.clone();
    tokio::spawn(async move {
        let (reply_tx, mut reply_rx) = channel(1);
        send_or_log_async!(
            topology_server,
            "handle_infer_congestion",
            TopologyServerMessage::InferCongestion {
                connection_measurements,
                reply_tx
            }
        )
        .await;
        let congestion_summary = match reply_rx.recv().await {
            Some(c) => c.perf_check_get("handle_infer_congstion"),
            None => {
                warn!("TopologyServer returned None!?");
                return;
            }
        };
        if let Err(e) = ws_tx
            .send(TopologyServerToDesktop::InferCongestionReply { congestion_summary })
            .await
        {
            warn!("Tried to write to websocket to desktop but got: {}", e);
        }
    });
}

/**
 * Just forward on to the TopologyServer for storage
 */
async fn handle_store(
    connection_measurements: Box<libconntrack_wasm::ConnectionMeasurements>,
    topology_server: &TopologyServerSender,
) {
    send_or_log_async!(
        topology_server,
        "handle_store",
        TopologyServerMessage::StoreConnectionMeasurements {
            connection_measurements
        }
    )
    .await
}

async fn handle_hello(
    ws_tx: &Sender<TopologyServerToDesktop>,
    user_agent: &str,
    addr: &SocketAddr,
) {
    info!("Handling HELLO message from {:?}", addr);
    if let Err(e) = ws_tx
        .send(TopologyServerToDesktop::Hello {
            client_ip: addr.ip(),
            user_agent: user_agent.to_string(),
        })
        .await
    {
        warn!("Problem sending HELLO reply to {:?}:: {}", addr, e);
    }
}

/**
 * The ws_tx from websocket doesn't support .clone() so if we want to
 * write to it from multiple places, we need to spawn a task off to send
 * messages to it via the standard tokio::sync::mpsc::channel method.
 */
pub async fn spawn_websocket_writer(
    mut ws_tx: SplitSink<WebSocket, Message>,
    channel_buffer_size: usize,
    addr_str: String,
) -> Sender<TopologyServerToDesktop> {
    let (tx, mut rx) = channel::<
        libconntrack_wasm::topology_server_messages::TopologyServerToDesktop,
    >(channel_buffer_size);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = ws_tx
                .send(ws::Message::text(
                    serde_json::to_string(&msg).unwrap().as_str(),
                ))
                .await
            {
                warn!("Error sending on websocket {} : {}", &addr_str, e);
            }
        }
    });

    tx
}

#[cfg(test)]
mod test {
    use indexmap::indexmap;
    // use influxdb::ReadQuery;

    use super::*;
    use crate::context::test::make_test_context;

    #[tokio::test]
    async fn test_cloud_timeseries_db_store() {
        let context = make_test_context();
        let client = make_timeseriesdb_client(&context);
        let localaddr = "127.0.0.1:12345".parse().unwrap();
        let now = Utc::now();
        let test_counters = indexmap! {
            "foo".to_string() => 1,
            "bar".to_string() => 2,
            "baz".to_string() => 3,

        };
        println!("Client = {:?}", client);
        // this will push data into the cloud timeseries db!
        handle_push_counters(now, test_counters, &localaddr, &client, "test").await;
        // now read it back to make sure it got there
        // let read_query = ReadQuery::new("SELECT * FROM test where time=");
    }
}
