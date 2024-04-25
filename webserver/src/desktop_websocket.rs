use std::{net::SocketAddr, sync::Arc};

use axum::extract::ws::{self, WebSocket};

use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use gui_types::OrganizationId;
use libconntrack::{
    send_or_log,
    topology_client::{TopologyRpcMessage, TopologyRpcSender},
    try_send_or_log,
    utils::PerfMsgCheck,
};
use libconntrack_wasm::topology_server_messages::{
    DesktopLogLevel, DesktopToTopologyServer, TopologyServerToDesktop,
};
use log::{debug, info, warn};
use tokio::sync::mpsc::{channel, Sender};
use uuid::Uuid;

use crate::{
    context::Context,
    devices::DeviceInfo,
    organizations::NETDEBUG_EMPLOYEE_ORG_ID,
    remotedb_client::{
        RemoteDBClient, RemoteDBClientMessages, RemoteDBClientSender, StorageSourceType,
    },
    secrets_db::Secrets,
    users::NetDebugUser,
};

// TODO: add a way for the device to communicate it's organization to the server
// with the appropriate auth
// For now, check the DB if the device already exists if it does, return the appropriate
// org_id, otherwise default to NETDEBUG_EMPLOYEES
async fn get_organization_id_for_device(
    secrets: &Secrets,
    device_uuid: Uuid,
) -> Option<OrganizationId> {
    let client = match RemoteDBClient::make_read_only_client(secrets).await {
        Ok(client) => Arc::new(client),
        Err(e) => {
            warn!(
                "Failed to get DB connection. Closing Websocket connection. {}",
                e
            );
            return None;
        }
    };
    match DeviceInfo::from_uuid(
        device_uuid,
        &NetDebugUser::make_internal_superuser(),
        client,
    )
    .await
    {
        Ok(Some(device)) => Some(device.organization_id),
        Ok(None) => {
            info!(
                "Websocket connection from device not in DB. Using netdebug org_id. device: {}",
                device_uuid
            );
            Some(NETDEBUG_EMPLOYEE_ORG_ID)
        }
        Err(e) => {
            warn!("Failed to query DB for device {}: {}", device_uuid, e);
            None
        }
    }
}

const DEFAULT_CHANNEL_BUFFER_SIZE: usize = 4096;
pub async fn handle_desktop_websocket(
    websocket: WebSocket,
    context: Context,
    device_uuid: Uuid,
    user_agent: String,
    addr: SocketAddr,
) {
    info!(
        "DesktopWebsocket connection from {} :: uuid = {}",
        addr, device_uuid
    );
    // clone secrets so we don't hold the lock acress the await from
    // make_read_only_client
    let secrets = context.read().await.secrets.clone();
    let organization_id = get_organization_id_for_device(&secrets, device_uuid).await;
    if organization_id.is_none() {
        // no need to log here, `get_organization_id_for_device()` takes care of that
        // for us
        return;
    }
    let organization_id = organization_id.unwrap();

    let (ws_tx, mut ws_rx) = websocket.split();
    let ws_tx = spawn_websocket_writer(ws_tx, DEFAULT_CHANNEL_BUFFER_SIZE, addr.to_string()).await;
    let (topology_server, remotedb_client) = {
        let lock = context.read().await;
        (lock.topology_server.clone(), lock.remotedb_client.clone())
    };
    if let Some(remotedb_client) = remotedb_client.clone() {
        log_device_connection(
            remotedb_client,
            context.clone(),
            device_uuid,
            organization_id,
            user_agent.clone(),
            addr,
        )
        .await;
    }

    /*
     * Unwrap the layering here:
     * 1. WebSockets has it's own Message Type
     * 2. If it's text, unwrap the json
     * 3. If it's json, convert to a DesktopToTopology message
     */
    while let Some(ws_msg_result) = ws_rx.next().await {
        match ws_msg_result {
            Ok(ws_msg) => match ws_msg {
                ws::Message::Text(text) => match serde_json::from_str(&text) {
                    Ok(desktop_to_topo_msg) => {
                        handle_desktop_message(
                            &topology_server,
                            &remotedb_client,
                            desktop_to_topo_msg,
                            &ws_tx,
                            &user_agent,
                            &addr,
                            device_uuid,
                            organization_id,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!("Cannot parse text message from websocket. Error: {}", e);
                        break;
                    }
                },
                ws::Message::Binary(_) => {
                    warn!("Got non-text message from websocket!? {:?}", ws_msg);
                }
                ws::Message::Ping(_) | ws::Message::Pong(_) | ws::Message::Close(_) => {
                    // ignore
                }
            },
            Err(e) => warn!("Error processing connection {} :: {}", e, addr),
        }
    }
    info!("DesktopWebsocket connection from {} closing", addr);
}

/// Tell the remotedb_client about this connection so it can log it and create the device entry if necessary
///
/// TODO: include auth components and return an error if the auth components don't check out
async fn log_device_connection(
    remotedb_client: RemoteDBClientSender,
    _context: Context,
    device_uuid: Uuid,
    organization_id: OrganizationId,
    user_agent: String,
    addr: SocketAddr,
) {
    try_send_or_log!(
        remotedb_client,
        "handle_register_device",
        RemoteDBClientMessages::LogDeviceConnect {
            device_uuid,
            organization: organization_id,
            description: user_agent,
            addr
        }
    );
}

// yes, it's a lot of arguments. But at least they all have a different type
#[allow(clippy::too_many_arguments)]
async fn handle_desktop_message(
    topology_server: &TopologyRpcSender,
    remotedb_client: &Option<RemoteDBClientSender>,
    msg: DesktopToTopologyServer,
    ws_tx: &Sender<TopologyServerToDesktop>,
    user_agent: &str,
    addr: &SocketAddr,
    device_uuid: Uuid,
    organization_id: OrganizationId,
) {
    use DesktopToTopologyServer::*;
    match msg {
        Hello => handle_hello(ws_tx, user_agent, addr).await,
        StoreConnectionMeasurement {
            connection_measurements: connection_measurement,
            // TODO: put client Info (OS, version, etc.) in the message
        } => handle_store_measurements(connection_measurement, device_uuid, organization_id, remotedb_client).await,
        InferCongestion {
            connection_measurements,
        } => handle_infer_congestion(ws_tx, connection_measurements, topology_server).await,
        PushCounters {
            timestamp,
            counters,
            os,
            version,
        } => handle_push_counters(remotedb_client, timestamp, counters, device_uuid, os, version).await,
        PushLog {
            timestamp,
            msg,
            level,
            os,
            version,
            .. // FIXME: use `scope` field!!
        } => handle_push_log(remotedb_client, timestamp, msg, level, os, version, device_uuid).await,
        Ping => {
            warn!("Received a DesktopToTopologyServer::Ping as JSON which should never be sent over the wire");
        }
        PushNetworkInterfaceState { network_interface_state } => {
            try_send_or_log_helper(remotedb_client,
                "handle_push_network_interface_state", 
                RemoteDBClientMessages::StoreNetworkInterfaceState { network_interface_state, device_uuid }
            ).await;
        }
        PushGatewayPingData { ping_data } => {
            try_send_or_log_helper(remotedb_client,
                "handle_push_gateway_ping_data",
                RemoteDBClientMessages::StoreGatewayPingData { ping_data }
            ).await;
        }
        PushDnsEntries { dns_entries } => {
            try_send_or_log_helper(remotedb_client,
                "handle_push_dns_entries",
                RemoteDBClientMessages::StoreDnsEntries { dns_entries, device_uuid }
            ).await;
        }

    }
}

async fn try_send_or_log_helper(
    remotedb_client: &Option<RemoteDBClientSender>,
    what: &str,
    msg: RemoteDBClientMessages,
) {
    if let Some(remotedb_client) = remotedb_client {
        try_send_or_log!(remotedb_client, what, msg);
    } else {
        debug!("Storage not configured:: not storing: {:?}", msg);
    }
}

async fn handle_push_log(
    remotedb_client: &Option<RemoteDBClientSender>,
    time: chrono::DateTime<chrono::Utc>,
    msg: String,
    level: DesktopLogLevel,
    os: String,
    version: String,
    device_uuid: Uuid,
) {
    if let Some(remotedb_client) = remotedb_client {
        try_send_or_log!(
            remotedb_client,
            "handle_push_log",
            RemoteDBClientMessages::StoreLog {
                msg,
                level,
                os,
                version,
                device_uuid,
                time,
            }
        );
    } else {
        debug!(
            "Storage not configured:: not storing log from {} :: {:?} :: {} :: {} :: {} :: {} :: ",
            device_uuid, level, time, os, version, msg
        );
    }
}

async fn handle_push_counters(
    remotedb_client: &Option<RemoteDBClientSender>,
    timestamp: chrono::DateTime<chrono::Utc>,
    counters: indexmap::IndexMap<String, u64>,
    device_uuid: Uuid,
    os: String,
    version: String,
) {
    if let Some(remotedb_client) = remotedb_client {
        debug!(
            "Got {} counters from {}  at {} - OS {} version {} : TODO - store them!",
            counters.len(),
            device_uuid,
            timestamp,
            os,
            version
        );
        try_send_or_log!(
            remotedb_client,
            "handle_push_counters",
            RemoteDBClientMessages::StoreCounters {
                counters,
                device_uuid,
                time: timestamp,
                os,
                version
            }
        )
    } else {
        debug!(
            "Got {} counters from {}. NOT STORING THEM -- NO REMOTE DB CONFIGURED",
            counters.len(),
            device_uuid,
        );
    }
}

async fn handle_infer_congestion(
    ws_tx: &Sender<TopologyServerToDesktop>,
    connection_measurements: Vec<libconntrack_wasm::ConnectionMeasurements>,
    topology_server: &Sender<PerfMsgCheck<TopologyRpcMessage>>,
) {
    // spawn this request off to a dedicated task as it might take a while to process
    // and the client is completely async
    let topology_server = topology_server.clone();
    let ws_tx = ws_tx.clone();
    tokio::spawn(async move {
        let (reply_tx, mut reply_rx) = channel(1);
        send_or_log!(
            topology_server,
            "handle_infer_congestion",
            TopologyRpcMessage::InferCongestion {
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
 * Just forward on to the RemoteDBClient for storage
 */
async fn handle_store_measurements(
    connection_measurements: Box<libconntrack_wasm::ConnectionMeasurements>,
    device_uuid: Uuid,
    organization_id: OrganizationId,
    remotedb_client: &Option<RemoteDBClientSender>,
) {
    if let Some(remotedb_client) = remotedb_client {
        try_send_or_log!(
            remotedb_client,
            "handle_store",
            RemoteDBClientMessages::StoreConnectionMeasurements {
                connection_measurements,
                device_uuid,
                organization_id,
                source_type: StorageSourceType::Desktop,
            }
        )
    } else {
        debug!(
            "Would have stored connection_measurement, but no remotedb_client specified: {:?}",
            connection_measurements
        );
    }
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
    mut ws_tx: SplitSink<WebSocket, ws::Message>,
    channel_buffer_size: usize,
    addr_str: String,
) -> Sender<TopologyServerToDesktop> {
    let (tx, mut rx) = channel::<
        libconntrack_wasm::topology_server_messages::TopologyServerToDesktop,
    >(channel_buffer_size);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = ws_tx
                .send(ws::Message::Text(serde_json::to_string(&msg).unwrap()))
                .await
            {
                warn!("Error sending on websocket {} : {}", &addr_str, e);
            }
        }
    });

    tx
}
