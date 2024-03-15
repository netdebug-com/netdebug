use libconntrack::utils::PerfMsgCheck;
use libconntrack::{send_or_log_async, topology_client::DataStorageSender};
use log::{debug, warn};
use tokio::sync::mpsc::channel;

use crate::remotedb_client::{RemoteDBClientMessages, RemoteDBClientSender, StorageSourceType};

/// Simple helper to take ConnectionMeasurement storage request from the *Webserver's* connection
/// tracker and send them to the remote DB.
pub fn spawn_webserver_connection_log_wrapper(
    remotedb_client: RemoteDBClientSender,
    storage_client_uuid: uuid::Uuid,
) -> DataStorageSender {
    // This is pretty much just a passthrough
    let (tx, mut rx) = channel(128);
    let tx_clone: DataStorageSender = tx.clone();
    tokio::spawn(async move {
        debug!("Starting webserver_connection_log_wrapper rx_loop");
        while let Some(msg) = rx.recv().await {
            let msg = msg.perf_check_get("WebserverConnectionLogWrapper--rx_loop");
            use libconntrack::topology_client::DataStorageMessage::*;
            match msg {
                // NOTE: this is triggered by measurements that the webserver itself makes, not measurements that pass through it
                StoreConnectionMeasurements {
                    connection_measurements,
                } => {
                    send_or_log_async!(
                        remotedb_client,
                        "handle_store",
                        RemoteDBClientMessages::StoreConnectionMeasurements {
                            connection_measurements,
                            client_uuid: storage_client_uuid,
                            source_type: StorageSourceType::TopologyServer,
                        }
                    )
                    .await
                }
                // Ignore all other cases. ConnectionTracker isn't generating them
                StoreNetworkInterfaceState { .. } => (),
                StoreGatewayPingData { .. } => (),
            }
        }
        warn!("Exiting WebserverConnectionLogWrapper--rx_loop");
    });
    tx_clone
}
