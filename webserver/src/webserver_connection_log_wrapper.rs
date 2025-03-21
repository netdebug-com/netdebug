use libconntrack::{send_or_log, topology_client::DataStorageSender};
use libconntrack_wasm::IpProtocol;
use log::{debug, warn};
use tokio::sync::mpsc::channel;

use crate::{
    organizations::NETDEBUG_EMPLOYEE_ORG_ID,
    remotedb_client::{RemoteDBClientMessages, RemoteDBClientSender, StorageSourceType},
};

/// Simple helper to take ConnectionMeasurement storage request from the *Webserver's* connection
/// tracker and send them to the remote DB.
pub fn spawn_webserver_connection_log_wrapper(
    remotedb_client: RemoteDBClientSender,
    device_uuid: uuid::Uuid,
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
                    if connection_measurements.key.ip_proto == IpProtocol::ICMP
                        || connection_measurements.key.ip_proto == IpProtocol::ICMP6
                    {
                        // Apparently the equinix servers are exposed to *a lot* of icmp echo's hitting it.
                        // If we export all of them, they flood the DB, so lets ignore them.
                        continue;
                    }
                    send_or_log!(
                        remotedb_client,
                        "handle_store",
                        RemoteDBClientMessages::StoreConnectionMeasurements {
                            connection_measurements,
                            device_uuid,
                            organization_id: NETDEBUG_EMPLOYEE_ORG_ID,
                            source_type: StorageSourceType::TopologyServer,
                        }
                    )
                    .await
                }
                // Ignore all other cases. ConnectionTracker isn't generating them
                StoreNetworkInterfaceState { .. } => (),
                StoreGatewayPingData { .. } => (),
                StoreDnsEntries { .. } => (),
            }
        }
        warn!("Exiting WebserverConnectionLogWrapper--rx_loop");
    });
    tx_clone
}
