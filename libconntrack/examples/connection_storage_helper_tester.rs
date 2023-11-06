use libconntrack::connection_storage_handler::ConnectionStorageHandler;
use pb_conntrack_types::ConnectionStorageEntry;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    let tx = ConnectionStorageHandler::spawn_from_url("http://[::1]:50051".to_string(), 10)
        .await
        .unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    sleep(Duration::from_millis(1000)).await;
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    tx.send(ConnectionStorageEntry::default()).await.unwrap();
    sleep(Duration::from_millis(3000)).await;
}
