use std::time::Duration;

use libconntrack::connection_storage_handler::ConnectionStorageHandler;
use pb_conntrack_types::ConnectionStorageEntry;
use pb_storage_service::storage_service_server::{StorageService, StorageServiceServer};
use pb_storage_service::{StorageReply, StorageRequest};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

mod common;

struct FakeStorageServiceImpl {
    /// used to signal when `store()` has been called.
    store_called_channel_tx: mpsc::UnboundedSender<()>,
}

type TestRes = Result<(), Box<dyn std::error::Error>>;

#[tonic::async_trait]
impl StorageService for FakeStorageServiceImpl {
    async fn store(&self, _req: Request<StorageRequest>) -> Result<Response<StorageReply>, Status> {
        let _ = self.store_called_channel_tx.send(());
        Ok(tonic::Response::new(StorageReply::default()))
    }
}

#[tokio::test]
async fn test_connection_storage_handler() -> TestRes {
    // FIXME: This is a very basic test. In particular we don't currently test the batching
    // of multiple `ConnectionStorageEntry` instances into a single request. But doing this
    // is non-trivial (I tried) so it's not worth the time to implement this right now
    let conn_pair = common::tonic_helpers::get_fake_connection().await;
    let to_handler = ConnectionStorageHandler::spawn_from_channel(conn_pair.client_channel, 10);
    let (store_called_channel_tx, mut store_called_channel_rx) = mpsc::unbounded_channel();

    let server_impl = FakeStorageServiceImpl {
        store_called_channel_tx,
    };
    tokio::spawn(async move {
        // see https://github.com/hyperium/tonic/blob/master/examples/src/mock/mock.rs
        // for the black magic used here
        tonic::transport::Server::builder()
            .add_service(StorageServiceServer::new(server_impl))
            .serve_with_incoming(tokio_stream::iter(vec![Ok::<_, std::io::Error>(
                conn_pair.server_stream,
            )]))
            .await
    });
    to_handler.send(ConnectionStorageEntry::default()).await?;
    tokio::time::timeout(Duration::from_millis(100), store_called_channel_rx.recv()).await?;
    Ok(())
}
