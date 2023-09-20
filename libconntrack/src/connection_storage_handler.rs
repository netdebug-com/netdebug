use log::info;
use log::warn;
use pb_conntrack_types::ConnectionStorageEntry;
use pb_storage_service::{storage_service_client::StorageServiceClient, StorageRequest};
use tokio::sync::mpsc;
use tonic::transport::Channel;

/// Take `ConnectionStorageEntry`s from an `mpsc` channel and send them to the
/// storage server via GRPC.
/// The `mpsc` is bounded. In case the storage server is slow, we don't want to
/// risk an OOM if the channel fills up. Better to drop additional entries.
pub struct ConnectionStorageHandler {
    client: StorageServiceClient<Channel>,
    rx: mpsc::Receiver<ConnectionStorageEntry>,
}

impl ConnectionStorageHandler {
    pub async fn spawn_from_url(
        url: String,
        queue_size: usize,
    ) -> mpsc::Sender<ConnectionStorageEntry> {
        // FIXME: handle the errors instead of just blindly `unwrap()`'ing
        ConnectionStorageHandler::spawn_from_channel(
            Channel::from_shared(url).unwrap().connect().await.unwrap(),
            queue_size,
        )
    }

    // This is used for testing where we can pass in an "in-memory" channel
    pub fn spawn_from_channel(
        channel: Channel,
        queue_size: usize,
    ) -> mpsc::Sender<ConnectionStorageEntry> {
        let (tx, rx) = mpsc::channel(queue_size);
        tokio::spawn(async move {
            // TODO: better error handling than panic
            // Also, if we panic here we just kill the thread but not the
            // process.
            let mut sender = ConnectionStorageHandler {
                client: StorageServiceClient::new(channel),
                rx,
            };
            sender.rx_loop().await;
        });
        tx
    }

    pub async fn rx_loop(&mut self) {
        // The GRPC client is non-pipeline. So after we send a request we wait until
        // the server responds. But `ConnectionStorageEntry`s can arrive faster than
        // the server response time: so we add logic to drain any `ConnectionStorageEntry`
        // that's in the `mpsc` channel and then send a batch to the server.
        // TODO: we should still figure out the right pipelining strategy
        'outer_while: while let Some(entry) = self.rx.recv().await {
            let mut req = StorageRequest {
                connection_entries: vec![entry],
            };
            'inner_loop: loop {
                // Lets drain any entries we might have accumulated in the msg queue
                use tokio::sync::mpsc::error::TryRecvError;
                match self.rx.try_recv() {
                    Ok(entry) => req.connection_entries.push(entry),
                    Err(TryRecvError::Empty) => break 'inner_loop,
                    Err(TryRecvError::Disconnected) => break 'outer_while,
                };
            }
            match self.client.store(req).await {
                Ok(_) => (),
                Err(e) => warn!("Failed to send to storage server: {:?}", e),
            }
        }
        info!("ConnectionStorageSender exiting rx_loop");
    }
}
