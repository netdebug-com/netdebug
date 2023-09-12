use log::info;
use pb_storage_service::storage_service_server::{StorageService, StorageServiceServer};
use pb_storage_service::{StorageReply, StorageRequest};
use tonic::{transport::Server, Status};

#[derive(Debug, Default)]
pub struct StorageServiceImpl {}

#[tonic::async_trait]
impl StorageService for StorageServiceImpl {
    async fn store(
        &self,
        _request: tonic::Request<StorageRequest>,
    ) -> Result<tonic::Response<StorageReply>, Status> {
        Ok(tonic::Response::new(StorageReply::default()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // if RUST_LOG isn't set explicitly, set RUST_LOG=info as a default
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "info");
    }
    // if RUST_BACKTRACE isn't set explicitly, set RUST_BACKTRACE=1 as a default
    if let Err(_) = std::env::var("RUST_BACKTRACE") {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    pretty_env_logger::init();
    info!("Starting storage server");

    let svc = StorageServiceImpl::default();
    let addr = "[::1]:50051".parse()?;
    Server::builder()
        .add_service(StorageServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    #[tokio::test]
    async fn very_basic() {
        let mut req = StorageRequest::default();
        req.connection_entries
            .push(pb_conntrack_types::ConnectionStorageEntry::default());
    }
}
