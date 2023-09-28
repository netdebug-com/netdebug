use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use log::{debug, info};
use pb_storage_service::storage_service_server::{StorageService, StorageServiceServer};
use pb_storage_service::{StorageReply, StorageRequest};
use prost::Message;
use tokio_rusqlite::Connection;
use tonic::{transport::Server, Request, Response, Status};

pub struct StorageServiceImpl {
    db: Connection,
}

impl StorageServiceImpl {
    async fn new(path: &str) -> tokio_rusqlite::Result<StorageServiceImpl> {
        let db = Connection::open(path).await?;
        db.call(|conn| {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY,
                    saved_at DATETIME, 
                    pb_storage_entry BLOB
                )",
                [],
            )
        })
        .await?;
        Ok(StorageServiceImpl { db })
    }
}

#[tonic::async_trait]
impl StorageService for StorageServiceImpl {
    async fn store(
        &self,
        request: Request<StorageRequest>,
    ) -> Result<Response<StorageReply>, Status> {
        info!("Received Request");
        for entry in request.into_inner().connection_entries {
            use tonic::Code;
            debug!("{:?}", entry);
            let db_res = self
                .db
                .call(move |conn| {
                    conn.execute(
                        "INSERT INTO connections (saved_at, pb_storage_entry) 
                         VALUES (
                            datetime('now'),
                            ?1
                        )",
                        rusqlite::params![entry.encode_to_vec()],
                    )
                })
                .await;
            match db_res {
                Err(e) => Err(Status::new(Code::Internal, e.to_string())),
                Ok(_) => Ok(()),
            }?;
        }

        Ok(tonic::Response::new(StorageReply::default()))
    }
}

/// Netdebug Storage Server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Used to enable production flags vs. (default) dev mode
    #[arg(long)]
    pub production: bool,

    /// which TCP port to listen on
    #[arg(long, default_value_t = 50051)]
    pub listen_port: u16,

    /// path to sqlite database file
    #[arg(long, default_value = "./connections.sqlite3")]
    pub sqlite_db_file: String,
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
    let args = Args::parse();

    info!("Starting storage server");
    info!("Opening SQLite DB {}", args.sqlite_db_file);
    let svc = StorageServiceImpl::new(&args.sqlite_db_file).await?;
    let ip: IpAddr = match args.production {
        true => "::",
        false => "::1",
    }
    .parse()?;
    let addr = SocketAddr::new(ip, args.listen_port);
    info!("Listening on {}", addr);
    Server::builder()
        .add_service(StorageServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}

#[cfg(test)]
mod test {
    type TestRes = Result<(), Box<dyn std::error::Error>>;
    use super::*;

    #[tokio::test]
    async fn very_basic() -> TestRes {
        let svc = StorageServiceImpl::new(":memory:").await.unwrap();
        let mut req = StorageRequest::default();
        req.connection_entries
            .push(pb_conntrack_types::ConnectionStorageEntry::default());
        svc.store(Request::new(req.clone())).await?;

        let actual = svc
            .db
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT id, pb_storage_entry FROM connections")?;
                let iter = stmt.query_map([], |row| {
                    // Ugh. From SQL to Vec<u8> to Bytes (or rather bytes::Buf). One would
                    // think there should be an easier way. Also error handling sucks because
                    // db.call() returns Result<_,rusqlite::Error>
                    let serialized: bytes::Bytes = row.get::<usize, Vec<u8>>(1)?.into();
                    Ok(pb_conntrack_types::ConnectionStorageEntry::decode(serialized).unwrap())
                })?;
                let mut res = Vec::new();
                for entry in iter {
                    let unwrapped = entry.unwrap();
                    res.push(unwrapped);
                }
                Ok(res)
            })
            .await?;
        assert_eq!(req.connection_entries, actual);
        Ok(())
    }
}
