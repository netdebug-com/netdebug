use std::{net::IpAddr, str::FromStr};

use libconntrack::send_or_log_async;
/**
 * TopologyServer is the other side of libconntrack::topology_client.  It provides:
 * 1. A database to store ConnectionMeasurements
 * 2. A service to turn a list of ConnectionMeasurements into a Graph/SVG
 * 3. [future] a single source of truth for IP aliases and geolocation data
 * 4. [future] a shared place to collect per-link performance data (latency, bandwidth, packet loss, etc.)
 *
 * It's important/by design that the TopologyServer maintain the same tx/rx interface as the TopologyClient,
 * i.e., the TopologyServerSender, so that a given binary can transparently have the TopologyServer
 * either be a local or remote process with light coupling between the two.
 *
 * DO NOT MERGE THIS CODE IN WITH ANYTHING THAT COULD BE OPEN-SOURCE!
 * (this is intended to be the secret stuff on the server)
 *
 */
use libconntrack::{
    topology_client::{TopologyServerReceiver, TopologyServerSender},
    utils::PerfMsgCheck,
};
use libconntrack_wasm::ConnectionMeasurements;
use log::{debug, warn};
use tokio::sync::mpsc::{channel, Sender};

use tokio_rusqlite::Connection as DbConnection;
pub struct TopologyServer {
    tx: TopologyServerSender,
    rx: TopologyServerReceiver,
    /// rustsql path identifier
    db_path: String,
    db: DbConnection,
}

impl TopologyServer {
    async fn new(
        tx: TopologyServerSender,
        rx: TopologyServerReceiver,
        db_path: String,
    ) -> tokio_rusqlite::Result<TopologyServer> {
        let db = init_db(&db_path).await?;
        Ok(TopologyServer {
            tx,
            rx,
            db_path,
            db,
        })
    }
    pub async fn spawn(
        db_path: &str,
        buffer_size: usize,
    ) -> tokio_rusqlite::Result<TopologyServerSender> {
        let (tx, rx) = channel(buffer_size);
        TopologyServer::spawn_with_tx_rx(db_path, tx, rx).await
    }

    pub async fn spawn_with_tx_rx(
        db_path: &str,
        tx: TopologyServerSender,
        rx: TopologyServerReceiver,
    ) -> tokio_rusqlite::Result<TopologyServerSender> {
        let topology_server = TopologyServer::new(tx.clone(), rx, db_path.to_string()).await?;
        tokio::spawn(async move {
            topology_server.rx_loop().await;
        });
        Ok(tx)
    }

    /*
    pub fn spawn_sync(db_path: &str, buffer_size: usize) -> tokio_rusqlite::Result<TopologyServerSender> {
        tokio::spawn(async move {
            TopologyServer::spawn(db_path, buffer_size)
        }).join()
    }
    */

    async fn rx_loop(mut self) {
        debug!("Starting TopologyServer:rx_loop()");
        while let Some(msg) = self.rx.recv().await {
            let msg = msg.perf_check_get("TopologyServer.rx_loop()");
            use libconntrack::topology_client::TopologyServerMessage::*;
            match msg {
                GetMyIpAndUserAgent { reply_tx } => self.handle_get_my_ip(reply_tx).await,
                StoreConnectionMeasurements {
                    connection_measurements,
                } => self.handle_store_measurement(connection_measurements).await,
            }
        }
        warn!("Exiting TopologyServer:rx_loop()");
    }

    /**
     * This is a bit of a round peg/square whole to fit this API into the local TopologyServer.
     * This call is supposed to be from the GUI to the desktop to ask the TopologyServer what is the
     * public IP of the host.  When it's all local, it shouldn't be called, but just return localhost
     * to be safe/compliant.
     */
    async fn handle_get_my_ip(&self, reply_tx: Sender<PerfMsgCheck<(IpAddr, String)>>) {
        let my_ip = IpAddr::from_str("127.0.0.1").unwrap();
        let fake_user_agent = "Fake User-agent".to_string();
        send_or_log_async!(
            reply_tx,
            "TopologyServer::handle_get_my_ip()",
            (my_ip, fake_user_agent)
        )
        .await;
    }

    async fn handle_store_measurement(&self, entry: Box<ConnectionMeasurements>) {
        debug!("{:?}", entry);
        let db_res = self
            .db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO connections (saved_at, measurements) 
                         VALUES (
                            datetime('now'),
                            ?1
                        )",
                    // store as a JSON blob for now
                    // TODO: do someting less braindead once it becomes a problem :-)
                    // unwrap() should be ok here b/c it was just serialized before
                    rusqlite::params![serde_json::to_string(&entry).unwrap()],
                )
            })
            .await;
        match db_res {
            Err(e) => {
                // what can we do about errors writing to the DB?  I guess just warn() for now...
                warn!(
                    "Error writing to topology server db {} :: {}",
                    self.db_path, e
                );
            }
            Ok(_rows_updated) => (),
        }
    }

    pub fn get_tx(&self) -> TopologyServerSender {
        self.tx.clone()
    }
}

async fn init_db(db_path: &str) -> tokio_rusqlite::Result<DbConnection> {
    let db = DbConnection::open(db_path).await?;
    db.call(|conn| {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY,
                    saved_at DATETIME, 
                    measurements TEXT
                )",
            [],
        )
    })
    .await?;
    Ok(db)
}

#[cfg(test)]
mod test {
    // Appropriated from the original storage-server code
    type TestRes = Result<(), Box<dyn std::error::Error>>;
    use chrono::Utc;
    use libconntrack_wasm::{traffic_stats::TrafficStatsSummary, ConnectionKey};

    use super::*;

    fn fake_measurement_data() -> ConnectionMeasurements {
        // generate some fake data
        ConnectionMeasurements {
            local_hostname: Some("foo".to_string()),
            key: ConnectionKey {
                local_ip: IpAddr::from_str("1.2.3.4").unwrap(),
                local_l4_port: 1111,
                remote_ip: IpAddr::from_str("5.6.7.8").unwrap(),
                remote_l4_port: 2222,
                ip_proto: libconntrack_wasm::IpProtocol::TCP,
            },
            remote_hostname: Some("bar".to_string()),
            probe_report_summary: common_wasm::ProbeReportSummary::new(),
            user_annotation: None,
            user_agent: None,
            associated_apps: None,
            close_has_started: false,
            four_way_close_done: false,
            start_tracking_time: Utc::now(),
            last_packet_time: Utc::now(),
            tx_stats: TrafficStatsSummary::default(),
            rx_stats: TrafficStatsSummary::default(),
        }
    }
    #[tokio::test]
    async fn very_basic() -> TestRes {
        let (tx, rx) = channel(10);
        let topology_server = TopologyServer::new(tx, rx, ":memory:".to_string())
            .await
            .unwrap();
        let measurements = fake_measurement_data();
        // write to topology server db
        topology_server
            .handle_store_measurement(Box::new(measurements.clone()))
            .await;

        // now read it back out by hand
        let actual_vec =
            topology_server
                .db
                .call(|conn| {
                    let mut stmt = conn.prepare("SELECT id, measurements FROM connections")?;
                    let measurements = stmt.query_map([], |row| {
                    let json = row.get::<usize, String>(1)?;
                    Ok(serde_json::from_str::<ConnectionMeasurements>(&json).unwrap())
                })?.collect::<std::result::Result<Vec<ConnectionMeasurements>, rusqlite::Error>>();
                    Ok(measurements)
                })
                .await
                .unwrap()
                .unwrap();
        assert_eq!(actual_vec.len(), 1);
        assert_eq!(measurements, actual_vec[0]);
        Ok(())
    }
}
