use std::{
    error::Error,
    fmt::{Debug, Display},
    time::Duration,
};

use chrono::{DateTime, Utc};
use common::test_utils::test_dir;
use common_wasm::timeseries_stats::{ExportedStatRegistry, StatHandleDuration, StatType, Units};
use indexmap::IndexMap;
use libconntrack::utils::PerfMsgCheck;
use libconntrack_wasm::{topology_server_messages::DesktopLogLevel, ConnectionMeasurements};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::channel;
use tokio_postgres::Client;
use uuid::Uuid;

use crate::secrets_db::Secrets;

/// An agent to manage the connection to the remote database service
/// Currently we're using timescaledb.com b/c it supports both
/// standard SQL as well as timeseries magic.
///
/// Also looked at influxdb but the rust client was unofficial and
/// didn't work for me.  Timescaledb was easier to setup and cheaper
/// to support
#[derive(Debug)]
pub struct RemoteDBClient {
    urls: MakeDbUrl,
    /// if we need to retry the connection, this is our next retry value; exponential backoff
    retry_time: tokio::time::Duration,
    /// max time that we wait between connections
    retry_time_max: tokio::time::Duration,
    /// A copy of the handle to send this messages
    tx: RemoteDBClientSender,
    /// The mpsc rx handle to receive messages
    rx: RemoteDBClientReceiver,
    /// A counter to track how long messages to us have been in the queue
    queue_duration: StatHandleDuration,
    /// Name of the table where we store desktop_counters
    counters_table_name: String,
    /// Name of the table where we store logs from the desktop
    logs_table_name: String,
    /// Basename of the table where we store the connection measurements, e.g., "connection_$company"
    connections_table_name: String,
}

/// CREATE TABLE desktop_counters (
///     counter varchar(256),
///     value int,
///     source varchar (256),
///     time DATE);
const COUNTERS_DB_NAME: &str = "desktop_counters";
const LOGS_DB_NAME: &str = "desktop_logs";
const CONNECTIONS_DB_NAME: &str = "desktop_connections";
const INITIAL_RETRY_TIME_MS: u64 = 100;
// Linux root cert db is /etc/ssl/certs/ca-certificates.crt, at least on Ubuntu

pub type RemoteDBClientSender = tokio::sync::mpsc::Sender<PerfMsgCheck<RemoteDBClientMessages>>;
pub type RemoteDBClientReceiver = tokio::sync::mpsc::Receiver<PerfMsgCheck<RemoteDBClientMessages>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// When we log a ConnectionMeasurement, is the source a desktop or a topology server?
pub enum StorageSourceType {
    Desktop,
    TopologyServer,
}

#[derive(thiserror::Error, Debug)]
pub enum RemoteDBClientError {
    #[error("TLS Error {0}")]
    TlsError(#[from] native_tls::Error),
    #[error("Postgresql Error {0}")]
    PostgresqlError(#[from] tokio_postgres::Error),
}

impl Display for StorageSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use StorageSourceType::*;
        match self {
            Desktop => write!(f, "Desktop"),
            TopologyServer => write!(f, "Topology"),
        }
    }
}
#[derive(Clone, Debug)]
pub enum RemoteDBClientMessages {
    StoreConnectionMeasurements {
        connection_measurements: Box<ConnectionMeasurements>,
        device_uuid: Uuid,
        source_type: StorageSourceType,
    },
    StoreCounters {
        counters: IndexMap<String, u64>,
        source: String,
        os: String,
        version: String,
        time: DateTime<Utc>,
    },
    StoreLog {
        msg: String,
        level: DesktopLogLevel,
        os: String,
        version: String,
        device_uuid: String,
        time: DateTime<Utc>,
    },
}

// full URL is postgres://rw_user:PASSWORD@ttfd71uhz4.m8ahrqo1nb.tsdb.cloud.timescale.com:33628/tsdb?sslmode=require
const PRODUCTION_DB_DRIVER: &str = "postgres";
const PRODUCTION_DB_URL_BASE: &str =
    "ttfd71uhz4.m8ahrqo1nb.tsdb.cloud.timescale.com:33628/tsdb?sslmode=require";
/// Create the URL to the production DB server.  There are different URLs for
/// connections with read-only vs. write priviledges
/// return two strings; one valid with the password and one with the password XXX'd out
/// for logging
struct MakeDbUrl {
    /// URL, but don't log this!
    url_with_auth: String,
    /// URL with auth info XXXXX'd out; safe to log
    url_without_auth: String,
}
impl Debug for MakeDbUrl {
    /// custom debug function to not log the auth info
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MakeDbUrl")
            .field("url_without_auth", &self.url_without_auth)
            .finish()
    }
}
fn make_db_url(secrets: &Secrets, is_readonly: bool) -> MakeDbUrl {
    let (user, passwd) = if is_readonly {
        (
            secrets
                .timescale_db_read_user
                .clone()
                .expect("Asked for a read-only prod DB connection, but no read user"),
            secrets
                .timescale_db_read_secret
                .clone()
                .expect("Asked for a read-only prod DB connection, but no read secret"),
        )
    } else {
        (
            secrets
                .timescale_db_write_user
                .clone()
                .expect("Asked for a write prod DB connection, but no write user"),
            secrets
                .timescale_db_write_secret
                .clone()
                .expect("Asked for a write prod DB connection, but no read user"),
        )
    };

    MakeDbUrl {
        url_with_auth: format!(
            "{}://{}:{}@{}",
            PRODUCTION_DB_DRIVER, user, passwd, PRODUCTION_DB_URL_BASE
        ),
        url_without_auth: format!(
            "{}://{}:{}@{}",
            PRODUCTION_DB_DRIVER, user, "XXXXX", PRODUCTION_DB_URL_BASE
        ),
    }
}

impl RemoteDBClient {
    pub fn spawn(
        secrets: Secrets,
        max_queue: usize,
        retry_time_max: tokio::time::Duration,
        stats: ExportedStatRegistry,
    ) -> Result<RemoteDBClientSender, Box<dyn Error>> {
        let (tx, rx) = channel(max_queue);
        let urls = make_db_url(&secrets, false);

        let remote_db_client = RemoteDBClient {
            urls,
            rx,
            retry_time: Duration::from_millis(INITIAL_RETRY_TIME_MS),
            retry_time_max,
            tx: tx.clone(),
            queue_duration: stats.add_duration_stat(
                "remotedb_client_queue_delay",
                Units::Microseconds,
                [StatType::AVG, StatType::MAX],
            ),
            counters_table_name: COUNTERS_DB_NAME.to_string(),
            logs_table_name: LOGS_DB_NAME.to_string(),
            connections_table_name: CONNECTIONS_DB_NAME.to_string(),
        };
        tokio::spawn(async move {
            remote_db_client.rx_loop().await.unwrap();
        });
        Ok(tx)
    }

    pub fn get_tx(&self) -> RemoteDBClientSender {
        self.tx.clone()
    }

    /// Useful for other processes that want to read the database but don't want to do message
    /// passing to and from this RemoteDbClient agent.  Just give them their own client.
    ///
    /// NOTE: I like the idea of all of the write connections going through the RemoteDbClient agent
    /// so that they queue and will reconnect if disconnected where as the read operations can be more
    /// fragile.
    pub async fn make_read_only_client(secrets: &Secrets) -> Result<Client, RemoteDBClientError> {
        let urls = make_db_url(secrets, true);
        let connector = native_tls::TlsConnector::new()?;
        let connector = postgres_native_tls::MakeTlsConnector::new(connector);

        let (client, connection) = tokio_postgres::connect(&urls.url_with_auth, connector).await?;
        // the tokio_postgres API requires that we spawn a task for the connection
        // so it can handle multiple reads/writes in parallel on the backend
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                // TODO: figure out under what conditions this could exit and see
                // if we need to be more resilient here
                warn!(
                    "tokio_postgress connection exited with {}... uhmm.. TODO",
                    e
                );
            }
        });
        Ok(client)
    }

    async fn rx_loop(mut self) -> Result<(), Box<dyn Error>> {
        loop {
            info!(
                "Trying to connect to database server: {}",
                self.urls.url_without_auth
            );
            let connector = native_tls::TlsConnector::new()?;
            let connector = postgres_native_tls::MakeTlsConnector::new(connector);

            let (client, connection) =
                match tokio_postgres::connect(&self.urls.url_with_auth, connector).await {
                    Ok((client, connection)) => (client, connection),
                    Err(e) => {
                        self.retry_time = std::cmp::min(self.retry_time * 2, self.retry_time_max);
                        warn!(
                        "Failed to connect to postgres server {} - retrying in {:?} -- error {}",
                        self.urls.url_without_auth, self.retry_time, e
                    );
                        tokio::time::sleep(self.retry_time).await;
                        continue;
                    }
                };
            // successful connect, reset retry timer
            self.retry_time = Duration::from_millis(INITIAL_RETRY_TIME_MS);

            // the tokio_postgres API requires that we spawn a task for the connection
            // so it can handle multiple reads/writes in parallel on the backend
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    // TODO: figure out under what conditions this could exit and see
                    // if we need to be more resilient here
                    warn!(
                        "tokio_postgress connection exited with {}... uhmm.. TODO",
                        e
                    );
                }
            });
            while let Some(msg) = self.rx.recv().await {
                let msg = msg.perf_check_get_with_stats("RemoteDBClient", &mut self.queue_duration);
                use RemoteDBClientMessages::*;
                if let Err(e) = match &msg {
                    StoreCounters {
                        counters,
                        source,
                        time,
                        os,
                        version,
                    } => {
                        self.handle_store_counters(&client, counters, source, time, os, version)
                            .await
                    }
                    StoreLog { .. } => self.handle_store_log(&client, msg).await,
                    StoreConnectionMeasurements {
                        connection_measurements,
                        device_uuid,
                        source_type,
                    } => {
                        self.handle_store_connection_measurement(
                            &client,
                            connection_measurements,
                            device_uuid,
                            source_type,
                        )
                        .await
                    }
                } {
                    warn!(
                        "RemoteClientDB loop produced error: restarting client: {}",
                        e
                    );
                    break;
                }
            }
        }
    }

    pub async fn handle_store_counters(
        &self,
        client: &Client,
        counters: &IndexMap<String, u64>,
        source: &String,
        time: &DateTime<Utc>,
        os: &String,
        version: &String,
    ) -> Result<(), tokio_postgres::error::Error> {
        /* GRRR - the more efficient 'COPY {table} FROM STDIN
         * doesn't compile... can't figure out why
         * error is "can't find write/write_all/finish"
         * even when I include std::io::Write;
         * It seems to have to do with not having the type parameters to copy_in()
         * correctly met!?

        let mut writer = client
            .copy_in(
                "COPY desktop-counters (counter, value, source, time) FROM STDIN",)
            .await
            .unwrap();
        for (c, v) in &counters {
            writer.write_all(format!("{}\t{}\t{}\t{}\n", c, v, source, time).as_bytes());
        }
        writer.finish();

        * SIGH:  falling back to less efficient INSERT loop
        *
        * See discussion at : https://stackoverflow.com/questions/71684651/multiple-value-inserts-to-postgres-using-tokio-postgres-in-rust
        * but it's not clear if we can insert multiple values into the same transaction AND keep the security of having the library
        * do the parameter escaping for us.
        *
        * TODO Add some counters to track how long this takes.
        */
        client.execute("BEGIN", &[]).await?;
        let statement = client
            .prepare(&format!(
                "INSERT INTO {} (counter, value, source, time, os, version) VALUES ($1, $2, $3, $4, $5, $6)",
                self.counters_table_name
            ))
            .await?;
        for (c, v) in counters {
            let v_i64 = *v as i64; // TODO: change this conversion once we move to i64 counters
                                   // NOTE: converting DateTime<UTC> to postgres requires the magical 'with-chrono-0_4' feature
            client
                .query(&statement, &[c, &v_i64, &source, &time, &os, &version])
                .await?;
        }
        // NOTE: if we hit an error in the above loop and never get here, that's ok b/c we'll
        // need to tear down the client connection and restart it which the calling code does
        // anyway
        client.execute("COMMIT", &[]).await?;
        Ok(())
    }

    /**
     * Load the table we've sync'd from prod into the database for testing
     *
     * This SHOULD fail with 'table already exists' if you mistakenly run this on the production DB,
     * but you know... like please don't do that.
     * FYI: super useful mapping of SQL types to Rust types: https://kotiri.com/2018/01/31/postgresql-diesel-rust-types.html
     *
     * TODO: decide how we want to do table schema migration
     *
     * NOTE: cannot wrap this in #[cfg(test)] as we need it for the integration tests in ./webserver/tests/test_remotedb_client.rs
     */
    pub async fn create_table_schema(
        &self,
        client: &Client,
    ) -> Result<(), tokio_postgres::error::Error> {
        let schema_file = test_dir("webserver", "production_schema.sql");
        let sql_instructions = std::fs::read_to_string(schema_file).unwrap();
        // the default table has a public schema - delete it before we add it
        client.execute("DROP SCHEMA PUBLIC", &[]).await?;
        // we need to create the needed roles so the sql can be inserted cleanly
        for role in ["tsdbadmin", "tsdbexplorer", "readaccess", "rw_updater"] {
            client
                .execute(format!("CREATE ROLE {} WITH SUPERUSER", role).as_str(), &[])
                .await?;
        }
        client.batch_execute(&sql_instructions).await?;
        // do some basic testing to make sure it's loaded properly
        for table in ["desktop_counters", "desktop_logs"] {
            let rows = client
                .query(
                    format!(
                        "SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'public' AND table_name = '{}');",
                        table
                    )
                    .as_str(),
                    &[],
                )
                .await
                .unwrap();
            let table_exists = rows.first().unwrap().get::<_, bool>(0);
            if !table_exists {
                // this is only called in test code, ok to panic
                panic!("Failed to create table {} - wtf!?", table);
            }
            println!("Tested that table {} was successfully created", table);
        }
        Ok(())
    }

    pub async fn handle_store_log(
        &self,
        client: &Client,
        msg: RemoteDBClientMessages,
    ) -> Result<(), tokio_postgres::Error> {
        match msg {
            RemoteDBClientMessages::StoreLog {
                msg,
                level,
                os,
                version,
                device_uuid,
                time,
            } => {
                client.execute(
                format!("INSERT INTO {} (msg, level, source, time, os, version) VALUES ($1, $2, $3, $4, $5, $6)",self.logs_table_name).as_str(),
            &[&msg, &level.to_string(), &device_uuid, &time, &os, &version  ]
        ).await?;
            }
            _ => panic!(
                "Called RemoteDBClient::handle_store_log with a non-store_log message {:?}",
                msg
            ),
        }
        Ok(())
    }

    /// Store a connection measurements struct to the remote db client
    /// NOTE: similar to the other stores, this info is coming directly from the client
    /// So we should assume this data might be malicious and should be checked for integrity
    /// TODO: DoS is probably ok for now, just make sure there can't be SQL injection attacks by
    /// using the right quoted insert.

    pub async fn handle_store_connection_measurement(
        &self,
        client: &Client,
        m: &ConnectionMeasurements,
        device_uuid: &Uuid,
        source_type: &StorageSourceType,
    ) -> Result<(), tokio_postgres::Error> {
        // store a bunch of more complex members as JSON blobs, for now
        // NOTE: these .unwrap()s are all safe b/c to get here all of the data needs to be
        //  already encoded this way
        let probe_report_summary = serde_json::to_string(&m.probe_report_summary).unwrap();
        let associated_apps = serde_json::to_string(&m.associated_apps).unwrap();
        // annoying; postgresql_tokio doesn't map u64 to BIGINT
        let tx_loss = m.tx_stats.lost_bytes.map(|b| b as i64);
        let rx_loss = m.tx_stats.lost_bytes.map(|b| b as i64);
        let tx_stats = serde_json::to_string(&m.tx_stats).unwrap();
        let rx_stats = serde_json::to_string(&m.rx_stats).unwrap();
        let now = Utc::now();
        client
            .execute(
                format!(
                    r#"INSERT INTO {} (
                    local_ip, 
                    remote_ip, 
                    local_port, 
                    remote_port, 
                    ip_protocol, 
                    local_hostname, 
                    remote_hostname, 
                    probe_report_summary, 
                    user_annotation, 
                    user_agent, 
                    associated_apps, 
                    close_has_started, 
                    four_way_close_done, 
                    start_tracking_time, 
                    last_packet_time, 
                    tx_loss, 
                    rx_loss, 
                    tx_stats, 
                    rx_stats, 
                    time,
                    client_uuid,
                    source_type
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 
                        $14, $15, $16, $17, $18, $19 , $20, $21, $22)"#,
                    self.connections_table_name
                )
                .as_str(),
                // annoying - formatter is confused by this... hand format
                &[
                    &m.key.local_ip.to_string(),
                    &m.key.remote_ip.to_string(),
                    &(m.key.local_l4_port as i32),
                    &(m.key.remote_l4_port as i32),
                    &(m.key.ip_proto.to_wire() as i16),
                    &m.local_hostname,
                    &m.remote_hostname,
                    &probe_report_summary,
                    &m.user_annotation,
                    &m.user_agent,
                    &associated_apps,
                    &m.close_has_started,
                    &m.four_way_close_done,
                    &m.start_tracking_time,
                    &m.last_packet_time,
                    &tx_loss,
                    &rx_loss,
                    &tx_stats,
                    &rx_stats,
                    &now,
                    &device_uuid,
                    &source_type.to_string(),
                ],
            )
            .await?;
        Ok(())
    }

    //    #[cfg(test)] // do NOT mark this as test only as the integration tests don't compile with 'test' flag (!?)
    pub fn mk_mock(url: &str) -> RemoteDBClient {
        let (tx, rx) = channel(10);
        let registry = ExportedStatRegistry::new("testing", std::time::Instant::now());
        RemoteDBClient {
            urls: MakeDbUrl {
                url_with_auth: url.to_string(),
                url_without_auth: url.to_string(), // mock version shouldn't have a password to protect
            },
            retry_time: Duration::from_millis(INITIAL_RETRY_TIME_MS),
            retry_time_max: Duration::from_secs(10),
            tx,
            rx,
            queue_duration: registry.add_duration_stat(
                "test_queue_duration",
                Units::Microseconds,
                [StatType::AVG],
            ),
            counters_table_name: COUNTERS_DB_NAME.to_string(),
            logs_table_name: LOGS_DB_NAME.to_string(),
            connections_table_name: CONNECTIONS_DB_NAME.to_string(),
        }
    }

    pub async fn count_remote_counters_rows(
        &self,
        client: &Client,
    ) -> Result<i64, tokio_postgres::error::Error> {
        let rows = client
            .query(
                format!("SELECT COUNT(*) FROM {}", self.counters_table_name).as_str(),
                &[],
            )
            .await?;
        // NOTE that postgres doesn't seem to have a native u64 type so it uses
        // int8 which maps to a i64 in rust.
        // Why allow negative!?
        let count = rows.first().unwrap().get::<_, i64>(0);
        Ok(count)
    }

    pub async fn count_remote_logs_rows(
        &self,
        client: &Client,
    ) -> Result<i64, tokio_postgres::error::Error> {
        let rows = client
            .query(
                format!("SELECT COUNT(*) FROM {}", self.logs_table_name).as_str(),
                &[],
            )
            .await?;
        // NOTE that postgres doesn't seem to have a native u64 type so it uses
        // int8 which maps to a i64 in rust.
        // Why allow negative!?
        let count = rows.first().unwrap().get::<_, i64>(0);
        Ok(count)
    }
    pub async fn count_remote_connection_rows(
        &self,
        client: &Client,
    ) -> Result<i64, tokio_postgres::error::Error> {
        let rows = client
            .query(
                format!("SELECT COUNT(*) FROM {}", self.connections_table_name).as_str(),
                &[],
            )
            .await?;
        // NOTE that postgres doesn't seem to have a native u64 type so it uses
        // int8 which maps to a i64 in rust.
        // Why allow negative!?
        let count = rows.first().unwrap().get::<_, i64>(0);
        Ok(count)
    }
}

/*
 * No unit tests here, but added a bunch of integration tests in webserver/tests/test_remotedb_client.rs
 *
 * Open to feedback if they should be here or there, but IMHO since we're dynamically downloading an instance of postgres
 * and starting it up/tearing it down, it's not longer a 'unit' test.
 */
