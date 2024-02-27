use std::{env, error::Error, path::PathBuf, time::Duration};

use chrono::{DateTime, Utc};
use common_wasm::timeseries_stats::{ExportedStatRegistry, StatHandleDuration, StatType, Units};
use indexmap::IndexMap;
use libconntrack::utils::PerfMsgCheck;
use libconntrack_wasm::{topology_server_messages::DesktopLogLevel, ConnectionMeasurements};
use log::{error, info, warn};
use tokio::sync::mpsc::channel;
use tokio_postgres::Client;
use uuid::Uuid;

/// An agent to manage the connection to the remote database service
/// Currently we're using timescaledb.com b/c it supports both
/// standard SQL as well as timeseries magic.
///
/// Also looked at influxdb but the rust client was unofficial and
/// didn't work for me.  Timescaledb was easier to setup and cheaper
/// to support
pub struct RemoteDBClient {
    /// Full URL to our remote database... WITH PASSWORD - DO NOT LOG
    url: String,
    /// URL to our remote database with password XX'd out; use for logging
    url_no_auth: String,
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

#[derive(Clone, Debug)]
pub enum RemoteDBClientMessages {
    StoreConnectionMeasurements {
        connection_measurements: Box<ConnectionMeasurements>,
        client_uuid: Uuid,
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
        client_id: String,
        time: DateTime<Utc>,
    },
}

impl RemoteDBClient {
    pub fn spawn(
        auth_file: String,
        max_queue: usize,
        retry_time_max: tokio::time::Duration,
        stats: ExportedStatRegistry,
    ) -> Result<RemoteDBClientSender, Box<dyn Error>> {
        let (tx, rx) = channel(max_queue);
        let auth_file = RemoteDBClient::get_fully_qualified_auth_file(auth_file);
        let auth_token = std::fs::read_to_string(auth_file.clone()).map_err(|e| {
            error!("Failed to read timescaledb_auth: {}", auth_file.display());
            e
        })?;
        let url = format!("postgres://tsdbadmin:{}@ttfd71uhz4.m8ahrqo1nb.tsdb.cloud.timescale.com:33628/tsdb?sslmode=require", auth_token.trim());
        let url_no_auth = format!("postgres://tsdbadmin:{}@ttfd71uhz4.m8ahrqo1nb.tsdb.cloud.timescale.com:33628/tsdb?sslmode=require", "XXXXXXX");

        let remote_db_client = RemoteDBClient {
            url,
            url_no_auth,
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

    async fn rx_loop(mut self) -> Result<(), Box<dyn Error>> {
        loop {
            info!("Trying to connect to database server: {}", self.url_no_auth);
            let connector = native_tls::TlsConnector::new()?;
            let connector = postgres_native_tls::MakeTlsConnector::new(connector);

            let (client, connection) = match tokio_postgres::connect(&self.url, connector).await {
                Ok((client, connection)) => (client, connection),
                Err(e) => {
                    self.retry_time = std::cmp::min(self.retry_time * 2, self.retry_time_max);
                    warn!(
                        "Failed to connect to postgres server {} - retrying in {:?} -- error {}",
                        self.url_no_auth, self.retry_time, e
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
                        client_uuid,
                    } => {
                        self.handle_store_connection_measurement(
                            &client,
                            connection_measurements,
                            client_uuid,
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

    /**
     * Try a couple of places to find the auth_file, e.g.,
     * $HOME
     * CWD
     * TODO : (some installed location?)
     */
    fn get_fully_qualified_auth_file(auth_file: String) -> PathBuf {
        let mut path = if let Ok(home) = env::var("HOME") {
            PathBuf::from(home)
        } else {
            PathBuf::from(".")
        };
        path.push(auth_file);
        path
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
     * The assumed table schema that we're writing into.  This is mostly for testing and doesn't
     * handle migrating the production database from what ever it's current schema is to this schema,
     * so that needs to be handled separately.
     *
     * This SHOULD fail with 'table already exists' if you mistakenly run this on the production DB,
     * but you know... like please don't do that.
     * FYI: super useful mapping of SQL types to Rust types: https://kotiri.com/2018/01/31/postgresql-diesel-rust-types.html
     *
     * TODO: decide how we want to do table schema migration
     */
    pub async fn create_table_schema(
        &self,
        client: &Client,
    ) -> Result<(), tokio_postgres::error::Error> {
        // for the counters
        client
            .query(
                format!(
                    "CREATE TABLE {} ( \
                        counter TEXT, \
                        value BIGINT, \
                        os TEXT, \
                        version TEXT, \
                        source TEXT, \
                        time TIMESTAMPTZ)",
                    self.counters_table_name
                )
                .as_str(),
                &[],
            )
            .await?;
        // for the logs
        client
            .query(
                format!(
                    "CREATE TABLE {} ( \
                        msg TEXT, \
                        level TEXT, \
                        os TEXT, \
                        version TEXT, \
                        source TEXT, \
                        time TIMESTAMPTZ)",
                    self.logs_table_name
                )
                .as_str(),
                &[],
            )
            .await?;
        // for the connections
        // TODO: we really need to think about how much of this we really want to store and what has value
        //      ... this is going to be a lot of data...
        // TODO: expand the top-level struct but many subcomponents are still in JSON blobs
        // TODO: add client ID here to make (client_id, connection_key) the primary key
        // TODO: add company here to make the table name a function of the company
        client
            .query(
                format!(
                    "CREATE TABLE {} ( 
                        connection_key TEXT, 
                        local_hostname TEXT, 
                        remote_hostname TEXT, 
                        probe_report_summary TEXT, 
                        user_annotation TEXT,
                        user_agent TEXT,
                        associated_apps TEXT,
                        close_has_started BOOLEAN,
                        four_way_close_done BOOLEAN,
                        start_tracking_time TIMESTAMPTZ,
                        last_packet_time TIMESTAMPTZ,
                        tx_loss BIGINT,
                        rx_loss BIGINT,
                        tx_stats TEXT,
                        rx_stats TEXT,
                        time TIMESTAMPTZ,
                        client_uuid UUID
                    )",
                    self.connections_table_name
                )
                .as_str(),
                &[],
            )
            .await?;
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
                client_id,
                time,
            } => {
                client.execute(
                format!("INSERT INTO {} (msg, level, source, time, os, version) VALUES ($1, $2, $3, $4, $5, $6)",self.logs_table_name).as_str(),
            &[&msg, &level.to_string(), &client_id, &time, &os, &version  ]
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
        client_uuid: &Uuid,
    ) -> Result<(), tokio_postgres::Error> {
        // store a bunch of more complex members as JSON blobs, for now
        // NOTE: these .unwrap()s are all safe b/c to get here all of the data needs to be
        //  already encoded this way
        let key = serde_json::to_string(&m.key).unwrap();
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
                    connection_key, 
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
                    client_uuid
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)"#,
                    self.connections_table_name
                )
                .as_str(),
                // annoying - formatter is confused by this... hand format
                &[
                    &key,
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
                    &client_uuid
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
            url: url.to_string(),
            url_no_auth: url.to_string(), // mock version shouldn't have a password to protect
            retry_time: Duration::from_millis(INITIAL_RETRY_TIME_MS),
            retry_time_max: Duration::from_secs(10),
            tx,
            rx,
            queue_duration: registry.add_duration_stat(
                "test_queue_duration",
                Units::Microseconds,
                [StatType::AVG],
            ),
            counters_table_name: "test_db_counters".to_string(),
            logs_table_name: "test_db_logs".to_string(),
            connections_table_name: "test_db_connections".to_string(),
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
