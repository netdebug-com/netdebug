use std::{env, error::Error, path::PathBuf, time::Duration};

use chrono::{DateTime, Utc};
use common_wasm::timeseries_stats::{ExportedStatRegistry, StatHandleDuration, StatType, Units};
use indexmap::IndexMap;
use libconntrack::utils::PerfMsgCheck;
use log::{info, warn};
use tokio::sync::mpsc::channel;
use tokio_postgres::Client;

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
}

/// CREATE TABLE desktop_counters (
///     counter varchar(256),
///     value int,
///     source varchar (256),
///     time DATE);
const COUNTERS_DB_NAME: &str = "desktop_counters";
const INITIAL_RETRY_TIME_MS: u64 = 100;

pub type RemoteDBClientSender = tokio::sync::mpsc::Sender<PerfMsgCheck<RemoteDBClientMessages>>;
pub type RemoteDBClientReceiver = tokio::sync::mpsc::Receiver<PerfMsgCheck<RemoteDBClientMessages>>;

pub enum RemoteDBClientMessages {
    StoreCounters {
        counters: IndexMap<String, u64>,
        source: String,
        time: DateTime<Utc>,
    },
}

impl RemoteDBClient {
    pub async fn spawn(
        auth_file: String,
        max_queue: usize,
        retry_time_max: tokio::time::Duration,
        stats: ExportedStatRegistry,
    ) -> Result<RemoteDBClientSender, Box<dyn Error>> {
        let (tx, rx) = channel(max_queue);
        let auth_file = RemoteDBClient::get_fully_qualified_auth_file(auth_file);
        let auth_token = std::fs::read_to_string(auth_file)?;
        let url = format!("postgres://tsdbadmin:{}@ttfd71uhz4.m8ahrqo1nb.tsdb.cloud.timescale.com:33628/tsdb?sslmode=require", auth_token);
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
        };
        tokio::spawn(async move {
            remote_db_client.rx_loop().await;
        });
        Ok(tx)
    }

    pub fn get_tx(&self) -> RemoteDBClientSender {
        self.tx.clone()
    }

    async fn rx_loop(mut self) {
        loop {
            // TODO!  Add TLS support in next diff
            // Linux root cert db is /etc/ssl/certs/ca-certificates.crt
            info!("Trying to connect to database server: {}", self.url_no_auth);
            let (client, connection) =
                match tokio_postgres::connect(&self.url, tokio_postgres::NoTls).await {
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
                if let Err(e) = match msg {
                    StoreCounters {
                        counters,
                        source,
                        time,
                    } => {
                        self.handle_store_counters(&client, counters, source, time)
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
        counters: IndexMap<String, u64>,
        source: String,
        time: DateTime<Utc>,
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
                "INSERT INTO {} (counter, value, source, time) VALUES ($1, $2, $3, $4)",
                self.counters_table_name
            ))
            .await?;
        for (c, v) in &counters {
            let v_i64 = *v as i64; // TODO: change this conversion once we move to i64 counters
                                   // NOTE: converting DateTime<UTC> to postgres requires the magical 'with-chrono-0_4' feature
            client
                .query(&statement, &[c, &v_i64, &source, &time])
                .await?;
        }
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
        client
            .query(
                format!(
                    "CREATE TABLE {} ( \
                        counter VARCHAR(256), \
                        value BIGINT, \
                        os VARCHAR(128), \
                        version INT, \
                        source VARCHAR(256), \
                        time TIMESTAMPTZ)",
                    self.counters_table_name
                )
                .as_str(),
                &[],
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
            counters_table_name: "test_db".to_string(),
        }
    }

    pub async fn count_remote_log_rows(
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
        let count = rows.get(0).unwrap().get::<_, i64>(0);
        Ok(count)
    }
}

/*
 * No unit tests here, but added a bunch of integration tests in webserver/tests/test_remotedb_client.rs
 *
 * Open to feedback if they should be here or there, but IMHO since we're dynamically downloading an instance of postgres
 * and starting it up/tearing it down, it's not longer a 'unit' test.
 */
