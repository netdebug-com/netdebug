use std::{
    error::Error,
    fmt::{Debug, Display},
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use chrono::{DateTime, Utc};
use common::test_utils::test_dir;
use common_wasm::timeseries_stats::{ExportedStatRegistry, StatHandleDuration, StatType, Units};
use futures::pin_mut;
use gui_types::OrganizationId;
use indexmap::IndexMap;
use itertools::Itertools;
use libconntrack::utils::PerfMsgCheck;
use libconntrack_wasm::{
    topology_server_messages::DesktopLogLevel, AggregatedGatewayPingData, ConnectionMeasurements,
    DnsTrackerEntry, NetworkInterfaceState,
};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use tokio_postgres::{binary_copy::BinaryCopyInWriter, types::Type, Client, GenericClient, Row};
use uuid::Uuid;

use crate::{
    db_utils::TimeRangeQueryParams,
    flows::{query_and_aggregate_flows, write_aggregated_flows},
    secrets_db::Secrets,
};

// We only aggregate a full bucket_size worth of flows at a time. In order to make sure we don't have an stragglers
// in the desktop_connections table, we only start the aggregation if the we are FLOW_AGGREGATION_TIME_GAP_MINUTES
// after the end of the bucket.
pub const FLOW_AGGREGATION_TIME_GAP_MINUTES: i64 = 5;

/// An agent to manage the connection to the remote database service
/// Currently we're using timescaledb.com b/c it supports both
/// standard SQL as well as timeseries magic.
///
/// Also looked at influxdb but the rust client was unofficial and
/// didn't work for me.  Timescaledb was easier to setup and cheaper
/// to support
#[derive(Clone)]
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
    stat_handles: RemoteDBClientStatHandles,
}

#[derive(Clone)]
pub struct RemoteDBClientStatHandles {
    /// A counter to track how long messages to us have been in the queue
    pub queue_duration: StatHandleDuration,
    pub store_counters_duration: StatHandleDuration,
    pub store_log_duration: StatHandleDuration,
    pub store_connections_duration: StatHandleDuration,
    pub store_network_interface_state_duration: StatHandleDuration,
    pub store_gateway_ping_data_duration: StatHandleDuration,
    pub store_dns_entries_duration: StatHandleDuration,
    pub handle_log_device: StatHandleDuration,
}

/// CREATE TABLE desktop_counters (
///     counter varchar(256),
///     value int,
///     source varchar (256),
///     time DATE);
pub const COUNTERS_TABLE_NAME: &str = "desktop_counters";
pub const LOGS_TABLE_NAME: &str = "desktop_logs";
pub const CONNECTIONS_TABLE_NAME: &str = "desktop_connections";
pub const DNS_ENTRIES_TABLE_NAME: &str = "desktop_dns_entries";
pub const NETWORK_INTERFACE_STATE_TABLE_NAME: &str = "desktop_network_interface_state";
pub const AGGREGATED_PING_DATA_TABLE_NAME: &str = "desktop_aggregated_ping_data";
pub const USERS_TABLE_NAME: &str = "users";
pub const ORGANIZATION_TABLE_NAME: &str = "organizations";
pub const DEVICE_TABLE_NAME: &str = "devices";

pub const INITIAL_RETRY_TIME_MS: u64 = 100;

// Linux root cert db is /etc/ssl/certs/ca-certificates.crt, at least on Ubuntu

pub type RemoteDBClientSender = async_channel::Sender<PerfMsgCheck<RemoteDBClientMessages>>;
pub type RemoteDBClientReceiver = async_channel::Receiver<PerfMsgCheck<RemoteDBClientMessages>>;

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
    #[error("Database Invariate Error {err}")]
    DbInvariateError { err: String },
    #[error("PermissionDenied: {err}")]
    PermissionDenied { err: String },
    #[error("Invalid IP Address format from DB column")]
    InvalidIpFormat(#[from] std::net::AddrParseError),
    #[error("Cannot parse via serde_json")]
    InvalidJson(#[from] serde_json::Error),
    #[error("Column does not exist")]
    NoSuchColumn { col_name: String },
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
        organization_id: OrganizationId,
        source_type: StorageSourceType,
    },
    StoreCounters {
        counters: IndexMap<String, u64>,
        device_uuid: Uuid,
        os: String,
        version: String,
        time: DateTime<Utc>,
    },
    StoreLog {
        msg: String,
        level: DesktopLogLevel,
        os: String,
        version: String,
        device_uuid: Uuid,
        time: DateTime<Utc>,
    },
    StoreNetworkInterfaceState {
        network_interface_state: NetworkInterfaceState,
        device_uuid: Uuid,
    },
    StoreGatewayPingData {
        ping_data: Vec<AggregatedGatewayPingData>,
    },
    StoreDnsEntries {
        dns_entries: Vec<DnsTrackerEntry>,
        device_uuid: Uuid,
    },
    LogDeviceConnect {
        device_uuid: Uuid,
        // defaults to '1' for the beta program
        organization: OrganizationId,
        description: String,
        addr: SocketAddr,
    },
}

impl From<RemoteDBClientMessages> for PerfMsgCheck<RemoteDBClientMessages> {
    fn from(msg: RemoteDBClientMessages) -> Self {
        PerfMsgCheck::new(msg)
    }
}

// full URL is postgres://rw_user:PASSWORD@ttfd71uhz4.m8ahrqo1nb.tsdb.cloud.timescale.com:33628/tsdb?sslmode=require
const PRODUCTION_DB_DRIVER: &str = "postgres";
/// Create the URL to the production DB server.  There are different URLs for
/// connections with read-only vs. write priviledges
/// return two strings; one valid with the password and one with the password XXX'd out
/// for logging
#[derive(Clone)]
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

    let base_url = secrets
        .timescale_db_base_url
        .clone()
        .expect("Need to specify timescaledb_base_url in secrets");
    MakeDbUrl {
        url_with_auth: format!(
            "{}://{}:{}@{}",
            PRODUCTION_DB_DRIVER, user, passwd, base_url
        ),
        url_without_auth: format!(
            "{}://{}:{}@{}",
            PRODUCTION_DB_DRIVER, user, "XXXXX", base_url
        ),
    }
}

impl RemoteDBClient {
    pub fn spawn(
        secrets: Secrets,
        max_queue: usize,
        retry_time_max: tokio::time::Duration,
        stats: ExportedStatRegistry,
        num_db_connections: usize,
    ) -> Result<RemoteDBClientSender, Box<dyn Error>> {
        let (tx, rx) = async_channel::bounded(max_queue);
        let urls = make_db_url(&secrets, false);

        let remote_db_client = RemoteDBClient {
            urls,
            rx,
            retry_time: Duration::from_millis(INITIAL_RETRY_TIME_MS),
            retry_time_max,
            tx: tx.clone(),
            stat_handles: RemoteDBClientStatHandles {
                queue_duration: stats.add_duration_stat(
                    "remotedb_client_queue_delay",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_counters_duration: stats.add_duration_stat(
                    "remotedb_client_store_counters_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_log_duration: stats.add_duration_stat(
                    "remotedb_client_store_log_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_connections_duration: stats.add_duration_stat(
                    "remotedb_client_store_connections_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_network_interface_state_duration: stats.add_duration_stat(
                    "remotedb_client_store_network_interface_state_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_gateway_ping_data_duration: stats.add_duration_stat(
                    "remotedb_client_store_gateway_ping_data_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_dns_entries_duration: stats.add_duration_stat(
                    "remotedb_client_store_dns_entries_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                handle_log_device: stats.add_duration_stat(
                    "remotedb_client_handle_log_device_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
            },
        };

        for id in 0..num_db_connections {
            let client_clone = remote_db_client.clone();
            tokio::spawn(async move {
                client_clone.rx_loop(id).await.unwrap();
            });
        }
        Ok(tx)
    }

    pub fn get_tx(&self) -> RemoteDBClientSender {
        self.tx.clone()
    }

    pub fn get_stat_handles(&self) -> RemoteDBClientStatHandles {
        self.stat_handles.clone()
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

    async fn rx_loop(mut self, id: usize) -> Result<(), Box<dyn Error>> {
        loop {
            info!(
                "DbConn {}: Trying to connect to database server: {}",
                id, self.urls.url_without_auth
            );
            let connector = native_tls::TlsConnector::new()?;
            let connector = postgres_native_tls::MakeTlsConnector::new(connector);

            let (client, connection) = match tokio_postgres::connect(
                &self.urls.url_with_auth,
                connector,
            )
            .await
            {
                Ok((client, connection)) => (client, connection),
                Err(e) => {
                    self.retry_time = std::cmp::min(self.retry_time * 2, self.retry_time_max);
                    warn!(
                        "DbConn {}: Failed to connect to postgres server {} - retrying in {:?} -- error {}", id,
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
                        "DbConn {}: tokio_postgress connection exited with {}... uhmm.. TODO",
                        id, e
                    );
                }
            });
            if let Err(e) =
                Self::inner_loop(self.rx.clone(), &client, self.stat_handles.clone()).await
            {
                warn!(
                    "DbConn {}: RemoteClientDB loop produced error: restarting client: {}",
                    id, e
                );
            }
        }
    }

    pub async fn inner_loop(
        rx: RemoteDBClientReceiver,
        client: &Client,
        mut stat_handles: RemoteDBClientStatHandles,
    ) -> Result<(), tokio_postgres::Error> {
        while let Ok(msg) = rx.recv().await {
            let msg =
                msg.perf_check_get_with_stats("RemoteDBClient", &mut stat_handles.queue_duration);
            use RemoteDBClientMessages::*;
            match &msg {
                StoreCounters {
                    counters,
                    device_uuid,
                    time,
                    os,
                    version,
                } => {
                    // records the time from when it's created to the time it's dropped to the
                    // store_counters_duration StatHandleDuration
                    let _stat_perf_recorder =
                        stat_handles.store_counters_duration.get_raii_recorder();
                    Self::handle_store_counters(client, counters, device_uuid, time, os, version)
                        .await
                }
                StoreLog { .. } => {
                    let _stat_perf_recorder = stat_handles.store_log_duration.get_raii_recorder();
                    Self::handle_store_log(client, msg).await
                }
                StoreConnectionMeasurements {
                    connection_measurements,
                    device_uuid,
                    organization_id,
                    source_type,
                } => {
                    let _stat_perf_recorder =
                        stat_handles.store_connections_duration.get_raii_recorder();
                    Self::handle_store_connection_measurement(
                        client,
                        connection_measurements,
                        None,
                        device_uuid,
                        *organization_id,
                        source_type,
                    )
                    .await
                }
                StoreNetworkInterfaceState {
                    network_interface_state,
                    device_uuid,
                } => {
                    let _stat_perf_recorder = stat_handles
                        .store_network_interface_state_duration
                        .get_raii_recorder();
                    Self::handle_store_network_interface_state(
                        client,
                        network_interface_state,
                        device_uuid,
                    )
                    .await
                }
                StoreGatewayPingData { ping_data } => {
                    let _stat_perf_recorder = stat_handles
                        .store_gateway_ping_data_duration
                        .get_raii_recorder();
                    Self::handle_store_gateway_ping_data(client, ping_data).await
                }
                StoreDnsEntries {
                    dns_entries,
                    device_uuid,
                } => {
                    let _stat_perf_recorder =
                        stat_handles.store_dns_entries_duration.get_raii_recorder();
                    Self::handle_store_dns_entries(client, dns_entries, device_uuid).await
                }
                LogDeviceConnect {
                    device_uuid,
                    organization,
                    description,
                    addr,
                } => {
                    let _stat_perf_recorder = stat_handles.handle_log_device.get_raii_recorder();
                    Self::handle_log_device_connect(
                        client,
                        organization,
                        device_uuid,
                        description,
                        addr,
                    )
                    .await
                }
            }?;
        }
        Ok(())
    }

    pub async fn handle_store_dns_entries(
        client: &Client,
        dns_entries: &[DnsTrackerEntry],
        device_uuid: &Uuid,
    ) -> Result<(), tokio_postgres::error::Error> {
        let sink = client.copy_in(
            &format!("COPY {} (ip, hostname, created, from_ptr_record, rtt_usec, ttl_sec, device_uuid) FROM STDIN BINARY", 
                DNS_ENTRIES_TABLE_NAME))
        .await?;
        let writer = BinaryCopyInWriter::new(
            sink,
            &[
                Type::TEXT,
                Type::TEXT,
                Type::TIMESTAMPTZ,
                Type::BOOL,
                Type::INT8,
                Type::INT8,
                Type::UUID,
            ],
        );
        pin_mut!(writer);
        for entry in dns_entries {
            if let Some(ip) = entry.ip {
                // Old clients don't send an IP. W/o IP it's pointless to add the entry to the DB
                // TODO: add counter of ip is None
                writer
                    .as_mut()
                    .write(&[
                        &ip.to_string(),
                        &entry.hostname,
                        &entry.created,
                        &entry.from_ptr_record,
                        &entry.rtt.map(|rtt| rtt.num_microseconds()),
                        &entry.ttl.map(|ttl| ttl.num_seconds()),
                        &device_uuid,
                    ])
                    .await?;
            }
        }
        writer.finish().await?;
        Ok(())
    }

    pub async fn handle_store_gateway_ping_data(
        client: &Client,
        ping_data: &[AggregatedGatewayPingData],
    ) -> Result<(), tokio_postgres::error::Error> {
        // TODO: do we need a timestamp when the *device* generated the aggregated
        // ping data? Right now we only timestamp in DB insert..... But if we use
        // client timestamps we don't know if they are accurate...
        // I think it's fine as-is
        let statement = client
            .prepare(&format!(
                "INSERT INTO {} (
                network_interface_state_uuid,
                gateway_ip,
                num_probes_sent,
                num_responses_recv,
                rtt_mean_ns,
                rtt_variance_ns,
                rtt_min_ns,
                rtt_p50_ns, 
                rtt_p75_ns,
                rtt_p90_ns,
                rtt_p99_ns,
                rtt_max_ns 
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                AGGREGATED_PING_DATA_TABLE_NAME
            ))
            .await?;

        for ping in ping_data {
            client
                .query(
                    &statement,
                    &[
                        &ping.network_interface_uuid,
                        &ping.gateway_ip.to_string(),
                        &(ping.num_probes_sent as i64),
                        &(ping.num_responses_recv as i64),
                        &(ping.rtt_mean_ns as i64),
                        &ping.rtt_variance_ns.map(|x| x as i64),
                        &(ping.rtt_min_ns as i64),
                        &(ping.rtt_p50_ns as i64),
                        &(ping.rtt_p75_ns as i64),
                        &(ping.rtt_p90_ns as i64),
                        &(ping.rtt_p99_ns as i64),
                        &(ping.rtt_max_ns as i64),
                    ],
                )
                .await?;
        }
        Ok(())
    }

    pub async fn handle_store_network_interface_state(
        client: &Client,
        network_state: &NetworkInterfaceState,
        device_uuid: &Uuid,
    ) -> Result<(), tokio_postgres::error::Error> {
        client
            .execute(
                &format!(
                    "INSERT INTO {} (
                    state_uuid, 
                    gateways, 
                    interface_name, 
                    interface_ips, 
                    comment,
                    has_link, 
                    is_wireless,
                    start_time,
                    end_time, 
                    device_uuid
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                    NETWORK_INTERFACE_STATE_TABLE_NAME
                ),
                &[
                    &network_state.uuid,
                    &network_state
                        .gateways
                        .iter()
                        .map(ToString::to_string)
                        .collect_vec(),
                    &network_state.interface_name,
                    &network_state
                        .interface_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect_vec(),
                    &network_state.comment,
                    &network_state.has_link,
                    &network_state.is_wireless,
                    &network_state.start_time,
                    &network_state.end_time,
                    &device_uuid,
                ],
            )
            .await?;
        Ok(())
    }

    pub async fn handle_store_counters(
        client: &Client,
        counters: &IndexMap<String, u64>,
        device_uuid: &Uuid,
        time: &DateTime<Utc>,
        os: &String,
        version: &String,
    ) -> Result<(), tokio_postgres::error::Error> {
        let sink = client
            .copy_in(&format!(
                "COPY {} (counter, value, device_uuid, time, os, version) FROM STDIN BINARY",
                COUNTERS_TABLE_NAME
            ))
            .await?;
        let writer = BinaryCopyInWriter::new(
            sink,
            &[
                Type::TEXT,
                Type::INT8,
                Type::UUID,
                Type::TIMESTAMPTZ,
                Type::TEXT,
                Type::TEXT,
            ],
        );

        pin_mut!(writer);
        for (c, v) in counters {
            let v_i64 = *v as i64; // TODO: change this conversion once we move to i64 counters
                                   // NOTE: converting DateTime<UTC> to postgres requires the magical 'with-chrono-0_4' feature
            writer
                .as_mut()
                .write(&[c, &v_i64, &device_uuid, &time, &os, &version])
                .await?;
        }
        writer.finish().await?;
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
                format!("INSERT INTO {} (msg, level, device_uuid, time, os, version) VALUES ($1, $2, $3, $4, $5, $6)", LOGS_TABLE_NAME).as_str(),
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
        client: &Client,
        m: &ConnectionMeasurements,
        timestamp: Option<DateTime<Utc>>,
        device_uuid: &Uuid,
        organization_id: OrganizationId,
        source_type: &StorageSourceType,
    ) -> Result<(), tokio_postgres::Error> {
        // store a bunch of more complex members as JSON blobs, for now
        // NOTE: these .unwrap()s are all safe b/c to get here all of the data needs to be
        //  already encoded this way
        let probe_report_summary = serde_json::to_string(&m.probe_report_summary).unwrap();
        let associated_apps = serde_json::to_string(&m.associated_apps).unwrap();
        // annoying; postgresql_tokio doesn't map u64 to BIGINT
        let tx_loss = m.tx_stats.lost_bytes.map(|b| b as i64);
        let rx_loss = m.rx_stats.lost_bytes.map(|b| b as i64);
        let tx_stats = serde_json::to_string(&m.tx_stats).unwrap();
        let rx_stats = serde_json::to_string(&m.rx_stats).unwrap();
        let tx_stats_since_prev_export =
            serde_json::to_string(&m.tx_stats_since_prev_export).unwrap();
        let rx_stats_since_prev_export =
            serde_json::to_string(&m.rx_stats_since_prev_export).unwrap();
        let ts = timestamp.unwrap_or_else(Utc::now);
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
                    device_uuid,
                    source_type,
                    pingtrees,
                    was_evicted,
                    organization,
                    rx_stats_since_prev_export,
                    tx_stats_since_prev_export,
                    prev_export_time,
                    export_count
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 
                        $14, $15, $16, $17, $18, $19 , $20, $21, $22, $23, $24, $25,
                        $26, $27, $28, $29)"#,
                    CONNECTIONS_TABLE_NAME
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
                    &ts,
                    &device_uuid,
                    &source_type.to_string(),
                    &serde_json::to_string(&m.pingtrees).unwrap(),
                    &m.was_evicted,
                    &organization_id,
                    &rx_stats_since_prev_export,
                    &tx_stats_since_prev_export,
                    &m.prev_export_time,
                    &(m.export_count as i64),
                ],
            )
            .await?;
        Ok(())
    }

    //    #[cfg(test)] // do NOT mark this as test only as the integration tests don't compile with 'test' flag (!?)
    pub fn mk_mock(url: &str) -> RemoteDBClient {
        let (tx, rx) = async_channel::bounded(10);
        let stat_registry = ExportedStatRegistry::new("testing", std::time::Instant::now());
        RemoteDBClient {
            urls: MakeDbUrl {
                url_with_auth: url.to_string(),
                url_without_auth: url.to_string(), // mock version shouldn't have a password to protect
            },
            retry_time: Duration::from_millis(INITIAL_RETRY_TIME_MS),
            retry_time_max: Duration::from_secs(10),
            tx,
            rx,
            stat_handles: RemoteDBClientStatHandles {
                queue_duration: stat_registry.add_duration_stat(
                    "test_queue_delay",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_log_duration: stat_registry.add_duration_stat(
                    "test_store_log_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_counters_duration: stat_registry.add_duration_stat(
                    "test_store_counters_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_connections_duration: stat_registry.add_duration_stat(
                    "test_store_connections_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_network_interface_state_duration: stat_registry.add_duration_stat(
                    "test_store_network_interface_state_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_gateway_ping_data_duration: stat_registry.add_duration_stat(
                    "test_store_gateway_ping_data_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                store_dns_entries_duration: stat_registry.add_duration_stat(
                    "test_store_dns_entries_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
                handle_log_device: stat_registry.add_duration_stat(
                    "test_store_dns_entries_duration",
                    Units::Microseconds,
                    [StatType::AVG, StatType::MAX, StatType::COUNT],
                ),
            },
        }
    }

    pub async fn count_remote_counters_rows(
        client: &Client,
    ) -> Result<i64, tokio_postgres::error::Error> {
        let rows = client
            .query(
                format!("SELECT COUNT(*) FROM {}", COUNTERS_TABLE_NAME).as_str(),
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
        client: &Client,
    ) -> Result<i64, tokio_postgres::error::Error> {
        let rows = client
            .query(
                format!("SELECT COUNT(*) FROM {}", LOGS_TABLE_NAME).as_str(),
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
        client: &Client,
    ) -> Result<i64, tokio_postgres::error::Error> {
        let rows = client
            .query(
                format!("SELECT COUNT(*) FROM {}", CONNECTIONS_TABLE_NAME).as_str(),
                &[],
            )
            .await?;
        // NOTE that postgres doesn't seem to have a native u64 type so it uses
        // int8 which maps to a i64 in rust.
        // Why allow negative!?
        let count = rows.first().unwrap().get::<_, i64>(0);
        Ok(count)
    }

    /// A device has just connected to the webserver; check it against the 'devices' table
    /// and if it's not there, create an entry for it.
    ///
    /// Also log this device in the 'device_connections' table to show where it's connected from
    ///
    /// TODO: implement device authentication here and have it return a thumbs up/down for if this device is
    /// authenticated
    pub async fn handle_log_device_connect(
        client: &Client,
        organization: &i64,
        device_uuid: &Uuid,
        description: &str,
        addr: &SocketAddr,
    ) -> Result<(), tokio_postgres::Error> {
        // the 'ON CONFLICT DO NOTHING' says "if this entry already exists, do nothing"
        // this simplifies our logic to insert into the table if this device does not exist
        client
            .query(
                &format!(
                    // UUID is the primary key
                    "INSERT INTO {} (uuid, organization, name, description) 
        VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                    DEVICE_TABLE_NAME
                ),
                &[
                    device_uuid,
                    &organization,
                    &addr.ip().to_string(), // as default 'name'
                    &description,           // as default 'description'
                ],
            )
            .await?;
        Ok(())
    }

    /// Spawn a task for periodic flow aggregation. The task will establish its own DB
    /// connection and will automatically try to reconnect on error (with exponential
    /// backoff). The task will check every 60secs if new flows can be aggregated
    ///
    pub fn spawn_flow_aggregation_task(
        secrets: Secrets,
        retry_time_max: tokio::time::Duration,
        aggregation_bucket_size: chrono::Duration,
    ) {
        tokio::spawn(async move {
            let urls = make_db_url(&secrets, false);
            let id = "(flow_agg)";
            let mut retry_time = tokio::time::Duration::from_millis(INITIAL_RETRY_TIME_MS);
            loop {
                // reconnect loop
                info!(
                    "DbConn {}: Trying to connect to database server: {}",
                    id, urls.url_without_auth
                );
                let connector =
                    native_tls::TlsConnector::new().expect("Failed to create a TLS connector");
                let connector = postgres_native_tls::MakeTlsConnector::new(connector);

                let (mut client, connection) = match tokio_postgres::connect(
                    &urls.url_with_auth,
                    connector,
                )
                .await
                {
                    Ok((client, connection)) => (client, connection),
                    Err(e) => {
                        retry_time = std::cmp::min(retry_time * 2, retry_time_max);
                        warn!(
                        "DbConn {}: Failed to connect to postgres server {} - retrying in {:?} -- error {}", id,
                        urls.url_without_auth, retry_time, e
                    );
                        tokio::time::sleep(retry_time).await;
                        continue;
                    }
                };
                // successful connect, reset retry timer
                retry_time = Duration::from_millis(INITIAL_RETRY_TIME_MS);

                // the tokio_postgres API requires that we spawn a task for the connection
                // so it can handle multiple reads/writes in parallel on the backend
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        // TODO: figure out under what conditions this could exit and see
                        // if we need to be more resilient here
                        warn!(
                            "DbConn {}: tokio_postgress connection exited with {}... uhmm.. TODO",
                            id, e
                        );
                    }
                });

                loop {
                    // inner loop
                    if let Err(e) =
                        do_flow_aggregation(&mut client, aggregation_bucket_size, Utc::now()).await
                    {
                        warn!(
                            "DbConn {}: RemoteClientDB loop produced error: restarting client: {}",
                            id, e
                        );
                        break;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                }
            }
        });
    }
}

///
/// Perform the flow aggregation. All work is done inside a transaction. We first
/// Order of operations:
///    0. Start transaction
///    1. acquire an exlusive lock on `aggregated_connections_lock` to prevent other
///       instances from aggregating at the same time
///    2. Read the timestamp from which we need to start aggregating (from
///       `aggregated_connections_lock` table).
///    3. Check if we have at least one bucket worth of flows to aggregate. If not,
///       return.
///    4. Compute time-window that we need to query (one or more buckets)
///    5. perform read from desktop_connections and aggregate
///    6. Write aggregated flow entries to `aggregated_connections_*` tables.
///    7. Update timestamp in `aggregated_connections_lock` table
///    8. COMMIT the transaction
///
/// This really shouldn't be called from outside this mod, but we want to test
/// it from the integration tests. So, it's `pub`
pub async fn do_flow_aggregation(
    client: &mut Client,
    bucket_size: chrono::Duration,
    now: DateTime<Utc>,
) -> Result<(), RemoteDBClientError> {
    let transaction = client.transaction().await?;
    // make sure only one process can update ==> aqcuire an exlusive lock
    // lock will be released when the transaction ends. Concurrent reads are still
    // allowed in `EXCLUSIVE` mode.
    let lock_res = transaction
        .execute(
            "LOCK TABLE aggregated_connections_lock IN EXCLUSIVE mode NOWAIT",
            &[],
        )
        .await;
    if lock_res.is_err() {
        warn!("Could not acquire lock on table `aggregated_connections_lock` -- is another instance running?");
        return Ok(());
    }
    let next_bucket_time = get_next_bucket_time(&transaction).await?;

    // We only aggregate a full bucket_size worth of flows at a time. In order to make sure we don't have an stragglers
    // in the desktop_connections table, we only start the aggregation if the we are FLOW_AGGREGATION_TIME_GAP_MINUTES
    // after the end of the bucket.
    let max_time = now - chrono::Duration::minutes(FLOW_AGGREGATION_TIME_GAP_MINUTES);
    if next_bucket_time + bucket_size < max_time {
        // We have at least one bucket worth of flows we can aggregate
        let mut end_time = next_bucket_time + bucket_size;
        while end_time + bucket_size < max_time {
            end_time += bucket_size;
        }
        assert!(end_time < max_time);
        let time_range = TimeRangeQueryParams {
            start: Some(next_bucket_time),
            end: Some(end_time),
        };
        info!(
            "Aggregating flows from {} to {}",
            next_bucket_time, end_time
        );
        let agg_buckets =
            query_and_aggregate_flows(transaction.client(), time_range, bucket_size).await?;
        write_aggregated_flows(&transaction, agg_buckets).await?;
        transaction
            .execute(
                "UPDATE aggregated_connections_lock SET next_bucket_start_time = $1",
                &[&end_time],
            )
            .await?;
        transaction.commit().await?;
        info!(
            "Flow aggregation from {} to {} is DONE.",
            next_bucket_time, end_time
        );
    } else {
        // Nothing to do.
        debug!(
            "Flow Aggregation: nothing to aggregate at this time. Next bucket start time is {}",
            next_bucket_time
        );
        transaction.rollback().await?;
    }

    Ok(())
}

/// Take a row from a SELECT * query and convert it into an
/// AggregatedPingData (or rather a tuple of `(insert_time, ping_data, device_uuid)`)
/// TODO: should this be moved to remotedb_client.rs?
pub fn extract_aggregated_ping_data(
    row: &Row,
) -> Result<(DateTime<Utc>, AggregatedGatewayPingData), tokio_postgres::error::Error> {
    Ok((
        row.try_get("time")?,
        AggregatedGatewayPingData {
            network_interface_uuid: row.try_get("network_interface_state_uuid")?,
            gateway_ip: IpAddr::from_str(row.try_get("gateway_ip")?).unwrap(),
            num_probes_sent: row.try_get::<_, i64>("num_probes_sent")? as usize,
            num_responses_recv: row.try_get::<_, i64>("num_responses_recv")? as usize,
            rtt_mean_ns: row.try_get::<_, i64>("rtt_mean_ns")? as u64,
            rtt_variance_ns: row
                .try_get::<_, Option<i64>>("rtt_variance_ns")?
                .map(|x| x as u64),
            rtt_min_ns: row.try_get::<_, i64>("rtt_min_ns")? as u64,
            rtt_p50_ns: row.try_get::<_, i64>("rtt_p50_ns")? as u64,
            rtt_p75_ns: row.try_get::<_, i64>("rtt_p75_ns")? as u64,
            rtt_p90_ns: row.try_get::<_, i64>("rtt_p90_ns")? as u64,
            rtt_p99_ns: row.try_get::<_, i64>("rtt_p99_ns")? as u64,
            rtt_max_ns: row.try_get::<_, i64>("rtt_max_ns")? as u64,
        },
    ))
}

/// Get the value from `aggregated_connections_lock.next_bucket_start_time`. I.e.,
/// the time after which we do NOT yet have aggregated flow data
pub async fn get_next_bucket_time<C: GenericClient>(
    generic_client: &C,
) -> Result<DateTime<Utc>, RemoteDBClientError> {
    let next_bucket_time_rows = generic_client
        .query(
            "SELECT next_bucket_start_time FROM aggregated_connections_lock",
            &[],
        )
        .await?;
    assert_eq!(
        next_bucket_time_rows.len(),
        1,
        "Invalid number of rows in next_bucket_start_time -- expected exactly 1"
    );
    Ok(next_bucket_time_rows.first().unwrap().try_get(0)?)
}

/*
 * No unit tests here, but added a bunch of integration tests in webserver/tests/test_remotedb_client.rs
 *
 * Open to feedback if they should be here or there, but IMHO since we're dynamically downloading an instance of postgres
 * and starting it up/tearing it down, it's not longer a 'unit' test.
 */
