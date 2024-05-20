use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use chrono::{DateTime, Utc};
use common_wasm::ProbeReportSummary;
use futures::{pin_mut, StreamExt};
use gui_types::OrganizationId;
use libconntrack_wasm::{ConnectionKey, ConnectionMeasurements, IpProtocol, TrafficStatsSummary};
use serde::{Deserialize, Serialize};
use tokio_postgres::{
    binary_copy::{BinaryCopyOutRow, BinaryCopyOutStream},
    types::{ToSql, Type},
    Client, Row, Transaction,
};
use uuid::Uuid;

use crate::{
    db_utils::{make_where_clause, CopyOutQueryHelper, TimeRangeQueryParams},
    devices::DeviceInfo,
    flow_aggregation::{
        AggregatedBucket, AggregatedConnectionMeasurement, BucketAggregator,
        AGGREGATION_BUCKET_SIZE_MINUTES,
    },
    organizations::NETDEBUG_EMPLOYEE_ORG_ID,
    remotedb_client::{get_next_bucket_time, RemoteDBClientError},
    users::NetDebugUser,
};

/// These `desktop_connections` columns can be fairly large, so we make retrieving them in a
/// query optional
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlowQueryExtraColumns {
    ProbeReportSummary,
    Pingtrees,
}

impl FlowQueryExtraColumns {
    pub fn col_info(&self) -> (&'static str, Type) {
        let col_name = match self {
            FlowQueryExtraColumns::ProbeReportSummary => "probe_report_summary",
            FlowQueryExtraColumns::Pingtrees => "pingtrees",
        };
        (col_name, Type::TEXT)
    }
}

// The columns from desktop_connections table that we always want to query,
// with their Postgres type. We use it to facilitate nicer column access for
// COPY OUT queries. See `copy_out_row_to_measurement()` and `CopyOutQueryHelper`
const DEFAULT_COLUMNS: [(&str, Type); 23] = [
    ("time", Type::TIMESTAMPTZ),
    ("local_ip", Type::TEXT),
    ("remote_ip", Type::TEXT),
    ("local_port", Type::INT4),
    ("remote_port", Type::INT4),
    ("ip_protocol", Type::INT2),
    ("local_hostname", Type::TEXT),
    ("remote_hostname", Type::TEXT),
    ("user_annotation", Type::TEXT),
    ("user_agent", Type::TEXT),
    ("associated_apps", Type::TEXT),
    ("close_has_started", Type::BOOL),
    ("four_way_close_done", Type::BOOL),
    ("start_tracking_time", Type::TIMESTAMPTZ),
    ("last_packet_time", Type::TIMESTAMPTZ),
    ("device_uuid", Type::UUID),
    ("was_evicted", Type::BOOL),
    ("tx_stats", Type::TEXT),
    ("rx_stats", Type::TEXT),
    ("rx_stats_since_prev_export", Type::TEXT),
    ("tx_stats_since_prev_export", Type::TEXT),
    ("prev_export_time", Type::TIMESTAMPTZ),
    ("export_count", Type::INT8),
];

/// The columns common across all of the `aggregated_connections_*` table.
/// (The ..._total table only has these columns_
const AGGREGATED_CONNS_COMMON_COLUMNS: [&str; 19] = [
    "bucket_start_time",
    "bucket_size_minutes",
    "device_uuid",
    "organization",
    "num_flows",
    "num_flows_with_rx_loss",
    "num_flows_with_tx_loss",
    "num_tcp_flows",
    "num_udp_flows",
    "rx_packets",
    "tx_packets",
    "rx_bytes",
    "tx_bytes",
    "rx_lost_bytes",
    "tx_lost_bytes",
    "tcp_rx_bytes",
    "tcp_tx_bytes",
    "udp_rx_bytes",
    "udp_tx_bytes",
];

/// convert an aggregated_connection_measurement into a list of parameters
/// to pass to `::execute()`. The order here must match the order in
/// AGGREGATED_CONNS_COMMON_COLUMNS.
/// In addition we add anything in extra_vals to the end of the parameter list
fn aggregated_flow_to_sql_params<'a>(
    bucket_start: &'a DateTime<Utc>,
    bucket_size_minutes: &'a i64,
    agg: &'a AggregatedConnectionMeasurement,
    // TODO: for extra_vals I really just wanted an `Option<&str>` or `Option<String>` but
    // I lost my battle with the borrow checker. So Vec it is.
    extra_vals: &'a [&'a str],
) -> Vec<&'a (dyn ToSql + Sync)> {
    let mut params: Vec<&'a (dyn ToSql + Sync)> = Vec::with_capacity(20);

    params.push(bucket_start);
    params.push(bucket_size_minutes);
    params.push(&agg.device_uuid);
    params.push(&agg.organization_id);
    params.push(&agg.num_flows);
    params.push(&agg.num_flows_with_rx_loss);
    params.push(&agg.num_flows_with_tx_loss);
    params.push(&agg.num_tcp_flows);
    params.push(&agg.num_udp_flows);

    params.push(&agg.rx_packets);
    params.push(&agg.tx_packets);
    params.push(&agg.rx_bytes);
    params.push(&agg.tx_bytes);
    params.push(&agg.rx_lost_bytes);
    params.push(&agg.tx_lost_bytes);

    params.push(&agg.tcp_rx_bytes);
    params.push(&agg.tcp_tx_bytes);
    params.push(&agg.udp_rx_bytes);
    params.push(&agg.udp_tx_bytes);
    for extra in extra_vals {
        params.push(extra);
    }

    params
}

fn get_flow_query_helper(extra_columns: &[FlowQueryExtraColumns]) -> CopyOutQueryHelper {
    let mut cols = DEFAULT_COLUMNS.to_vec();
    for extra_col in extra_columns {
        cols.push(extra_col.col_info());
    }
    CopyOutQueryHelper::new(cols)
}

// Extract a ConnectionMeasurement from a given COPY OUT row.
fn copy_out_row_to_measurement(
    helper: &CopyOutQueryHelper,
    row: BinaryCopyOutRow,
) -> Result<ConnectionMeasurements, RemoteDBClientError> {
    let key = ConnectionKey {
        local_ip: IpAddr::from_str(helper.get(&row, "local_ip")?)?,
        remote_ip: IpAddr::from_str(helper.get(&row, "remote_ip")?)?,
        local_l4_port: helper.get::<i32>(&row, "local_port")? as u16,
        remote_l4_port: helper.get::<i32>(&row, "remote_port")? as u16,
        ip_proto: IpProtocol::from_wire(helper.get::<i16>(&row, "ip_protocol")? as u8),
    };
    Ok(ConnectionMeasurements {
        key,
        local_hostname: helper.get(&row, "local_hostname")?,
        remote_hostname: helper.get(&row, "remote_hostname")?,
        // probe_report_summary is optional so we gracefully handle it if get() fails
        probe_report_summary: helper
            .get::<&str>(&row, "probe_report_summary")
            .map(serde_json::from_str)
            .unwrap_or_else(|_| Ok(ProbeReportSummary::new()))?,
        user_annotation: helper.get(&row, "user_annotation")?,
        user_agent: helper.get(&row, "user_agent")?,
        associated_apps: serde_json::from_str(helper.get(&row, "associated_apps")?)?,
        close_has_started: helper.get(&row, "close_has_started")?,
        four_way_close_done: helper.get(&row, "four_way_close_done")?,
        start_tracking_time: helper.get(&row, "start_tracking_time")?,
        last_packet_time: helper.get(&row, "last_packet_time")?,
        rx_stats: serde_json::from_str(helper.get::<&str>(&row, "rx_stats")?)?,
        tx_stats: serde_json::from_str(helper.get::<&str>(&row, "tx_stats")?)?,
        // pingtrees is optional so we gracefully handle it if get() fails
        pingtrees: helper
            .get::<&str>(&row, "pingtrees")
            .map(serde_json::from_str)
            .unwrap_or_else(|_| Ok(Vec::default()))?,
        was_evicted: helper.get(&row, "was_evicted")?,
        rx_stats_since_prev_export: helper
            .get::<Option<&str>>(&row, "rx_stats_since_prev_export")?
            .map_or(Ok(TrafficStatsSummary::default()), serde_json::from_str)?,
        tx_stats_since_prev_export: helper
            .get::<Option<&str>>(&row, "tx_stats_since_prev_export")?
            .map_or(Ok(TrafficStatsSummary::default()), serde_json::from_str)?,
        prev_export_time: helper.get(&row, "prev_export_time")?,
        export_count: helper.get::<i64>(&row, "export_count")? as u64,
    })
}

/// Query the Database for all flow from a particular device_uuid and return the results
/// as a vector of ConnectionMeasurements.
///
/// The function verifies that the given user is allowed to see/query the given device.
/// The query can be narrowed to a particular time range (based on the `time` column).
/// By default, `probe_report_summary` and `pingtrees` are **NOT** returned, since they add
/// a substantial amount of bytes. However, they can be requested with `extra_columns`
pub async fn flow_queries(
    client: Arc<Client>,
    user: &NetDebugUser,
    device_uuid: Uuid,
    time_range: TimeRangeQueryParams,
    extra_columns: &[FlowQueryExtraColumns],
) -> Result<Vec<ConnectionMeasurements>, RemoteDBClientError> {
    // NOTE: we use the DeviceInfo as our permission checks. If the user is allowed to see
    // the device we get a Some(device) back.
    // In order to speed things up, we fetch the device and start the copy_out() in parallel,
    // but we check the device / permission before we read the actual rows
    let device_future = DeviceInfo::from_uuid(device_uuid, user, client.clone());

    let mut time_range_where = time_range.to_sql_where();
    if !time_range_where.is_empty() {
        time_range_where.insert_str(0, "AND ");
    }

    let helper = get_flow_query_helper(extra_columns);

    // Note, COPY TO does not support placeholders. But it's safe to pass the UUID in a format
    // string, since we use the uuid class (and not a raw string), so the uuid format is guranteed
    let query = format!(
        "COPY (SELECT {}
        FROM desktop_connections WHERE device_uuid='{}' {} ORDER BY TIME ASC) TO STDOUT BINARY",
        helper.columns_names(),
        device_uuid,
        time_range_where
    );

    let copy_out_fut = client.copy_out(&query);

    let (device, copy_out) = futures::join!(device_future, copy_out_fut);
    let device = device?;
    let copy_out = copy_out?;

    // If we have a device, we know the user is allowed to see it. So it's safe to
    // query for this device now.
    if device.is_none() {
        // TODO: maybe return a permission error instead?
        return Ok(Vec::new());
    }

    let reader = BinaryCopyOutStream::new(copy_out, helper.col_types());
    pin_mut!(reader);
    let mut measurements = Vec::new();
    while let Some(maybe_row) = reader.next().await {
        let row = maybe_row?;
        measurements.push(copy_out_row_to_measurement(&helper, row)?);
    }
    Ok(measurements)
}

/// Query the desktop_connections table for the given timerange, and aggregate
/// all flows.
/// This function does not do any permission checks all will always query all
/// flows from all devices/orgs
pub async fn query_and_aggregate_flows(
    client: &Client,
    time_range: TimeRangeQueryParams,
    aggregate_bucket_size: chrono::Duration,
) -> Result<Vec<AggregatedBucket>, RemoteDBClientError> {
    // We need to query for the `time` column here. start_tracking_time and last_packet_time
    // are created/derived from the client/device but `time` is server-side
    let mut time_range_where = time_range.to_sql_where_with_keys("time", "time");
    if !time_range_where.is_empty() {
        time_range_where.insert_str(0, "WHERE ");
    }
    let helper = get_flow_query_helper(&[]);

    // Note, COPY TO does not support placeholders. But it's safe to pass the UUID in a format
    // string, since we use the uuid class (and not a raw string), so the uuid format is guranteed
    let query = format!(
        "COPY (SELECT {}
        FROM desktop_connections {} ORDER BY TIME ASC) TO STDOUT BINARY",
        helper.columns_names(),
        time_range_where
    );
    let mut aggregator = BucketAggregator::new(aggregate_bucket_size);
    let copy_out_fut = client.copy_out(&query);
    let superuser = NetDebugUser::make_internal_superuser();
    let device_list_fut = DeviceInfo::get_devices(&superuser, None, client);
    let (device_list, copy_out) = futures::join!(device_list_fut, copy_out_fut);

    let mut device_to_org = HashMap::new();
    for dev in device_list? {
        device_to_org.insert(dev.uuid, dev.organization_id);
    }

    let reader = BinaryCopyOutStream::new(copy_out?, helper.col_types());
    pin_mut!(reader);
    while let Some(maybe_row) = reader.next().await {
        let row = maybe_row?;
        let ts: DateTime<Utc> = helper.get(&row, "time")?;
        let device_uuid: Uuid = helper.get(&row, "device_uuid")?;
        let org_id = *device_to_org
            .get(&device_uuid)
            .unwrap_or(&NETDEBUG_EMPLOYEE_ORG_ID);
        let m = copy_out_row_to_measurement(&helper, row)?;
        aggregator.add(ts, device_uuid, org_id, &m);
    }
    Ok(aggregator.to_vec())
}

/// Write aggregated flows to the DB. All inserts are performed insided the
/// given transaction. It's the caller's responsibility to `commit` the transaction
pub async fn write_aggregated_flows(
    transaction: &Transaction<'_>,
    buckets: Vec<AggregatedBucket>,
) -> Result<(), RemoteDBClientError> {
    let query_total = format!(
        "INSERT INTO aggregated_connections_total ({}) VALUES ($1, $2, $3, $4, $5,
               $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)",
        AGGREGATED_CONNS_COMMON_COLUMNS.join(", ")
    );
    let query_by_app = format!(
        "INSERT INTO aggregated_connections_by_application ({}, application) VALUES ($1, $2, $3, $4, $5,
               $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)",
        AGGREGATED_CONNS_COMMON_COLUMNS.join(", ")
    );
    let query_by_dest = format!(
        "INSERT INTO aggregated_connections_by_dest ({}, dns_dest_domain) VALUES ($1, $2, $3, $4, $5,
               $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)",
        AGGREGATED_CONNS_COMMON_COLUMNS.join(", ")
    );
    // use futures::join to execute these in parallel (i.e., pipelined)
    let (stmt_total, stmt_by_app, stmt_by_dest) = futures::join!(
        transaction.prepare(&query_total),
        transaction.prepare(&query_by_app),
        transaction.prepare(&query_by_dest),
    );
    let stmt_total = stmt_total?;
    let stmt_by_app = stmt_by_app?;
    let stmt_by_dest = stmt_by_dest?;
    for bucket in buckets {
        for per_device in bucket.aggregate.values() {
            transaction
                .execute(
                    &stmt_total,
                    &aggregated_flow_to_sql_params(
                        &bucket.bucket_start,
                        &bucket.bucket_size.num_minutes(),
                        &per_device.total,
                        &[],
                    ),
                )
                .await?;
            for (application, entry) in &per_device.by_app {
                transaction
                    .execute(
                        &stmt_by_app,
                        &aggregated_flow_to_sql_params(
                            &bucket.bucket_start,
                            &bucket.bucket_size.num_minutes(),
                            entry,
                            &[application],
                        ),
                    )
                    .await?;
            }
            for (dst_domain, entry) in &per_device.by_dns_dest_domain {
                transaction
                    .execute(
                        &stmt_by_dest,
                        &aggregated_flow_to_sql_params(
                            &bucket.bucket_start,
                            &bucket.bucket_size.num_minutes(),
                            entry,
                            &[dst_domain],
                        ),
                    )
                    .await?;
            }
        }
    }

    Ok(())
}

#[derive(Eq, Debug, PartialEq, Hash, Serialize, Deserialize)]
#[serde(tag = "tag", content = "name")]
pub enum AggregatedFlowCategory {
    Total,
    ByApp(String),
    ByDnsDestDomain(String),
}

/// Represents one row of aggregated flows / connection measurements
/// from the DB.
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct AggregatedFlowRow {
    pub bucket_start: DateTime<Utc>,
    pub bucket_size: chrono::Duration,
    pub category: AggregatedFlowCategory,
    pub aggregate: AggregatedConnectionMeasurement,
}

pub fn row_to_aggregated_connection_measurement(
    row: &Row,
) -> Result<AggregatedConnectionMeasurement, RemoteDBClientError> {
    Ok(AggregatedConnectionMeasurement {
        device_uuid: row.try_get::<_, Uuid>("device_uuid")?,
        organization_id: row.try_get("organization")?,
        num_flows: row.try_get("num_flows")?,
        num_flows_with_rx_loss: row.try_get("num_flows_with_rx_loss")?,
        num_flows_with_tx_loss: row.try_get("num_flows_with_tx_loss")?,
        num_tcp_flows: row.try_get("num_tcp_flows")?,
        num_udp_flows: row.try_get("num_udp_flows")?,
        rx_packets: row.try_get("rx_packets")?,
        tx_packets: row.try_get("tx_packets")?,
        rx_bytes: row.try_get("rx_bytes")?,
        tx_bytes: row.try_get("tx_bytes")?,
        rx_lost_bytes: row.try_get("rx_lost_bytes")?,
        tx_lost_bytes: row.try_get("tx_lost_bytes")?,
        tcp_rx_bytes: row.try_get("tcp_rx_bytes")?,
        tcp_tx_bytes: row.try_get("tcp_tx_bytes")?,
        udp_rx_bytes: row.try_get("udp_rx_bytes")?,
        udp_tx_bytes: row.try_get("udp_tx_bytes")?,
    })
}

/// Returns `(bucket_start, bucket_size)` of the given row
fn row_to_aggregated_bucket_info(
    row: &Row,
) -> Result<(DateTime<Utc>, chrono::Duration), RemoteDBClientError> {
    Ok((
        row.try_get("bucket_start_time")?,
        chrono::Duration::minutes(row.try_get("bucket_size_minutes")?),
    ))
}

/// Query the DB for aggregated flows
/// If org_id is None, all organazations are queried, it if
/// `Some(id)` only the given org_id is queried. This functions
/// checks if the `user` is allowed to access the requested org(s).
/// If not a Permission error is returned.
pub async fn query_aggregated_flow_tables(
    user: &NetDebugUser,
    org_id: Option<OrganizationId>,
    time_range: TimeRangeQueryParams,
    client: &Client,
) -> Result<Vec<AggregatedFlowRow>, RemoteDBClientError> {
    user.check_org_allowed_or_fail(org_id)?;

    let org_id_term = if let Some(org_id) = org_id {
        format!("organization = {}", org_id)
    } else {
        String::new()
    };
    let time_range_term =
        time_range.to_sql_where_with_keys("bucket_start_time", "bucket_start_time");
    let where_clause = make_where_clause(&[&org_id_term, &time_range_term]);

    let query_total = format!(
        "SELECT {} FROM aggregated_connections_total {}",
        AGGREGATED_CONNS_COMMON_COLUMNS.join(", "),
        where_clause
    );
    let query_by_app = format!(
        "SELECT {}, application FROM aggregated_connections_by_application {}",
        AGGREGATED_CONNS_COMMON_COLUMNS.join(", "),
        where_clause
    );
    let query_by_dest = format!(
        "SELECT {}, dns_dest_domain FROM aggregated_connections_by_dest {}",
        AGGREGATED_CONNS_COMMON_COLUMNS.join(", "),
        where_clause
    );

    let (total_rows, by_app_rows, by_dest_rows) = futures::join!(
        client.query(&query_total, &[]),
        client.query(&query_by_app, &[]),
        client.query(&query_by_dest, &[]),
    );

    let mut out = Vec::new();
    for row in total_rows? {
        let entry = row_to_aggregated_connection_measurement(&row)?;
        let (bucket_start, bucket_size) = row_to_aggregated_bucket_info(&row)?;
        out.push(AggregatedFlowRow {
            bucket_start,
            bucket_size,
            category: AggregatedFlowCategory::Total,
            aggregate: entry,
        });
    }
    for row in by_app_rows? {
        let (bucket_start, bucket_size) = row_to_aggregated_bucket_info(&row)?;
        let application: String = row.try_get("application")?;
        let entry = row_to_aggregated_connection_measurement(&row)?;
        out.push(AggregatedFlowRow {
            bucket_start,
            bucket_size,
            category: AggregatedFlowCategory::ByApp(application),
            aggregate: entry,
        });
    }
    for row in by_dest_rows? {
        let (bucket_start, bucket_size) = row_to_aggregated_bucket_info(&row)?;
        let dns_dest_domain: String = row.try_get("dns_dest_domain")?;
        let entry = row_to_aggregated_connection_measurement(&row)?;
        out.push(AggregatedFlowRow {
            bucket_start,
            bucket_size,
            category: AggregatedFlowCategory::ByDnsDestDomain(dns_dest_domain),
            aggregate: entry,
        });
    }

    Ok(out)
}

// TODO: add option to only query for one or some of the aggegration
// categories instead of all of them
pub async fn get_aggregated_flow_view(
    user: &NetDebugUser,
    org_id: Option<OrganizationId>,
    time_range: TimeRangeQueryParams,
    client: &Client,
) -> Result<Vec<AggregatedFlowRow>, RemoteDBClientError> {
    user.check_org_allowed_or_fail(org_id)?;
    let next_bucket_time = get_next_bucket_time(client).await?;

    let agg_rows_fut = query_aggregated_flow_tables(
        user,
        org_id,
        TimeRangeQueryParams {
            start: time_range.start,
            end: Some(next_bucket_time),
        },
        client,
    );
    let from_raw_fut = query_and_aggregate_flows(
        client,
        TimeRangeQueryParams {
            start: Some(next_bucket_time),
            end: time_range.end,
        },
        chrono::Duration::minutes(AGGREGATION_BUCKET_SIZE_MINUTES),
    );
    let (agg_rows, from_raw) = futures::join!(agg_rows_fut, from_raw_fut);
    let mut agg_rows = agg_rows?;

    for bucket in from_raw? {
        for by_category in bucket.aggregate.into_values() {
            if let Some(org_id) = org_id {
                if by_category.organization_id != org_id {
                    continue;
                }
            }
            agg_rows.push(AggregatedFlowRow {
                bucket_start: bucket.bucket_start,
                bucket_size: bucket.bucket_size,
                category: AggregatedFlowCategory::Total,
                aggregate: by_category.total,
            });
            for (app_name, entry) in by_category.by_app.into_iter() {
                agg_rows.push(AggregatedFlowRow {
                    bucket_start: bucket.bucket_start,
                    bucket_size: bucket.bucket_size,
                    category: AggregatedFlowCategory::ByApp(app_name),
                    aggregate: entry,
                });
            }
            for (dns_dst_domain, entry) in by_category.by_dns_dest_domain.into_iter() {
                agg_rows.push(AggregatedFlowRow {
                    bucket_start: bucket.bucket_start,
                    bucket_size: bucket.bucket_size,
                    category: AggregatedFlowCategory::ByDnsDestDomain(dns_dst_domain),
                    aggregate: entry,
                });
            }
        }
    }

    Ok(agg_rows)
}
