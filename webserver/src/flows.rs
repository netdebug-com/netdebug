use std::{net::IpAddr, str::FromStr, sync::Arc};

use common_wasm::ProbeReportSummary;
use futures::{pin_mut, StreamExt};
use libconntrack_wasm::{ConnectionKey, ConnectionMeasurements, IpProtocol, TrafficStatsSummary};
use tokio_postgres::{
    binary_copy::{BinaryCopyOutRow, BinaryCopyOutStream},
    types::Type,
    Client,
};
use uuid::Uuid;

use crate::{
    db_utils::CopyOutQueryHelper, db_utils::TimeRangeQueryParams, devices::DeviceInfo,
    remotedb_client::RemoteDBClientError, users::NetDebugUser,
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

const DEFAULT_COLUMNS: [(&str, Type); 22] = [
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

fn get_flow_query_helper(extra_columns: &[FlowQueryExtraColumns]) -> CopyOutQueryHelper {
    let mut cols = DEFAULT_COLUMNS.to_vec();
    for extra_col in extra_columns {
        cols.push(extra_col.col_info());
    }
    CopyOutQueryHelper::new(cols)
}

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
