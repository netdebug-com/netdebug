use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use common_wasm::ProbeReportSummary;
use futures::{pin_mut, StreamExt};
use itertools::Itertools;
use libconntrack_wasm::{ConnectionKey, ConnectionMeasurements, IpProtocol};
use tokio_postgres::{
    binary_copy::{BinaryCopyOutRow, BinaryCopyOutStream},
    types::{FromSql, Type},
    Client,
};
use uuid::Uuid;

use crate::{
    devices::DeviceInfo, remotedb_client::RemoteDBClientError, rest_routes::TimeRangeQueryParams,
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

/// Keeps track column names, types, and a column name-to-index mapping to make
/// `COPY TO` queries easier.
struct FlowQueryHelper {
    col_names: Vec<String>,
    col_types: Vec<Type>,
    col_to_idx: HashMap<String, usize>,
}

impl FlowQueryHelper {
    fn new(columns: Vec<(&str, Type)>) -> Self {
        let mut col_to_idx = HashMap::with_capacity(columns.len());
        let mut col_names = Vec::with_capacity(columns.len());
        let mut col_types = Vec::with_capacity(columns.len());
        for (idx, (name, typ)) in columns.iter().enumerate() {
            col_to_idx.insert(name.to_string(), idx);
            col_types.push(typ.clone());
            col_names.push(name.to_string());
        }
        // Make sure we have every column name only once
        assert_eq!(columns.len(), col_to_idx.len());
        FlowQueryHelper {
            col_names,
            col_types,
            col_to_idx,
        }
    }

    /// Wrapper function around `BinaryCopyOutRow::get` that allows us to use column names
    /// instead of column indicies
    fn get<'a, T>(&self, row: &'a BinaryCopyOutRow, col: &str) -> Result<T, RemoteDBClientError>
    where
        T: FromSql<'a>,
    {
        let idx = *self
            .col_to_idx
            .get(col)
            .ok_or(RemoteDBClientError::NoSuchColumn {
                col_name: col.to_string(),
            })?;
        Ok(row.try_get(idx)?)
    }

    fn columns_names(&self) -> String {
        self.col_names.iter().join(", ")
    }

    fn col_types(&self) -> &[Type] {
        &self.col_types
    }
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
    let mut cols = vec![
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
    ];
    for extra_col in extra_columns {
        cols.push(extra_col.col_info());
    }
    let helper = FlowQueryHelper::new(cols);

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
        let key = ConnectionKey {
            local_ip: IpAddr::from_str(helper.get(&row, "local_ip")?)?,
            remote_ip: IpAddr::from_str(helper.get(&row, "remote_ip")?)?,
            local_l4_port: helper.get::<i32>(&row, "local_port")? as u16,
            remote_l4_port: helper.get::<i32>(&row, "remote_port")? as u16,
            ip_proto: IpProtocol::from_wire(helper.get::<i16>(&row, "ip_protocol")? as u8),
        };
        measurements.push(ConnectionMeasurements {
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
        });
    }
    Ok(measurements)
}
