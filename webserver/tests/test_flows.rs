use std::{collections::HashSet, sync::Arc};

use axum::{
    body::Body,
    http::{Response, StatusCode},
};
use chrono::{DateTime, Timelike, Utc};
#[cfg(test)]
use common::init::netdebug_test_init;
use common_wasm::ProbeReportSummary;
use db_test_utils::{add_fake_connection_logs_for_flow_query_test, get_alice_dev1_uuid};

use libconntrack_wasm::ConnectionMeasurements;
use libwebserver::{db_utils::TimeRangeQueryParams, flows::query_and_aggregate_flows};
use libwebserver::{
    flows::{flow_queries, FlowQueryExtraColumns},
    remotedb_client::RemoteDBClient,
    users::NetDebugUser,
};
use pg_embed::postgres::PgEmbed;
use tokio_postgres::Client;

use crate::db_test_utils::{
    add_fake_connection_logs, add_fake_devices, add_fake_users, get_auth_token_from_rest_router,
    get_resp_from_rest_router, make_mock_protected_routes, mk_test_db, response_to_bytes,
};

pub mod db_test_utils;

// there are unused fields in this struct that I think we'll want need at some point, so
// lets allows dead_code to stop the compiler from complaining about them
#[allow(dead_code)]
struct FlowTestFixture {
    db_client: Arc<Client>,
    test_db: PgEmbed,
    remotedb_client: RemoteDBClient,
    protected_routes: axum::Router,
    session_token: Option<String>,
    expected_measurement: ConnectionMeasurements,
    /// The timestamp just before we start adding connection measurements to the DB.
    /// All these timestamps can be used for time based DB queries.
    before_connections_time: DateTime<Utc>,
    /// Time between adding "add_fake_devices" and "add_fake_connection_logs"
    between_connections_time: DateTime<Utc>,
    /// Time after adding thbe last connection measurements to DB.
    after_connections_time: DateTime<Utc>,
}

impl FlowTestFixture {
    async fn new() -> Self {
        netdebug_test_init();
        let db_name = format!("flow_test_fixture_{}", rand::random::<u16>());
        let (db_client, test_db) = mk_test_db(&db_name).await.unwrap();
        let remotedb_client = RemoteDBClient::mk_mock(&test_db.db_uri);
        remotedb_client
            .create_table_schema(&db_client)
            .await
            .unwrap();
        add_fake_users(&db_client).await;
        let before_connections_time = Utc::now();
        add_fake_devices(&db_client).await;
        add_fake_connection_logs(&db_client).await.unwrap();
        // lets add a sleep to make extra-sure we have a time-gap between the `time` column
        // that gets written into the DB for `add_fake_connection_logs()` and the one for
        // `add_fake_connection_logs_for_flow_query_test()`, since postgres runs in a different
        // process. (In theory it shouln't be necessary since the write/INSERT should block until the
        // data is committed, but the sleep makes extra sure)
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let between_connections_time = Utc::now();
        let expected_measurement = add_fake_connection_logs_for_flow_query_test(&db_client)
            .await
            .unwrap();
        // Similar to the sleep above, make sure we have a time gap between the `time` column for
        // `add_fake_connection_logs_for_flow_query_test()` and the `after_connections_time` timestamp
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let protected_routes = make_mock_protected_routes(&test_db).await;
        let after_connections_time = Utc::now();
        Self {
            db_client: Arc::new(db_client),
            test_db,
            remotedb_client,
            protected_routes,
            session_token: None,
            expected_measurement,
            before_connections_time,
            between_connections_time,
            after_connections_time,
        }
    }

    async fn authenticate(&mut self) {
        self.session_token =
            Some(get_auth_token_from_rest_router(self.protected_routes.clone(), "Alice").await);
    }

    async fn get_resp_from_rest_router(&self, path: &str) -> Response<Body> {
        assert!(self.session_token.is_some(), "Not authenticated");
        get_resp_from_rest_router(
            self.protected_routes.clone(),
            path,
            self.session_token.as_ref().unwrap(),
        )
        .await
    }
}

fn truncate_nanos(ts: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(ts.timestamp_micros()).unwrap()
}

#[tokio::test]
async fn test_device_flows_rest() {
    let mut fix = FlowTestFixture::new().await;

    let device_uuid = get_alice_dev1_uuid();
    let url = format!("/get_device_flows/{}", device_uuid);
    // first try with an invalid auth token
    let resp = get_resp_from_rest_router(fix.protected_routes.clone(), &url, "JOEMAMA").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    fix.authenticate().await;

    // now get an valid auth token and try again
    let resp = fix.get_resp_from_rest_router(&url).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_to_bytes(resp).await;
    let measurements: Vec<ConnectionMeasurements> = serde_json::from_slice(&body).unwrap();
    assert_eq!(measurements.len(), 3);
    let mut expected_local_ports = HashSet::from([6667, 4242, 12345]);
    for m in &measurements {
        expected_local_ports.remove(&m.key.local_l4_port);
        if m.key.local_l4_port == 4242 {
            let mut expected = fix.expected_measurement.clone();
            // We don't query for probe_report_summary or pingtrees
            // first sanity check
            assert!(!expected.pingtrees.is_empty());
            assert!(!expected.probe_report_summary.raw_reports.is_empty());
            expected.pingtrees.clear();
            expected.probe_report_summary = ProbeReportSummary::new();
            expected.start_tracking_time = truncate_nanos(expected.start_tracking_time);
            expected.last_packet_time = truncate_nanos(expected.last_packet_time);
            expected.prev_export_time = expected.prev_export_time.map(truncate_nanos);
            assert_eq!(m, &expected);
        }
    }

    // repeat query with a time-range
    let url = format!(
        "/get_device_flows/{}?start={}",
        device_uuid,
        fix.between_connections_time
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
    );
    let resp = fix.get_resp_from_rest_router(&url).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_to_bytes(resp).await;
    let measurements: Vec<ConnectionMeasurements> = serde_json::from_slice(&body).unwrap();
    assert_eq!(measurements.len(), 1);
    assert_eq!(measurements.first().unwrap().key.local_l4_port, 4242);

    // repeat query with a time-range
    let url = format!(
        "/get_device_flows/{}?end={}",
        device_uuid,
        fix.between_connections_time
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
    );
    let resp = fix.get_resp_from_rest_router(&url).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_to_bytes(resp).await;
    let measurements: Vec<ConnectionMeasurements> = serde_json::from_slice(&body).unwrap();
    assert_eq!(measurements.len(), 2);
    assert_ne!(measurements[0].key.local_l4_port, 4242);
    assert_ne!(measurements[1].key.local_l4_port, 4242);
}

#[tokio::test]
async fn test_device_flows_sql() {
    let fix = FlowTestFixture::new().await;

    let device_uuid = get_alice_dev1_uuid();
    let user = NetDebugUser::make_internal_superuser();

    let measurements = flow_queries(
        fix.db_client.clone(),
        &user,
        device_uuid,
        TimeRangeQueryParams::default(),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(measurements.len(), 3);
    let mut expected_local_ports = HashSet::from([6667, 4242, 12345]);
    for m in &measurements {
        expected_local_ports.remove(&m.key.local_l4_port);
        if m.key.local_l4_port == 4242 {
            let mut expected = fix.expected_measurement.clone();
            // We don't query for probe_report_summary or pingtrees
            // first sanity check
            assert!(!expected.pingtrees.is_empty());
            assert!(!expected.probe_report_summary.raw_reports.is_empty());
            expected.pingtrees.clear();
            expected.probe_report_summary = ProbeReportSummary::new();
            expected.start_tracking_time = truncate_nanos(expected.start_tracking_time);
            expected.last_packet_time = truncate_nanos(expected.last_packet_time);
            expected.prev_export_time = expected.prev_export_time.map(truncate_nanos);
            assert_eq!(m, &expected);
        }
    }

    // repeat query with a time-range
    let measurements = flow_queries(
        fix.db_client.clone(),
        &user,
        device_uuid,
        TimeRangeQueryParams {
            start: Some(fix.between_connections_time),
            end: None,
        },
        &[],
    )
    .await
    .unwrap();
    assert_eq!(measurements.len(), 1);
    assert_eq!(measurements.first().unwrap().key.local_l4_port, 4242);

    // repeat query with a time-range
    let measurements = flow_queries(
        fix.db_client.clone(),
        &user,
        device_uuid,
        TimeRangeQueryParams {
            start: None,
            end: Some(fix.between_connections_time),
        },
        &[],
    )
    .await
    .unwrap();
    assert_eq!(measurements.len(), 2);
    assert_ne!(measurements[0].key.local_l4_port, 4242);
    assert_ne!(measurements[1].key.local_l4_port, 4242);

    // Now a query with bot start and end time. Also query additional columns
    // repeat query with a time-range
    let measurements = flow_queries(
        fix.db_client.clone(),
        &user,
        device_uuid,
        TimeRangeQueryParams {
            start: Some(fix.between_connections_time),
            end: Some(fix.after_connections_time),
        },
        &[
            FlowQueryExtraColumns::ProbeReportSummary,
            FlowQueryExtraColumns::Pingtrees,
        ],
    )
    .await
    .unwrap();
    assert_eq!(measurements.len(), 1);
    assert_eq!(measurements.first().unwrap().key.local_l4_port, 4242);
    let mut expected = fix.expected_measurement.clone();
    assert!(!expected.pingtrees.is_empty());
    assert!(!expected.probe_report_summary.raw_reports.is_empty());
    expected.start_tracking_time = truncate_nanos(expected.start_tracking_time);
    expected.last_packet_time = truncate_nanos(expected.last_packet_time);
    expected.prev_export_time = expected.prev_export_time.map(truncate_nanos);
    assert_eq!(measurements.first().unwrap(), &expected);
}

#[tokio::test]
async fn test_query_aggregate_flows() {
    let fix = FlowTestFixture::new().await;

    let aggregates = query_and_aggregate_flows(
        fix.db_client.clone(),
        TimeRangeQueryParams::default(),
        chrono::Duration::minutes(60),
    )
    .await
    .unwrap();

    // db_test_utils has 3 fake devices, two flows per device, plus
    // an additional flow from `get_expected_fake_connection_log_for_flow_query_alice`
    // ==> 7 total flows
    // TODO: in theory we could end up with two entries in `aggregates`, if the DB writes
    // in FlowTestFixture::new() happen to span an hour boundrary... But given that we can
    // live with that for now
    assert_eq!(aggregates.len(), 1);
    assert_eq!(aggregates[0].aggregate.total.num_flows, 7);

    // we use 60min buckets, with bucket boundraries at multiples of 60min
    // since unix epoch. Therefore, the bucket_start should have 0 min and 0 sec
    let bucket_start = aggregates[0].bucket_start;
    assert_eq!(bucket_start.minute(), 0);
    assert_eq!(bucket_start.second(), 0);
    assert_eq!(bucket_start.nanosecond(), 0);
}
