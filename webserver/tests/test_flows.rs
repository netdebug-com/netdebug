use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use axum::{
    body::Body,
    http::{Response, StatusCode},
};
use chrono::{DateTime, Timelike, Utc};
#[cfg(test)]
use common::init::netdebug_test_init;
use common_wasm::ProbeReportSummary;
use db_test_utils::{add_fake_connection_logs_for_flow_query_test, get_alice_dev1_uuid};

use itertools::Itertools;
use libconntrack_wasm::ConnectionMeasurements;
use libwebserver::{
    db_utils::TimeRangeQueryParams,
    flow_aggregation::{
        AggregateByCategory, AggregatedBucket, AggregatedConnectionMeasurement,
        AGGREGATION_BUCKET_SIZE_MINUTES,
    },
    flows::{
        get_aggregated_flow_view, query_aggregated_flow_tables, query_and_aggregate_flows,
        write_aggregated_flows, AggregatedFlowCategory, AggregatedFlowRow,
    },
    remotedb_client::{get_next_bucket_time, StorageSourceType, FLOW_AGGREGATION_TIME_GAP_MINUTES},
};
use libwebserver::{
    flows::{flow_queries, FlowQueryExtraColumns},
    remotedb_client::{do_flow_aggregation, RemoteDBClient},
    users::NetDebugUser,
};
use pg_embed::postgres::PgEmbed;
use tokio_postgres::Client;
use uuid::Uuid;

use crate::db_test_utils::{
    add_fake_connection_logs, add_fake_devices, add_fake_users, get_auth_token_from_rest_router,
    get_bob_dev2_uuid, get_cathy_dev3_uuid, get_resp_from_rest_router, make_mock_protected_routes,
    mk_test_db, response_to_bytes,
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
        &fix.db_client,
        TimeRangeQueryParams::default(),
        chrono::Duration::minutes(60),
    )
    .await
    .unwrap();

    // db_test_utils has 3 fake devices, two flows per device, plus
    // an additional flow from `get_expected_fake_connection_log_for_flow_query_alice`
    // TODO: in theory we could end up with two entries in `aggregates`, if the DB writes
    // in FlowTestFixture::new() happen to span an hour boundrary... But given that we can
    // live with that for now
    assert_eq!(aggregates.len(), 1);
    assert_eq!(aggregates[0].aggregate.len(), 3); // three different devices
    assert_eq!(
        aggregates[0]
            .aggregate
            .get(&get_alice_dev1_uuid())
            .unwrap()
            .total
            .num_flows,
        3
    );
    assert_eq!(
        aggregates[0]
            .aggregate
            .get(&get_bob_dev2_uuid())
            .unwrap()
            .total
            .num_flows,
        2
    );
    let cathys_dev_aggregate = aggregates[0].aggregate.get(&get_cathy_dev3_uuid()).unwrap();
    assert_eq!(cathys_dev_aggregate.total.num_flows, 2);
    assert_eq!(
        cathys_dev_aggregate.total.device_uuid,
        get_cathy_dev3_uuid()
    );
    assert_eq!(cathys_dev_aggregate.total.organization_id, 2);

    // we use 60min buckets, with bucket boundraries at multiples of 60min
    // since unix epoch. Therefore, the bucket_start should have 0 min and 0 sec
    let bucket_start = aggregates[0].bucket_start;
    assert_eq!(bucket_start.minute(), 0);
    assert_eq!(bucket_start.second(), 0);
    assert_eq!(bucket_start.nanosecond(), 0);
}

fn mk_aggregated_connection_measurement(
    dev_id: u128,
    org_id: i64,
    seed: i64,
) -> AggregatedConnectionMeasurement {
    AggregatedConnectionMeasurement {
        device_uuid: Uuid::from_u128(dev_id),
        organization_id: org_id,
        num_flows: seed + 20,
        num_flows_with_rx_loss: seed + 1,
        num_flows_with_tx_loss: seed + 2,
        num_tcp_flows: seed + 4,
        num_udp_flows: seed + 5,
        rx_packets: seed + 6,
        tx_packets: seed + 7,
        rx_bytes: seed + 8,
        tx_bytes: seed + 9,
        rx_lost_bytes: seed + 10,
        tx_lost_bytes: seed + 11,
        tcp_rx_bytes: seed + 12,
        tcp_tx_bytes: seed + 13,
        udp_rx_bytes: seed + 14,
        udp_tx_bytes: seed + 15,
    }
}

#[tokio::test]
async fn test_write_aggregated_flows_read_aggregated_flows() {
    // Don't need the full fixture here
    netdebug_test_init();
    let db_name = "flow_test_write_aggregated_flows";
    let (mut db_client, test_db) = mk_test_db(db_name).await.unwrap();
    let remotedb_client = RemoteDBClient::mk_mock(&test_db.db_uri);
    remotedb_client
        .create_table_schema(&db_client)
        .await
        .unwrap();

    let mut b1_agg: HashMap<Uuid, AggregateByCategory> = HashMap::new();
    b1_agg.insert(
        Uuid::from_u128(42),
        AggregateByCategory {
            device_uuid: Uuid::from_u128(42),
            organization_id: 2,
            total: mk_aggregated_connection_measurement(42, 2, 0),
            by_dns_dest_domain: HashMap::from([
                (
                    "example.com".to_string(),
                    mk_aggregated_connection_measurement(42, 2, 100),
                ),
                (
                    "netdebug.com".to_string(),
                    mk_aggregated_connection_measurement(42, 2, 200),
                ),
            ]),
            by_app: HashMap::from([
                (
                    "magic-app".to_string(),
                    mk_aggregated_connection_measurement(42, 2, 300),
                ),
                (
                    "super-duper-app".to_string(),
                    mk_aggregated_connection_measurement(42, 2, 400),
                ),
            ]),
        },
    );
    b1_agg.insert(
        Uuid::from_u128(23),
        AggregateByCategory {
            device_uuid: Uuid::from_u128(23),
            organization_id: 3,
            total: mk_aggregated_connection_measurement(23, 3, 1000),
            by_dns_dest_domain: HashMap::from([(
                "foobar.com".to_string(),
                mk_aggregated_connection_measurement(23, 3, 1100),
            )]),
            by_app: HashMap::from([(
                "my-app".to_string(),
                mk_aggregated_connection_measurement(23, 3, 1200),
            )]),
        },
    );

    let b1 = AggregatedBucket {
        bucket_start: DateTime::from_timestamp(300_000, 0).unwrap(),
        bucket_size: chrono::Duration::minutes(5),
        aggregate: b1_agg,
    };

    let mut b2_agg: HashMap<Uuid, AggregateByCategory> = HashMap::new();
    b2_agg.insert(
        Uuid::from_u128(23),
        AggregateByCategory {
            device_uuid: Uuid::from_u128(23),
            organization_id: 3,
            total: mk_aggregated_connection_measurement(23, 3, 2000),
            by_dns_dest_domain: HashMap::from([(
                "foobar.com".to_string(),
                mk_aggregated_connection_measurement(23, 3, 2100),
            )]),
            by_app: HashMap::from([(
                "my-app".to_string(),
                mk_aggregated_connection_measurement(23, 3, 2200),
            )]),
        },
    );
    let b2 = AggregatedBucket {
        bucket_start: DateTime::from_timestamp(300_900, 0).unwrap(),
        bucket_size: chrono::Duration::minutes(5),
        aggregate: b2_agg,
    };

    let transaction = db_client.transaction().await.unwrap();
    write_aggregated_flows(&transaction, vec![b1, b2])
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    //
    // Now read back and verify
    //
    let agg_flow_rows = query_aggregated_flow_tables(
        &NetDebugUser::make_internal_superuser(),
        None,
        TimeRangeQueryParams::default(),
        &db_client,
    )
    .await
    .unwrap();

    let agg_flow_rows_set: HashSet<AggregatedFlowRow> =
        HashSet::from_iter(agg_flow_rows.into_iter());

    let t0 = DateTime::from_timestamp(300_000, 0).unwrap();
    let t1 = DateTime::from_timestamp(300_900, 0).unwrap();
    let bucket_size = chrono::Duration::minutes(5);
    let expected = HashSet::from([
        AggregatedFlowRow {
            bucket_start: t0,
            bucket_size,
            category: AggregatedFlowCategory::Total,
            aggregate: mk_aggregated_connection_measurement(42, 2, 0),
        },
        AggregatedFlowRow {
            bucket_start: t0,
            bucket_size,
            category: AggregatedFlowCategory::ByDnsDestDomain("example.com".to_string()),
            aggregate: mk_aggregated_connection_measurement(42, 2, 100),
        },
        AggregatedFlowRow {
            bucket_start: t0,
            bucket_size,
            category: AggregatedFlowCategory::ByDnsDestDomain("netdebug.com".to_string()),
            aggregate: mk_aggregated_connection_measurement(42, 2, 200),
        },
        AggregatedFlowRow {
            bucket_start: t0,
            bucket_size,
            category: AggregatedFlowCategory::ByApp("magic-app".to_string()),
            aggregate: mk_aggregated_connection_measurement(42, 2, 300),
        },
        AggregatedFlowRow {
            bucket_start: t0,
            bucket_size,
            category: AggregatedFlowCategory::ByApp("super-duper-app".to_string()),
            aggregate: mk_aggregated_connection_measurement(42, 2, 400),
        },
        AggregatedFlowRow {
            bucket_start: t0,
            bucket_size,
            category: AggregatedFlowCategory::Total,
            aggregate: mk_aggregated_connection_measurement(23, 3, 1000),
        },
        AggregatedFlowRow {
            bucket_start: t0,
            bucket_size,
            category: AggregatedFlowCategory::ByDnsDestDomain("foobar.com".to_string()),
            aggregate: mk_aggregated_connection_measurement(23, 3, 1100),
        },
        AggregatedFlowRow {
            bucket_start: t0,
            bucket_size,
            category: AggregatedFlowCategory::ByApp("my-app".to_string()),
            aggregate: mk_aggregated_connection_measurement(23, 3, 1200),
        },
        AggregatedFlowRow {
            bucket_start: t1,
            bucket_size,
            category: AggregatedFlowCategory::Total,
            aggregate: mk_aggregated_connection_measurement(23, 3, 2000),
        },
        AggregatedFlowRow {
            bucket_start: t1,
            bucket_size,
            category: AggregatedFlowCategory::ByDnsDestDomain("foobar.com".to_string()),
            aggregate: mk_aggregated_connection_measurement(23, 3, 2100),
        },
        AggregatedFlowRow {
            bucket_start: t1,
            bucket_size,
            category: AggregatedFlowCategory::ByApp("my-app".to_string()),
            aggregate: mk_aggregated_connection_measurement(23, 3, 2200),
        },
    ]);
    let only_in_actual = agg_flow_rows_set.difference(&expected).collect_vec();
    let only_in_expected = expected.difference(&agg_flow_rows_set).collect_vec();

    if !only_in_actual.is_empty() || !only_in_expected.is_empty() {
        println!("\n\nOnly in actual: {}", only_in_actual.len());
        for x in &only_in_actual {
            println!("    {:?}", x);
        }
        println!("\nOnly in expected: {}", only_in_expected.len());
        for x in &only_in_expected {
            println!("    {:?}", x);
        }
        panic!("Actual and expected mismatch");
    }

    // Test query by org_id
    let agg_flow_rows = query_aggregated_flow_tables(
        &NetDebugUser::make_internal_superuser(),
        Some(2),
        TimeRangeQueryParams::default(),
        &db_client,
    )
    .await
    .unwrap();
    assert_eq!(agg_flow_rows.len(), 5);

    // Test query by org_id. No flows for this org
    let agg_flow_rows = query_aggregated_flow_tables(
        &NetDebugUser::make_internal_superuser(),
        Some(7),
        TimeRangeQueryParams::default(),
        &db_client,
    )
    .await
    .unwrap();
    assert_eq!(agg_flow_rows.len(), 0);

    // Test time-range query
    let agg_flow_rows = query_aggregated_flow_tables(
        &NetDebugUser::make_internal_superuser(),
        None,
        TimeRangeQueryParams {
            start: Some(t0),
            end: Some(t1),
        },
        &db_client,
    )
    .await
    .unwrap();
    assert_eq!(agg_flow_rows.len(), 8);

    // Test time-range query -- start only
    let agg_flow_rows = query_aggregated_flow_tables(
        &NetDebugUser::make_internal_superuser(),
        None,
        TimeRangeQueryParams {
            start: Some(t1),
            end: None,
        },
        &db_client,
    )
    .await
    .unwrap();
    assert_eq!(agg_flow_rows.len(), 3);

    // Test time-range query and org query
    let agg_flow_rows = query_aggregated_flow_tables(
        &NetDebugUser::make_internal_superuser(),
        Some(3),
        TimeRangeQueryParams {
            start: Some(t0),
            end: Some(t1),
        },
        &db_client,
    )
    .await
    .unwrap();
    assert_eq!(agg_flow_rows.len(), 3);
}

struct FlowAggregationTestFixture {
    db_client: Client,
    bucket1_time: DateTime<Utc>,
    bucket2_time: DateTime<Utc>,
    bucket3_time: DateTime<Utc>,
    // _test_db must be alive for the duration of the test
    _test_db: PgEmbed,
}

type ExpectedFlows = HashMap<(DateTime<Utc>, Uuid, AggregatedFlowCategory), i64>;
impl FlowAggregationTestFixture {
    async fn new() -> FlowAggregationTestFixture {
        netdebug_test_init();
        let db_name = format!("flow_aggregation_test_fixture{}", rand::random::<u16>());
        let (mut db_client, test_db) = mk_test_db(&db_name).await.unwrap();
        let remotedb_client = RemoteDBClient::mk_mock(&test_db.db_uri);
        remotedb_client
            .create_table_schema(&db_client)
            .await
            .unwrap();

        // Insert already aggregated flows
        // Two buckets, one starting at 3_600_000 sec since epoch,
        // the otehr starting 1hr later.
        let mut b1_agg: HashMap<Uuid, AggregateByCategory> = HashMap::new();
        b1_agg.insert(
            Uuid::from_u128(42),
            AggregateByCategory {
                device_uuid: Uuid::from_u128(42),
                organization_id: 2,
                total: mk_aggregated_connection_measurement(42, 2, 0),
                by_dns_dest_domain: HashMap::from([(
                    "netdebug.com".to_string(),
                    mk_aggregated_connection_measurement(42, 2, 100),
                )]),
                by_app: HashMap::from([(
                    "super-duper-app".to_string(),
                    mk_aggregated_connection_measurement(42, 2, 200),
                )]),
            },
        );
        b1_agg.insert(
            Uuid::from_u128(23),
            AggregateByCategory {
                device_uuid: Uuid::from_u128(23),
                organization_id: 3,
                total: mk_aggregated_connection_measurement(23, 3, 1000),
                by_dns_dest_domain: HashMap::from([(
                    "foobar.com".to_string(),
                    mk_aggregated_connection_measurement(23, 3, 1100),
                )]),
                by_app: HashMap::from([(
                    "my-app".to_string(),
                    mk_aggregated_connection_measurement(23, 3, 1200),
                )]),
            },
        );

        let b2_agg = b1_agg.clone();
        let bucket1_time = DateTime::from_timestamp(3_600_000, 0).unwrap();
        let bucket2_time = DateTime::from_timestamp(3_603_600, 0).unwrap();
        let bucket3_time = DateTime::from_timestamp(3_607_200, 0).unwrap();
        let b1 = AggregatedBucket {
            bucket_start: bucket1_time,
            bucket_size: chrono::Duration::minutes(AGGREGATION_BUCKET_SIZE_MINUTES),
            aggregate: b1_agg,
        };

        let b2 = AggregatedBucket {
            bucket_start: bucket2_time,
            bucket_size: chrono::Duration::minutes(AGGREGATION_BUCKET_SIZE_MINUTES),
            aggregate: b2_agg,
        };

        let transaction = db_client.transaction().await.unwrap();
        write_aggregated_flows(&transaction, vec![b1, b2])
            .await
            .unwrap();
        transaction
            .execute(
                "UPDATE aggregated_connections_lock SET next_bucket_start_time=$1",
                &[&bucket3_time],
            )
            .await
            .unwrap();
        transaction.commit().await.unwrap();

        // Now add raw, not yet aggregated flows
        // Add raw, not yet aggregates flows/connections.
        let m1 = ConnectionMeasurements::make_mock();
        RemoteDBClient::handle_store_connection_measurement(
            &db_client,
            &m1,
            Some(bucket3_time),
            &Uuid::from_u128(42),
            2,
            &StorageSourceType::Desktop,
        )
        .await
        .unwrap();

        RemoteDBClient::handle_store_connection_measurement(
            &db_client,
            &m1,
            Some(bucket3_time),
            &Uuid::from_u128(42),
            2,
            &StorageSourceType::Desktop,
        )
        .await
        .unwrap();

        let mut m2 = ConnectionMeasurements::make_mock();
        m2.remote_hostname = None;
        m2.associated_apps = None;

        RemoteDBClient::handle_store_connection_measurement(
            &db_client,
            &m2,
            Some(bucket3_time + chrono::Duration::minutes(5)),
            &Uuid::from_u128(23),
            3,
            &StorageSourceType::Desktop,
        )
        .await
        .unwrap();

        // Add m2 again, but beyond our aggregation goal (and using a different uuid
        RemoteDBClient::handle_store_connection_measurement(
            &db_client,
            &m2,
            Some(bucket3_time + chrono::Duration::minutes(AGGREGATION_BUCKET_SIZE_MINUTES + 5)),
            &Uuid::from_u128(0xff),
            2,
            &StorageSourceType::Desktop,
        )
        .await
        .unwrap();

        // Add a flow that falls into the already aggregated time window ==> should be ignored
        // Add m2 again, but beyond our aggregation goal (and using a different uuid
        RemoteDBClient::handle_store_connection_measurement(
            &db_client,
            &ConnectionMeasurements::make_mock(),
            Some(bucket2_time + chrono::Duration::minutes(5)),
            &Uuid::from_u128(0xff),
            2,
            &StorageSourceType::Desktop,
        )
        .await
        .unwrap();

        let fake_devices = [(Uuid::from_u128(42), 2i64), (Uuid::from_u128(23), 3)];
        for (uuid, org_id) in fake_devices {
            let name = format!("fake device {}", uuid);
            db_client
                .execute(
                    "INSERT INTO devices (uuid, name, organization) VALUES ($1, $2, $3)",
                    &[&uuid, &name, &org_id],
                )
                .await
                .unwrap();
        }

        FlowAggregationTestFixture {
            db_client,
            bucket1_time,
            bucket2_time,
            bucket3_time,
            _test_db: test_db,
        }
    }

    /// Helper functions. Returns the expected flows that are already aggregated.
    fn get_expected_already_aggregated_flows(&self) -> ExpectedFlows {
        let mut expected_num_flows = HashMap::new();

        // We've inserted the same aggregated flows in two buckets
        for t in [self.bucket1_time, self.bucket2_time] {
            let agg = mk_aggregated_connection_measurement(42, 2, 0);
            #[rustfmt::skip]
            expected_num_flows.insert((t, agg.device_uuid, AggregatedFlowCategory::Total), agg.num_flows);

            let agg = mk_aggregated_connection_measurement(42, 2, 100);
            #[rustfmt::skip]
            expected_num_flows.insert((t, agg.device_uuid, AggregatedFlowCategory::ByDnsDestDomain("netdebug.com".to_string())), agg.num_flows);

            let agg = mk_aggregated_connection_measurement(42, 2, 200);
            #[rustfmt::skip]
            expected_num_flows.insert((t, agg.device_uuid, AggregatedFlowCategory::ByApp("super-duper-app".to_string())), agg.num_flows);

            let agg = mk_aggregated_connection_measurement(23, 3, 1000);
            #[rustfmt::skip]
            expected_num_flows.insert((t, agg.device_uuid, AggregatedFlowCategory::Total), agg.num_flows);

            let agg = mk_aggregated_connection_measurement(23, 3, 1100);
            #[rustfmt::skip]
            expected_num_flows.insert((t, agg.device_uuid, AggregatedFlowCategory::ByDnsDestDomain("foobar.com".to_string())), agg.num_flows);

            let agg = mk_aggregated_connection_measurement(23, 3, 1200);
            #[rustfmt::skip]
            expected_num_flows.insert((t, agg.device_uuid, AggregatedFlowCategory::ByApp("my-app".to_string())), agg.num_flows);
        }
        expected_num_flows
    }

    /// Helper functions. Returns the expected flows that aren't yet aggregated. I.e., the flows that are just
    /// in the `desktop_connections` table
    fn get_expected_not_yet_aggregated(&self) -> ExpectedFlows {
        let mut expected_num_flows = HashMap::new();

        let id42 = Uuid::from_u128(42);
        let id23 = Uuid::from_u128(23);
        let t = self.bucket3_time;
        #[rustfmt::skip]
        expected_num_flows.insert((t, id42, AggregatedFlowCategory::Total), 2);
        #[rustfmt::skip]
        expected_num_flows.insert((t, id42, AggregatedFlowCategory::ByApp("SuperApp".to_string())), 2);
        #[rustfmt::skip]
        expected_num_flows.insert((t, id42, AggregatedFlowCategory::ByDnsDestDomain("example.com".to_string())), 2);
        #[rustfmt::skip]
        expected_num_flows.insert((t, id23, AggregatedFlowCategory::Total), 1);
        #[rustfmt::skip]
        expected_num_flows.insert((t, id23, AggregatedFlowCategory::ByApp("<UNKNOWN>".to_string())), 1);
        #[rustfmt::skip]
        expected_num_flows.insert((t, id23, AggregatedFlowCategory::ByDnsDestDomain("<UNKNOWN>".to_string())), 1);

        expected_num_flows
    }

    fn get_all_expected_flows(&self) -> ExpectedFlows {
        let mut expected = self.get_expected_already_aggregated_flows();
        expected.extend(self.get_expected_not_yet_aggregated());
        expected
    }
}

/// Helper macro to compare two HashMaps for equality and print a legible error message
/// if they are not equal
macro_rules! assert_actual_expected_flows_equal {
    ($actual_num_flows:expr, $expected_num_flows:expr) => {{
        let expected_keys = format!(
            "EXPECTED KEYS = {:#?}",
            $expected_num_flows.keys().collect_vec()
        );
        let actual_keys = format!(
            "ACTUAL KEYS = {:#?}",
            $actual_num_flows.keys().collect_vec()
        );
        for (key, value) in &$actual_num_flows {
            assert!(
                $expected_num_flows.contains_key(key),
                "Key {:?} is in actual but not expected. {}",
                key,
                expected_keys
            );
            let expected_val = $expected_num_flows.get(key).unwrap();
            assert_eq!(
                value, expected_val,
                "Number of flows for key {:#?} differs between actual and expected",
                key
            );
        }
        for (key, value) in &$expected_num_flows {
            assert!(
                $actual_num_flows.contains_key(key),
                "Key {:?} is in expected but not actual. {}",
                key,
                actual_keys
            );
            let actual_val = $actual_num_flows.get(key).unwrap();
            assert_eq!(
                actual_val, value,
                "Number of flows for key {:#?} differs between actual and expected",
                key
            );
        }
        assert_eq!($actual_num_flows, $expected_num_flows);
    }};
}

#[tokio::test]
async fn test_aggregation_logic() {
    let mut agg_fix = FlowAggregationTestFixture::new().await;

    let expected_next_bucket_time = agg_fix.bucket3_time + chrono::Duration::minutes(60);

    do_flow_aggregation(
        &mut agg_fix.db_client,
        chrono::Duration::minutes(AGGREGATION_BUCKET_SIZE_MINUTES),
        expected_next_bucket_time
            + chrono::Duration::minutes(FLOW_AGGREGATION_TIME_GAP_MINUTES + 1),
    )
    .await
    .unwrap();

    // check next_bucket_time
    assert_eq!(
        get_next_bucket_time(&agg_fix.db_client).await.unwrap(),
        expected_next_bucket_time
    );

    let aggregated_flow_rows = query_aggregated_flow_tables(
        &NetDebugUser::make_internal_superuser(),
        None,
        TimeRangeQueryParams::default(),
        &agg_fix.db_client,
    )
    .await
    .unwrap();

    let mut actual_num_flows = HashMap::new();
    for row in aggregated_flow_rows {
        actual_num_flows.insert(
            (row.bucket_start, row.aggregate.device_uuid, row.category),
            row.aggregate.num_flows,
        );
    }

    let expected_num_flows = agg_fix.get_all_expected_flows();
    assert_actual_expected_flows_equal!(actual_num_flows, expected_num_flows);
}

#[tokio::test]
async fn test_get_aggregated_flow_view() {
    let agg_fix = FlowAggregationTestFixture::new().await;
    let next_bucket_time =
        agg_fix.bucket3_time + chrono::Duration::minutes(AGGREGATION_BUCKET_SIZE_MINUTES);

    // sanity check
    assert_eq!(
        get_next_bucket_time(&agg_fix.db_client).await.unwrap(),
        agg_fix.bucket3_time
    );

    let aggregated_flow_rows = get_aggregated_flow_view(
        &NetDebugUser::make_internal_superuser(),
        None,
        // there is a raw, unaggregated flow after next_bucket_time
        TimeRangeQueryParams {
            start: None,
            end: Some(next_bucket_time),
        },
        &agg_fix.db_client,
    )
    .await
    .unwrap();

    let mut actual_num_flows = HashMap::new();
    for row in aggregated_flow_rows {
        actual_num_flows.insert(
            (row.bucket_start, row.aggregate.device_uuid, row.category),
            row.aggregate.num_flows,
        );
    }
    let exptecd_num_flows = agg_fix.get_all_expected_flows();
    assert_actual_expected_flows_equal!(actual_num_flows, exptecd_num_flows);

    //
    // Query with org filter
    //
    let aggregated_flow_rows = get_aggregated_flow_view(
        &NetDebugUser::make_internal_superuser(),
        Some(2),
        // there is a raw, unaggregated flow after next_bucket_time
        TimeRangeQueryParams {
            start: None,
            end: Some(next_bucket_time),
        },
        &agg_fix.db_client,
    )
    .await
    .unwrap();
    let mut actual_num_flows = HashMap::new();
    for row in aggregated_flow_rows {
        actual_num_flows.insert(
            (row.bucket_start, row.aggregate.device_uuid, row.category),
            row.aggregate.num_flows,
        );
    }
    let exptecd_num_flows: ExpectedFlows = agg_fix
        .get_all_expected_flows()
        .into_iter()
        // uuid 42 is in org 2, which we filtered for
        .filter(|(k, _v)| k.1 == Uuid::from_u128(42))
        .collect();
    assert_actual_expected_flows_equal!(actual_num_flows, exptecd_num_flows);

    //
    // Query again without end time.
    //
    let aggregated_flow_rows = get_aggregated_flow_view(
        &NetDebugUser::make_internal_superuser(),
        None,
        TimeRangeQueryParams {
            start: None,
            end: None,
        },
        &agg_fix.db_client,
    )
    .await
    .unwrap();

    let mut actual_num_flows = HashMap::new();
    for row in aggregated_flow_rows {
        actual_num_flows.insert(
            (row.bucket_start, row.aggregate.device_uuid, row.category),
            row.aggregate.num_flows,
        );
    }
    let mut exptecd_num_flows = agg_fix.get_all_expected_flows();

    #[rustfmt::skip]
    exptecd_num_flows.insert((next_bucket_time, Uuid::from_u128(0xff), AggregatedFlowCategory::Total,), 1);
    #[rustfmt::skip]
    exptecd_num_flows.insert((next_bucket_time, Uuid::from_u128(0xff), AggregatedFlowCategory::ByApp("<UNKNOWN>".to_string())), 1);
    #[rustfmt::skip]
    exptecd_num_flows.insert((next_bucket_time, Uuid::from_u128(0xff), AggregatedFlowCategory::ByDnsDestDomain("<UNKNOWN>".to_string())), 1);

    assert_actual_expected_flows_equal!(actual_num_flows, exptecd_num_flows);

    //
    //  Time window that essentially only queries already aggregated flows
    //
    let aggregated_flow_rows = get_aggregated_flow_view(
        &NetDebugUser::make_internal_superuser(),
        None,
        TimeRangeQueryParams {
            start: None,
            end: Some(agg_fix.bucket3_time),
        },
        &agg_fix.db_client,
    )
    .await
    .unwrap();
    assert_eq!(aggregated_flow_rows.len(), 12);

    //
    //  Time window that only queries bucket2
    //
    let aggregated_flow_rows = get_aggregated_flow_view(
        &NetDebugUser::make_internal_superuser(),
        None,
        TimeRangeQueryParams {
            start: Some(agg_fix.bucket2_time),
            end: Some(agg_fix.bucket3_time),
        },
        &agg_fix.db_client,
    )
    .await
    .unwrap();
    assert_eq!(aggregated_flow_rows.len(), 6);
    let times = aggregated_flow_rows
        .iter()
        .map(|r| r.bucket_start)
        .unique()
        .collect_vec();
    assert_eq!(times, vec![agg_fix.bucket2_time]);

    //
    //  Time window that only queries bucket2
    //
    let aggregated_flow_rows = get_aggregated_flow_view(
        &NetDebugUser::make_internal_superuser(),
        None,
        TimeRangeQueryParams {
            start: Some(agg_fix.bucket3_time),
            end: Some(next_bucket_time),
        },
        &agg_fix.db_client,
    )
    .await
    .unwrap();
    assert_eq!(aggregated_flow_rows.len(), 6);
    let times = aggregated_flow_rows
        .iter()
        .map(|r| r.bucket_start)
        .unique()
        .collect_vec();
    assert_eq!(times, vec![agg_fix.bucket3_time]);
}
