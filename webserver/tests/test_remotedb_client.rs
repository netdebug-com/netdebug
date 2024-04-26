use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use common::init::netdebug_test_init;
use common_wasm::get_git_hash_version;
use indexmap::IndexMap;
use itertools::Itertools;
use libconntrack_wasm::{topology_server_messages::DesktopLogLevel, DnsTrackerEntry};
use libconntrack_wasm::{AggregatedGatewayPingData, ConnectionMeasurements, NetworkInterfaceState};
use libwebserver::remotedb_client::{
    extract_aggregated_ping_data, RemoteDBClient, RemoteDBClientMessages, StorageSourceType,
    NETWORK_INTERFACE_STATE_TABLE_NAME,
};
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client as PostgresClient, Row};
use uuid::Uuid;

pub mod db_utils;

use db_utils::mk_test_db;
/**
 * Test against FAKE credentials!
 *
 * Brazenly put the handle_store_counters() and handle_store_logs() and connection tests
 * into the same #[test] b/c the startup time for this test is quite high
 */
#[tokio::test]
async fn test_remotedb_client() {
    netdebug_test_init();
    let (client, db) = mk_test_db("testdb-test_remotedb_client").await.unwrap();
    let remotedb_client = RemoteDBClient::mk_mock(&db.db_uri);
    remotedb_client.create_table_schema(&client).await.unwrap();
    // tokio::time::sleep(Duration::from_secs(10000000)).await;
    let now = Utc::now();
    let alice_counters =
        IndexMap::from_iter([("count1".to_string(), 2), ("count2".to_string(), 43)]);
    RemoteDBClient::handle_store_counters(
        &client,
        &alice_counters,
        &Uuid::from_u128(0x1234_5678_9abc_0000_1234),
        &now,
        &"testOS".to_string(),
        &get_git_hash_version(),
    )
    .await
    .unwrap();
    let rows = RemoteDBClient::count_remote_counters_rows(&client)
        .await
        .unwrap();
    assert_eq!(rows, 2);
    let bob_counters = IndexMap::from_iter([("count1".to_string(), 2), ("count2".to_string(), 43)]);
    RemoteDBClient::handle_store_counters(
        &client,
        &bob_counters,
        &Uuid::from_u128(0x1234_0000_cafe_dead_beef),
        &now,
        &"testOS2".to_string(),
        &get_git_hash_version(),
    )
    .await
    .unwrap();
    let rows = RemoteDBClient::count_remote_counters_rows(&client)
        .await
        .unwrap();
    assert_eq!(rows, 4);
    // now store a log and make sure it's there
    RemoteDBClient::handle_store_log(
        &client,
        RemoteDBClientMessages::StoreLog {
            msg: "Yay logging!".to_string(),
            level: DesktopLogLevel::Debug,
            os: "TestOS".to_string(),
            version: "1".to_string(),
            device_uuid: Uuid::from_u128(0x1111_2222_3333_4444_5555),
            time: Utc::now(),
        },
    )
    .await
    .unwrap();
    let rows = RemoteDBClient::count_remote_logs_rows(&client)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    // now store a connection measurement and make sure it's there
    RemoteDBClient::handle_store_connection_measurement(
        &client,
        &ConnectionMeasurements::make_mock(),
        &Uuid::from_u128(0x1234_1234_1234_1234),
        1,
        &StorageSourceType::Desktop,
    )
    .await
    .unwrap();
    let rows = RemoteDBClient::count_remote_connection_rows(&client)
        .await
        .unwrap();
    assert_eq!(rows, 1);

    do_test_store_dns_entries(&remotedb_client, &client).await;
    do_test_store_network_interface_state(&remotedb_client, &client).await;
    do_test_store_aggregated_ping_data(&remotedb_client, &client).await;
}

async fn do_test_store_dns_entries(remotedb_client: &RemoteDBClient, client: &PostgresClient) {
    // timestamp is from 2024-04-02.
    // Note timescaledb appears to truncate timestamps to microsecond precision so make sure that the
    // nanos part of the timestamps is otherwise zero
    let ts = DateTime::from_timestamp(1712088645, 112_233_000).unwrap();
    let entries = vec![
        DnsTrackerEntry {
            ip: Some(IpAddr::from_str("1.2.3.4").unwrap()),
            hostname: "host1.example.com".to_owned(),
            created: ts,
            from_ptr_record: false,
            rtt: None,
            ttl: None,
        },
        DnsTrackerEntry {
            ip: Some(IpAddr::from_str("5.6.7.8").unwrap()),
            hostname: "host2.example.com".to_owned(),
            created: ts,
            from_ptr_record: true,
            rtt: Some(chrono::Duration::microseconds(123_456)),
            ttl: Some(chrono::Duration::seconds(4242)),
        },
    ];
    let uuid = Uuid::from_u128(0x1111_2222_3333_4444_5555);
    let (tx, rx) = async_channel::bounded(10);
    tx.send(
        RemoteDBClientMessages::StoreDnsEntries {
            dns_entries: entries.clone(),
            device_uuid: uuid,
        }
        .into(),
    )
    .await
    .unwrap();
    drop(tx); // need to drop rx otherwise inner_loop won't return
    RemoteDBClient::inner_loop(rx, client, remotedb_client.get_stat_handles())
        .await
        .unwrap();

    let from_db = db_select_all_helper(
        client,
        libwebserver::remotedb_client::DNS_ENTRIES_TABLE_NAME,
        extract_dns_entry_row,
    )
    .await;

    assert_eq!(
        HashSet::from_iter(from_db.iter().map(|x| x.1.clone())),
        HashSet::<DnsTrackerEntry>::from_iter(entries),
    );

    assert_eq!(from_db.iter().map(|x| x.2).collect_vec(), vec![uuid, uuid]);
}

fn mk_ip(ip_str: &str) -> IpAddr {
    IpAddr::from_str(ip_str).unwrap()
}

async fn do_test_store_network_interface_state(
    remotedb_client: &RemoteDBClient,
    client: &PostgresClient,
) {
    // timestamp is from 2024-04-02.
    // Note timescaledb appears to truncate timestamps to microsecond precision so make sure that the
    // nanos part of the timestamps is otherwise zero
    let ts = DateTime::from_timestamp(1712088645, 112_233_000).unwrap();
    let state_uuid = Uuid::from_u128(0x4242_4242);
    let state = NetworkInterfaceState {
        uuid: state_uuid,
        gateways: vec![mk_ip("192.168.42.1")],
        interface_name: Some("eth-foo".to_owned()),
        interface_ips: vec![mk_ip("192.168.42.42"), mk_ip("10.0.0.1")],
        comment: "No comment!".to_owned(),
        has_link: true,
        is_wireless: false,
        start_time: ts,
        end_time: Some(ts + chrono::Duration::seconds(23)),
        gateways_ping: HashMap::new(), // unused
    };
    let device_uuid = Uuid::from_u128(0x1111_2222_3333_4444_5555);
    let (tx, rx) = async_channel::bounded(10);
    tx.send(
        RemoteDBClientMessages::StoreNetworkInterfaceState {
            network_interface_state: state.clone(),
            device_uuid,
        }
        .into(),
    )
    .await
    .unwrap();
    drop(tx); // need to drop rx otherwise inner_loop won't return
    RemoteDBClient::inner_loop(rx.clone(), client, remotedb_client.get_stat_handles())
        .await
        .unwrap();
    let from_db = db_select_all_helper(
        client,
        NETWORK_INTERFACE_STATE_TABLE_NAME,
        extract_network_interface_state_row,
    )
    .await;
    assert_eq!(from_db.len(), 1);
    assert_eq!(from_db[0].1, state);
    assert_eq!(from_db[0].2, device_uuid);

    // Delete previous entry and try again -- this time checking NULL columns
    assert_eq!(
        client
            .execute(
                &format!("DELETE FROM {}", NETWORK_INTERFACE_STATE_TABLE_NAME),
                &[],
            )
            .await
            .unwrap(),
        1 // one row deleted
    );
    let state = NetworkInterfaceState {
        uuid: state_uuid,
        gateways: Vec::new(),
        interface_name: None,
        interface_ips: Vec::new(),
        comment: "No comment!".to_owned(),
        has_link: true,
        is_wireless: false,
        start_time: ts,
        end_time: None,
        gateways_ping: HashMap::new(), // unused
    };
    let device_uuid = Uuid::from_u128(0x1111_2222_3333_4444_5555);
    let (tx, rx) = async_channel::bounded(10);
    tx.send(
        RemoteDBClientMessages::StoreNetworkInterfaceState {
            network_interface_state: state.clone(),
            device_uuid,
        }
        .into(),
    )
    .await
    .unwrap();
    drop(tx); // need to drop rx otherwise inner_loop won't return
    RemoteDBClient::inner_loop(rx.clone(), client, remotedb_client.get_stat_handles())
        .await
        .unwrap();
    let from_db = db_select_all_helper(
        client,
        NETWORK_INTERFACE_STATE_TABLE_NAME,
        extract_network_interface_state_row,
    )
    .await;
    assert_eq!(from_db.len(), 1);
    assert_eq!(from_db[0].1, state);
    assert_eq!(from_db[0].2, device_uuid);
}

async fn do_test_store_aggregated_ping_data(
    remotedb_client: &RemoteDBClient,
    client: &PostgresClient,
) {
    let ping_data = vec![AggregatedGatewayPingData {
        network_interface_uuid: Uuid::from_u128(0x1000_1000_aaaa),
        gateway_ip: mk_ip("192.168.1.1"),
        num_probes_sent: 42,
        num_responses_recv: 23,
        rtt_mean_ns: 42_000,
        rtt_variance_ns: Some(23_000),
        rtt_min_ns: 10_000,
        rtt_p50_ns: 50_000,
        rtt_p75_ns: 75_000,
        rtt_p90_ns: 90_000,
        rtt_p99_ns: 99_000,
        rtt_max_ns: 100_000,
    }];
    let (tx, rx) = async_channel::bounded(10);
    tx.send(
        RemoteDBClientMessages::StoreGatewayPingData {
            ping_data: ping_data.clone(),
        }
        .into(),
    )
    .await
    .unwrap();
    drop(tx); // need to drop rx otherwise inner_loop won't return
    RemoteDBClient::inner_loop(rx.clone(), client, remotedb_client.get_stat_handles())
        .await
        .unwrap();

    let from_db = db_select_all_helper(
        client,
        libwebserver::remotedb_client::AGGREGATED_PING_DATA_TABLE_NAME,
        extract_aggregated_ping_data,
    )
    .await;

    assert_eq!(from_db.len(), 1);
    assert_eq!(from_db[0].1, ping_data[0]);
}

/// Execute `SELECT * FROM <table_name>` and pass each resulting row through the
/// `extractor` function, which should convert each row into the rust type `T`.
/// TODO: should this be moved to remotedb_client.rs?
pub async fn db_select_all_helper<F, T>(
    client: &PostgresClient,
    table_name: &str,
    extractor: F,
) -> Vec<T>
where
    F: Fn(&Row) -> Result<T, tokio_postgres::error::Error>,
{
    client
        .query(&format!("SELECT * FROM {};", table_name), &[])
        .await
        .unwrap()
        .iter()
        .map(|row| extractor(row).unwrap())
        .collect_vec()
}

/// Take a row from a SELECT * query and convert it into a
/// DnsTrackerEntry (or rather a tuple of `(insert_time, dns_entry, device_uuid)`)
/// TODO: should this be moved to remotedb_client.rs?
pub fn extract_dns_entry_row(
    row: &Row,
) -> Result<(DateTime<Utc>, DnsTrackerEntry, Uuid), tokio_postgres::error::Error> {
    Ok((
        row.try_get("time")?,
        DnsTrackerEntry {
            ip: Some(IpAddr::from_str(row.try_get("ip")?).unwrap()),
            hostname: row.try_get("hostname")?,
            created: row.try_get("created")?,
            from_ptr_record: row.try_get("from_ptr_record")?,
            rtt: row
                .try_get::<_, Option<i64>>("rtt_usec")?
                .map(chrono::Duration::microseconds),
            ttl: row
                .try_get::<_, Option<i64>>("ttl_sec")?
                .map(chrono::Duration::seconds),
        },
        row.try_get("device_uuid")?,
    ))
}

/// Take a row from a SELECT * query and convert it into a
/// NetworkInterfaceState (or rather a tuple of `(insert_time, state, device_uuid)`)
/// TODO: should this be moved to remotedb_client.rs?
pub fn extract_network_interface_state_row(
    row: &Row,
) -> Result<(DateTime<Utc>, NetworkInterfaceState, Uuid), tokio_postgres::error::Error> {
    Ok((
        row.try_get("time")?,
        NetworkInterfaceState {
            uuid: row.try_get("state_uuid")?,
            // TODO: instead of unwrap we should prob. propagate the json error (if any
            gateways: row
                .try_get::<_, Vec<String>>("gateways")?
                .iter()
                .map(|ip_str| IpAddr::from_str(ip_str).unwrap())
                .collect_vec(),
            interface_name: row.try_get("interface_name")?,
            interface_ips: row
                .try_get::<_, Vec<String>>("interface_ips")?
                .iter()
                .map(|ip_str| IpAddr::from_str(ip_str).unwrap())
                .collect_vec(),
            comment: row.try_get("comment")?,
            has_link: row.try_get("has_link")?,
            is_wireless: row.try_get("is_wireless")?,
            start_time: row.try_get("start_time")?,
            end_time: row.try_get("end_time")?,
            gateways_ping: HashMap::new(),
        },
        row.try_get("device_uuid")?,
    ))
}

/**
 * Does the embedded DB thing work?
 * Simple write and read back test with none of our code for sanity
 */
#[tokio::test]
async fn test_pm_embed() {
    netdebug_test_init();
    let (client, _db) = mk_test_db("testdb").await.unwrap();
    client
        .execute(
            "CREATE TABLE test_pm_embed (num INT, name varchar(265))",
            &[],
        )
        .await
        .unwrap();
    for (num, name) in [(1, "Alice"), (2, "Bob"), (3, "Cathy")] {
        // OMG look at this type!!  Fought for a while and then had to C&P from stackoverflow :-(
        let num = &num as &(dyn ToSql + Sync);
        let affected_rows = client
            .execute(
                "INSERT INTO test_pm_embed (num, name) VALUES ($1, $2)",
                &[num, &name],
            )
            .await
            .unwrap();
        assert_eq!(affected_rows, 1);
    }
    let matched_rows = client
        .execute("SELECT * FROM test_pm_embed", &[])
        .await
        .unwrap();
    assert_eq!(matched_rows, 3);
}
