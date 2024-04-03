use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use common_wasm::get_git_hash_version;
use indexmap::IndexMap;
use itertools::Itertools;
use libconntrack_wasm::ConnectionMeasurements;
use libconntrack_wasm::{topology_server_messages::DesktopLogLevel, DnsTrackerEntry};
use libwebserver::remotedb_client::{RemoteDBClient, RemoteDBClientMessages, StorageSourceType};
use tokio::sync::mpsc;
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
        &StorageSourceType::Desktop,
    )
    .await
    .unwrap();
    let rows = RemoteDBClient::count_remote_connection_rows(&client)
        .await
        .unwrap();
    assert_eq!(rows, 1);

    do_test_store_dns_entries(&remotedb_client, &client).await;
}

async fn do_test_store_dns_entries(remotedb_client: &RemoteDBClient, client: &PostgresClient) {
    // timestamp is from 2024-04-02.
    // Note timescaledb appears to truncate timestamps to microsecond precision so make sure that the
    // nanos part of the timestamps is otherwise zero
    let ts = DateTime::from_timestamp(1712088645, 112_233_000).unwrap();
    let entries = vec![
        DnsTrackerEntry {
            ip: IpAddr::from_str("1.2.3.4").unwrap(),
            hostname: "host1.example.com".to_owned(),
            created: ts,
            from_ptr_record: false,
            rtt: None,
            ttl: None,
        },
        DnsTrackerEntry {
            ip: IpAddr::from_str("5.6.7.8").unwrap(),
            hostname: "host2.example.com".to_owned(),
            created: ts,
            from_ptr_record: true,
            rtt: Some(chrono::Duration::microseconds(123_456)),
            ttl: Some(chrono::Duration::seconds(4242)),
        },
    ];
    let uuid = Uuid::from_u128(0x1111_2222_3333_4444_5555);
    let (tx, mut rx) = mpsc::channel(10);
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
    RemoteDBClient::inner_loop(&mut rx, client, remotedb_client.get_queue_duration())
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
            ip: IpAddr::from_str(row.try_get("ip")?).unwrap(),
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

/**
 * Does the embedded DB thing work?
 * Simple write and read back test with none of our code for sanity
 */
#[tokio::test]
async fn test_pm_embed() {
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
