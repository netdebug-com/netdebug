use chrono::Utc;
use common_wasm::get_git_hash_version;
use indexmap::IndexMap;
use libconntrack_wasm::topology_server_messages::DesktopLogLevel;
use libconntrack_wasm::ConnectionMeasurements;
use libwebserver::remotedb_client::{RemoteDBClient, RemoteDBClientMessages, StorageSourceType};
use tokio_postgres::types::ToSql;
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
    remotedb_client
        .handle_store_counters(
            &client,
            &alice_counters,
            &Uuid::from_u128(0x1234_5678_9abc_0000_1234),
            &now,
            &"testOS".to_string(),
            &get_git_hash_version(),
        )
        .await
        .unwrap();
    let rows = remotedb_client
        .count_remote_counters_rows(&client)
        .await
        .unwrap();
    assert_eq!(rows, 2);
    let bob_counters = IndexMap::from_iter([("count1".to_string(), 2), ("count2".to_string(), 43)]);
    remotedb_client
        .handle_store_counters(
            &client,
            &bob_counters,
            &Uuid::from_u128(0x1234_0000_cafe_dead_beef),
            &now,
            &"testOS2".to_string(),
            &get_git_hash_version(),
        )
        .await
        .unwrap();
    let rows = remotedb_client
        .count_remote_counters_rows(&client)
        .await
        .unwrap();
    assert_eq!(rows, 4);
    // now store a log and make sure it's there
    remotedb_client
        .handle_store_log(
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
    let rows = remotedb_client
        .count_remote_logs_rows(&client)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    // now store a connection measurement and make sure it's there
    remotedb_client
        .handle_store_connection_measurement(
            &client,
            &ConnectionMeasurements::make_mock(),
            &Uuid::from_u128(0x1234_1234_1234_1234),
            &StorageSourceType::Desktop,
        )
        .await
        .unwrap();
    let rows = remotedb_client
        .count_remote_connection_rows(&client)
        .await
        .unwrap();
    assert_eq!(rows, 1);
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
