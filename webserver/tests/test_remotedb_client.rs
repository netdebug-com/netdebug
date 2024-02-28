use chrono::Utc;
use common_wasm::get_git_hash_version;
use indexmap::IndexMap;
use libconntrack_wasm::topology_server_messages::DesktopLogLevel;
use libconntrack_wasm::ConnectionMeasurements;
use libwebserver::remotedb_client::{RemoteDBClient, RemoteDBClientMessages};
use pg_embed::pg_fetch::{PgFetchSettings, PG_V13};
use pg_embed::pg_types::PgResult;
use pg_embed::postgres::{PgEmbed, PgSettings};
use rand::Rng;
use std::{path::PathBuf, time::Duration};
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;
use uuid::Uuid;

use pg_embed::pg_enums::PgAuthMethod;

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
    let now = Utc::now();
    let alice_counters =
        IndexMap::from_iter([("count1".to_string(), 2), ("count2".to_string(), 43)]);
    remotedb_client
        .handle_store_counters(
            &client,
            &alice_counters,
            &"alice".to_string(),
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
            &"bob".to_string(),
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
                client_id: "JOemama".to_string(),
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
            &Uuid::new_v4(),
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
#[ignore] // skip this test b/c it takes quite a while to run and seems stable
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

async fn mk_test_db(database_name: &str) -> PgResult<(Client, PgEmbed)> {
    let db_dir = db_dir(database_name);
    // https://github.com/faokunega/pg-embed/issues/31
    // can't bind '0' for an ephemeral port :-( so just fake it and pray :-()
    let port = rand::thread_rng().gen_range(1024..65000);
    // Postgresql settings; all copied directly from documentation
    let pg_settings = PgSettings {
        // Where to store the postgresql database
        database_dir: db_dir.clone(),
        port,
        user: "postgres".to_string(),
        password: "password".to_string(),
        // authentication method
        auth_method: PgAuthMethod::Plain,
        persistent: false, // clean up after done
        // duration to wait before terminating process execution
        // pg_ctl start/stop and initdb timeout
        // if set to None the process will not be terminated
        timeout: Some(Duration::from_secs(15)),
        // If migration sql scripts need to be run, the directory containing those scripts can be
        // specified here with `Some(PathBuf(path_to_dir)), otherwise `None` to run no migrations.
        // To enable migrations view the **Usage** section for details
        migration_dir: None,
    };

    // Postgresql binaries download settings
    let fetch_settings = PgFetchSettings {
        version: PG_V13,
        ..Default::default()
    };

    // Create a new instance
    let mut pg = PgEmbed::new(pg_settings, fetch_settings).await?;

    // Download, unpack, create password file and database cluster
    pg.setup().await?;

    // start postgresql database
    pg.start_db().await?;

    // create a new database
    // to enable migrations view the [Usage] section for details
    pg.create_database(database_name).await?;

    // drop a database
    // to enable migrations view [Usage] for details
    // pg.drop_database("database_name").await;

    // check database existence
    // to enable migrations view [Usage] for details
    // pg.database_exists("database_name").await;

    // run migration sql scripts
    // to enable migrations view [Usage] for details
    // pg.migrate("database_name").await;

    // stop postgresql database
    // pg.stop_db().await;
    // `postgres://{username}:{password}@localhost:{port}`
    // let pg_uri: &str = &pg.db_uri;

    // get a postgresql database uri
    // `postgres://{username}:{password}@localhost:{port}/{specified_database_name}`
    // let pg_db_uri: String = pg.full_db_uri("database_name");
    let (client, connection) = tokio_postgres::connect(&pg.db_uri, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    Ok((client, pg))
}

fn db_dir(test_name: &str) -> PathBuf {
    let mut db_path = if let Ok(_metadata) = std::fs::metadata("/tmp") {
        PathBuf::from("/tmp")
    } else {
        PathBuf::from(".")
    };
    db_path.push(format!("netdebug-db-test-{}", test_name));
    db_path
}
