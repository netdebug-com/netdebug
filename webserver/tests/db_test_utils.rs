use axum::body::Body;
use axum::http::{header, Request, Response, StatusCode};
use axum::Router;
use axum_login::tower_sessions::cookie::{self, Cookie};
use axum_login::tower_sessions::{MemoryStore, SessionManagerLayer};
use axum_login::AuthManagerLayerBuilder;
use chrono::Utc;
use common::test_utils::test_dir;
use common_wasm::{PingtreeUiResult, ProbeReportSummary};
use gui_types::OrganizationId;
use http_body_util::BodyExt;
use libconntrack_wasm::ConnectionMeasurements;
use libwebserver::context::make_test_context;
use libwebserver::http_routes::{
    setup_protected_rest_routes_with_auth_layer, CLERK_JWT_COOKIE_NAME,
};
use libwebserver::remotedb_client::{RemoteDBClient, StorageSourceType};
use libwebserver::secrets_db::Secrets;
use libwebserver::users::{NetDebugUserBackend, UserServiceData};
use pg_embed::pg_fetch::{PgFetchSettings, PG_V13};
use pg_embed::pg_types::PgResult;
use pg_embed::postgres::{PgEmbed, PgSettings};
use rand::Rng;
use std::sync::Arc;
use std::time::Instant;
use std::{path::PathBuf, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;

use pg_embed::pg_enums::PgAuthMethod;
use tokio_postgres::Client;

pub const TEST_DB_USER: &str = "postgres";
pub const TEST_DB_PASSWD: &str = "postgres";
pub const TEST_NETDEBUG_SESSION_COOKIE: &str = "TestNetDebugSessionCookie";
/// Wrap the pg_embed crate to get a convenient 'download on demand' postgres
/// database for testing.  
pub async fn mk_test_db(database_name: &str) -> PgResult<(Client, PgEmbed)> {
    // pg-embed captures the output of sub-processes it spawns using async tokio tasks.
    // So if a command error's out and Result-error chain bubbles up, the test process
    // will likely terminate before these async tasks can actually capture and log the output,
    // so we are left w/o any error messages in this case.
    // I tried fixing pg_embed to await the log capturing tasks, but this doesn't work for long-running
    // tasks (like the actual postgres daemon). So fixing it would require more substantial changes
    // in pg_embed. Instead, we work around it in a hacky wait by waiting
    // "long enough" for the logging tasks to run and print the output
    let res = mk_test_db_impl(database_name).await;
    if res.is_err() {
        tokio::time::sleep(tokio::time::Duration::from_millis(5000)).await;
    }

    res
}

async fn mk_test_db_impl(database_name: &str) -> PgResult<(Client, PgEmbed)> {
    let db_dir = db_dir(database_name);
    // https://github.com/faokunega/pg-embed/issues/31
    // can't bind '0' for an ephemeral port :-( so just fake it and pray :-()
    let port = rand::thread_rng().gen_range(1024..65000);
    // Postgresql settings; all copied directly from documentation
    let pg_settings = PgSettings {
        // Where to store the postgresql database
        database_dir: db_dir.clone(),
        port,
        user: TEST_DB_USER.to_string(),
        password: TEST_DB_PASSWD.to_string(),
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

    let start = Instant::now();
    println!("DB_PERF: Start: {:?}", start.elapsed());
    // Create a new instance
    let mut pg = PgEmbed::new(pg_settings, fetch_settings).await?;
    println!("DB_PERF: Done new(): {:?}", start.elapsed());
    // Download, unpack, create password file and database cluster
    pg.setup().await?;
    println!("DB_PERF: Done setup(): {:?}", start.elapsed());

    // start postgresql database
    pg.start_db().await?;
    println!("DB_PERF: Done start(): {:?}", start.elapsed());

    // create a new database
    // to enable migrations view the [Usage] section for details
    pg.create_database(database_name).await?;
    println!("DB_PERF: Done create_database(): {:?}", start.elapsed());

    // drop a database
    // to enable migrations view [Usage] for details
    // pg.drop_database("database_name").await;

    // check database existence
    // to enable migrations view [Usage] for details
    // pg.database_exists("database_name").await;

    // run migration sql scripts
    // to enable migrations view [Usage] for details
    // pg.migrate(database_name).await;

    // stop postgresql database
    // pg.stop_db().await;
    // `postgres://{username}:{password}@localhost:{port}`
    // let pg_uri: &str = &pg.db_uri;

    // get a postgresql database uri
    // `postgres://{username}:{password}@localhost:{port}/{specified_database_name}`
    // let pg_db_uri: String = pg.full_db_uri("database_name");
    let uri = &pg.db_uri;
    println!("TestDB URI = {}", uri);
    let (client, connection) = tokio_postgres::connect(&pg.db_uri, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    println!("DB_PERF: Done connect(): {:?}", start.elapsed());
    Ok((client, pg))
}

fn db_dir(test_name: &str) -> PathBuf {
    let mut db_path = std::env::temp_dir();

    // Put the PID back in the DB path now that I understand this is
    // not the directory where things are cached
    db_path.push(format!(
        "netdebug-db-test-{}-{}",
        test_name,
        std::process::id()
    ));
    println!("Starting DB {} in {}", test_name, db_path.display());
    db_path
}

pub async fn make_mock_protected_routes(test_db: &PgEmbed) -> Router {
    let mut mock_secrets = Secrets::make_mock();
    mock_secrets.timescale_db_read_user = Some(TEST_DB_USER.to_string());
    mock_secrets.timescale_db_read_secret = Some(TEST_DB_PASSWD.to_string());
    // this is the postgres://user@host:port/path?options=stuff
    // we just want everything after the '@'
    let url = test_db
        .db_uri
        .clone()
        .split('@')
        .collect::<Vec<&str>>()
        .get(1)
        .unwrap()
        .to_string();
    mock_secrets.timescale_db_base_url = Some(url);
    let context = make_test_context();

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_name(TEST_NETDEBUG_SESSION_COOKIE);
    // Start the user service in 'auth disabled' mode where jwt=$username
    let user_service = UserServiceData::disable_auth_for_testing();
    let mock_backend = NetDebugUserBackend::new(Arc::new(user_service), &mock_secrets)
        .await
        .unwrap();
    let auth_layer = AuthManagerLayerBuilder::new(mock_backend, session_layer).build();
    setup_protected_rest_routes_with_auth_layer(auth_layer, mock_secrets)
        .await
        .with_state(context)
    // context not needed except to make compiler happy
}

pub async fn add_fake_users(db_client: &Client) {
    for (user, org_id) in [("Alice", 0i64), ("Bob", 1)] {
        db_client
            .execute(
                "INSERT INTO users (clerk_id, name, organization) VALUES ($1, $2, $3)",
                &[&user, &user, &org_id],
            )
            .await
            .unwrap();
    }
}

pub fn mk_uuid_from_string(user: &str) -> Uuid {
    Uuid::new_v3(&Uuid::NAMESPACE_DNS, user.as_bytes())
}

const FAKE_PEOPLE_DATA: [(&str, OrganizationId); 3] = [
    ("Alice's dev1", 0i64),
    ("Bob's dev2", 1),
    ("Cathy's dev3", 2),
];
pub async fn add_fake_devices(db_client: &Client) {
    for (name, org_id) in FAKE_PEOPLE_DATA {
        db_client
            .execute(
                "INSERT INTO devices (uuid, name, organization) VALUES ($1, $2, $3)",
                &[&mk_uuid_from_string(name), &name, &org_id],
            )
            .await
            .unwrap();
    }
}

pub fn get_alice_dev1_uuid() -> Uuid {
    mk_uuid_from_string(FAKE_PEOPLE_DATA[0].0)
}

// also see add_fake_connection_logs
pub fn get_expected_fake_connection_logs_alice() -> Vec<ConnectionMeasurements> {
    let org_id = FAKE_PEOPLE_DATA[0].1;
    let mut m1 = ConnectionMeasurements::make_mock_with_ips(
        &format!("{}.{}.{}.{}", org_id, org_id, org_id, org_id),
        "128.8.128.38",
    );
    let m2 = m1.clone();
    // The mock by default sets lost_bytes= 1500; make this flow 'good' by marking it zero
    m1.tx_stats.lost_bytes = None;
    m1.key.local_l4_port = 6667; // and give it a different source port
    vec![m1, m2]
}

pub async fn add_fake_connection_logs(db_client: &Client) -> Result<(), tokio_postgres::Error> {
    // make two flows for each person; one happy, one sad
    for (name, org_id) in FAKE_PEOPLE_DATA {
        let device_uuid = &mk_uuid_from_string(name);
        let mut m1 = ConnectionMeasurements::make_mock_with_ips(
            &format!("{}.{}.{}.{}", org_id, org_id, org_id, org_id),
            "128.8.128.38",
        );
        let m2 = m1.clone();
        // The mock by default sets lost_bytes= 1500; make this flow 'good' by marking it zero
        m1.tx_stats.lost_bytes = None;
        m1.key.local_l4_port = 6667; // and give it a different source port
        for m in &[m1, m2] {
            RemoteDBClient::handle_store_connection_measurement(
                db_client,
                m,
                device_uuid,
                org_id,
                &StorageSourceType::Desktop,
            )
            .await?;
        }
    }
    Ok(())
}

// also see add_fake_connection_logs_for_flow_query_test
pub fn get_expected_fake_connection_log_for_flow_query_alice() -> ConnectionMeasurements {
    let org_id = FAKE_PEOPLE_DATA[0].1;
    let mut m1 = ConnectionMeasurements::make_mock_with_ips(
        &format!("{}.{}.{}.{}", org_id, org_id, org_id, org_id),
        "128.8.128.38",
    );
    m1.key.local_l4_port = 4242;
    m1.tx_stats.bytes = 8420;
    m1.tx_stats.pkts = 10;

    let json = std::fs::read_to_string(test_dir(
        "libconntrack",
        "tests/data/probe-report-summary.json",
    ))
    .unwrap();
    m1.probe_report_summary = serde_json::from_str::<ProbeReportSummary>(&json).unwrap();
    let json =
        std::fs::read_to_string(test_dir("libconntrack", "tests/data/pingtrees.json")).unwrap();
    m1.pingtrees = serde_json::from_str::<Vec<PingtreeUiResult>>(&json).unwrap();
    m1.tx_stats_since_prev_export.pkts = 3;
    m1.tx_stats_since_prev_export.bytes = 300;
    m1.rx_stats_since_prev_export.pkts = 2;
    m1.rx_stats_since_prev_export.bytes = 200;
    m1.export_count = 3;
    m1.prev_export_time = Some(Utc::now());
    m1
}

pub async fn add_fake_connection_logs_for_flow_query_test(
    db_client: &Client,
) -> Result<ConnectionMeasurements, tokio_postgres::Error> {
    let device_uuid = &get_alice_dev1_uuid();
    let m1 = get_expected_fake_connection_log_for_flow_query_alice();
    RemoteDBClient::handle_store_connection_measurement(
        db_client,
        &m1,
        device_uuid,
        FAKE_PEOPLE_DATA[0].1,
        &StorageSourceType::Desktop,
    )
    .await?;
    Ok(m1)
}

pub async fn get_auth_token_from_rest_router(router: Router, user: &str) -> String {
    // `Router` implements `tower::Service<Request<Body>>` so we can
    // call it like any tower service, no need to run an HTTP server.
    let response = router
        .oneshot(
            Request::builder()
                .header(
                    header::COOKIE,
                    // in Mock mode, with UserServiceData.disable_auth_check
                    // just set the JWT to the user you want to auth as
                    format!("{}={}", CLERK_JWT_COOKIE_NAME, user),
                )
                .uri("/login")
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    assert_eq!(status, StatusCode::OK);
    let cookie = get_session_cookie(&response).unwrap().unwrap().clone();
    assert_eq!(cookie.name(), TEST_NETDEBUG_SESSION_COOKIE);
    cookie.value().to_string()
}

pub async fn get_resp_from_rest_router(
    router: Router,
    url: &str,
    session_token: &str,
) -> Response<Body> {
    // `Router` implements `tower::Service<Request<Body>>` so we can
    // call it like any tower service, no need to run an HTTP server.
    let request = Request::builder()
        .header(
            header::COOKIE,
            format!("{}={}", TEST_NETDEBUG_SESSION_COOKIE, session_token),
        )
        .uri(url)
        .body(Body::empty())
        .unwrap();
    println!("Making request {:?}", request);
    router.oneshot(request).await.unwrap()
}

pub async fn response_to_bytes(resp: Response<Body>) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

pub fn get_session_cookie(res: &Response<Body>) -> Option<Result<Cookie, cookie::ParseError>> {
    res.headers()
        .get(header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .map(cookie::Cookie::parse)
}
