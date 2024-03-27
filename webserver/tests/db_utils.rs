use axum::Router;
use axum_login::tower_sessions::{MemoryStore, SessionManagerLayer};
use axum_login::AuthManagerLayerBuilder;
use libwebserver::context::make_test_context;
use libwebserver::http_routes::setup_protected_rest_routes_with_auth_layer;
use libwebserver::secrets_db::Secrets;
use libwebserver::users::{NetDebugUserBackend, UserServiceData};
use pg_embed::pg_fetch::{PgFetchSettings, PG_V13};
use pg_embed::pg_types::PgResult;
use pg_embed::postgres::{PgEmbed, PgSettings};
use rand::Rng;
use std::sync::Arc;
use std::time::Instant;
use std::{path::PathBuf, time::Duration};

use pg_embed::pg_enums::PgAuthMethod;
use tokio_postgres::Client;

pub const TEST_DB_USER: &str = "postgres";
pub const TEST_DB_PASSWD: &str = "postgres";
/// Wrap the pg_embed crate to get a convenient 'download on demand' postgres
/// database for testing.  
pub async fn mk_test_db(database_name: &str) -> PgResult<(Client, PgEmbed)> {
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

    db_path.push(format!("netdebug-db-test-{}", test_name));
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
    let session_layer = SessionManagerLayer::new(session_store).with_secure(false);
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
