use std::sync::Arc;
mod db_utils;
use crate::db_utils::mk_test_db;

/// Following examples from https://github.com/tokio-rs/axum/blob/main/examples/testing/src/main.rs#L85
/// and
/// https://docs.rs/axum-login/latest/src/axum_login/middleware.rs.html#303
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::Response,
    Router,
};
use axum_login::{
    tower_sessions::{cookie, MemoryStore, SessionManagerLayer},
    AuthManagerLayerBuilder,
};
use db_utils::{TEST_DB_PASSWD, TEST_DB_USER};
use http_body_util::BodyExt;
use pg_embed::postgres::PgEmbed;
use tokio_postgres::Client;
use tower::ServiceExt; // for `call`, `oneshot`, and `ready`

use libwebserver::{
    context::make_test_context,
    http_routes::setup_protected_rest_routes_with_auth_layer,
    remotedb_client::RemoteDBClient,
    secrets_db::Secrets,
    users::{NetDebugUserBackend, UserServiceData},
};

fn get_session_cookie(res: &Response<Body>) -> Option<String> {
    res.headers()
        .get(header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie_str| {
            let cookie = cookie::Cookie::parse(cookie_str);
            cookie.map(|c| c.to_string()).ok()
        })
}

async fn make_mock_protected_routes(test_db: &PgEmbed) -> Router {
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

async fn add_fake_users(db_client: &Client) {
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

#[tokio::test]
async fn auth_check_no_auth() {
    let (db_client, test_db) = mk_test_db("test_http_routes_no_auth").await.unwrap();
    let remotedb_client = RemoteDBClient::mk_mock(&test_db.db_uri);
    remotedb_client
        .create_table_schema(&db_client)
        .await
        .unwrap();
    add_fake_users(&db_client).await;
    let protected_routes = make_mock_protected_routes(&test_db).await;

    // `Router` implements `tower::Service<Request<Body>>` so we can
    // call it like any tower service, no need to run an HTTP server.
    let response = protected_routes
        .oneshot(
            Request::builder()
                .uri("/test_auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    // let body = response.into_body().collect().await.unwrap().to_bytes();
    // println!("Response={:#?}", body);

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_check_with_get_auth() {
    let (db_client, test_db) = mk_test_db("test_http_routes_get").await.unwrap();
    let remotedb_client = RemoteDBClient::mk_mock(&test_db.db_uri);
    remotedb_client
        .create_table_schema(&db_client)
        .await
        .unwrap();
    add_fake_users(&db_client).await;
    let protected_routes = make_mock_protected_routes(&test_db).await;

    // `Router` implements `tower::Service<Request<Body>>` so we can
    // call it like any tower service, no need to run an HTTP server.
    let response = protected_routes
        .oneshot(
            Request::builder()
                .uri("/login?clerk_jwt=Alice")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let cookie = get_session_cookie(&response);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    println!("Response={:#?}", body);
    println!("Cookie={:?}", cookie);
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn auth_check_with_post_auth() {
    let (db_client, test_db) = mk_test_db("test_http_routes_post").await.unwrap();
    let remotedb_client = RemoteDBClient::mk_mock(&test_db.db_uri);
    remotedb_client
        .create_table_schema(&db_client)
        .await
        .unwrap();
    add_fake_users(&db_client).await;
    let protected_routes = make_mock_protected_routes(&test_db).await;

    // `Router` implements `tower::Service<Request<Body>>` so we can
    // call it like any tower service, no need to run an HTTP server.
    let response = protected_routes
        .oneshot(
            Request::builder()
                .uri("/login")
                .method("POST")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("clerk_jwt=Alice"))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let cookie = get_session_cookie(&response);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    println!("Response={:#?}", body);
    println!("Cookie={:?}", cookie);
    assert_eq!(status, StatusCode::OK);
}
