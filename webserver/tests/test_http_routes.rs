pub mod db_utils;
use crate::db_utils::{
    add_fake_users, get_auth_token_from_rest_router, get_session_cookie,
    make_mock_protected_routes, mk_test_db,
};

/// Following examples from https://github.com/tokio-rs/axum/blob/main/examples/testing/src/main.rs#L85
/// and
/// https://docs.rs/axum-login/latest/src/axum_login/middleware.rs.html#303
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use tower::ServiceExt; // for `call`, `oneshot`, and `ready`

use libwebserver::remotedb_client::RemoteDBClient;
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

    // this function will assert if we don't get the cookie
    let _session_cookie = get_auth_token_from_rest_router(protected_routes, "Alice").await;
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
    println!("Cookie={:?}", cookie);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    println!("Response={:#?}", body);
    assert_eq!(status, StatusCode::OK);
}
