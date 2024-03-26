pub mod db_utils;
use crate::db_utils::{add_fake_users, make_mock_protected_routes, mk_test_db};

/// Following examples from https://github.com/tokio-rs/axum/blob/main/examples/testing/src/main.rs#L85
/// and
/// https://docs.rs/axum-login/latest/src/axum_login/middleware.rs.html#303
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::Response,
};
use axum_login::tower_sessions::cookie;
use http_body_util::BodyExt;
use tower::ServiceExt; // for `call`, `oneshot`, and `ready`

use libwebserver::remotedb_client::RemoteDBClient;

fn get_session_cookie(res: &Response<Body>) -> Option<String> {
    res.headers()
        .get(header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie_str| {
            let cookie = cookie::Cookie::parse(cookie_str);
            cookie.map(|c| c.to_string()).ok()
        })
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
