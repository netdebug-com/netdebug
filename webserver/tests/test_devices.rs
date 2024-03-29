use axum::http::StatusCode;
#[cfg(test)]
use common::init::netdebug_test_init;
use gui_types::{PublicDeviceDetails, PublicDeviceInfo};
use http_body_util::BodyExt;
use libwebserver::remotedb_client::RemoteDBClient;

use crate::db_utils::{
    add_fake_connection_logs, add_fake_devices, add_fake_users, get_auth_token_from_rest_router,
    get_resp_from_rest_router, make_mock_protected_routes, mk_test_db,
};

pub mod db_utils;

#[tokio::test]
async fn test_devices_non_netdebug_employee() {
    netdebug_test_init();
    let (db_client, test_db) = mk_test_db("devices_non_netdebug_employee").await.unwrap();
    let remotedb_client = RemoteDBClient::mk_mock(&test_db.db_uri);
    remotedb_client
        .create_table_schema(&db_client)
        .await
        .unwrap();
    add_fake_users(&db_client).await;
    add_fake_devices(&db_client).await;
    let protected_routes = make_mock_protected_routes(&test_db).await;

    // first try with an invalid auth token
    let resp = get_resp_from_rest_router(protected_routes.clone(), "/get_devices", "JOEMAMA").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // now get an valid auth token and try again
    let session_token = get_auth_token_from_rest_router(protected_routes.clone(), "Alice").await;
    let resp =
        get_resp_from_rest_router(protected_routes.clone(), "/get_devices", &session_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let devices: Vec<PublicDeviceInfo> = serde_json::from_slice(&body).unwrap();
    assert_eq!(devices.len(), 1);
    let device = devices.first().unwrap();
    assert_eq!(device.name, Some("Alice's dev1".to_string()));
    // now try to look up with the UUID
    let resp = get_resp_from_rest_router(
        protected_routes.clone(),
        &format!("/get_device/{}", device.uuid),
        &session_token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let alice_device: PublicDeviceDetails = serde_json::from_slice(&body).unwrap();
    assert_eq!(alice_device.num_flows_stored, 0);
    assert_eq!(alice_device.newest_flow_time, None);
}

#[tokio::test]
async fn test_devices_netdebug_employee() {
    netdebug_test_init();
    let (db_client, test_db) = mk_test_db("devices_netdebug_employee").await.unwrap();
    let remotedb_client = RemoteDBClient::mk_mock(&test_db.db_uri);
    remotedb_client
        .create_table_schema(&db_client)
        .await
        .unwrap();
    add_fake_users(&db_client).await;
    add_fake_devices(&db_client).await;
    let protected_routes = make_mock_protected_routes(&test_db).await;

    // get an valid auth token
    let session_token = get_auth_token_from_rest_router(protected_routes.clone(), "Bob").await;
    let resp =
        get_resp_from_rest_router(protected_routes.clone(), "/get_devices", &session_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let devices: Vec<PublicDeviceInfo> = serde_json::from_slice(&body).unwrap();
    assert_eq!(devices.len(), 1);
    let device = devices.first().unwrap();
    assert_eq!(device.name, Some("Bob's dev2".to_string()));
}

#[tokio::test]
async fn test_devices_details() {
    // TODO: create our own test fixture to setup all of this for us...
    netdebug_test_init();
    let (db_client, test_db) = mk_test_db("devices_netdebug_details").await.unwrap();
    let remotedb_client = RemoteDBClient::mk_mock(&test_db.db_uri);
    remotedb_client
        .create_table_schema(&db_client)
        .await
        .unwrap();
    add_fake_users(&db_client).await;
    add_fake_devices(&db_client).await;
    add_fake_connection_logs(&db_client).await.unwrap();
    let protected_routes = make_mock_protected_routes(&test_db).await;

    // get an valid auth token
    let session_token = get_auth_token_from_rest_router(protected_routes.clone(), "Bob").await;
    let resp = get_resp_from_rest_router(
        protected_routes.clone(),
        "/get_devices_details",
        &session_token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    println!("GetDetails Body {:?}", body);
    let details: Vec<PublicDeviceDetails> = serde_json::from_slice(&body).unwrap();
    // Bob only has 1 device
    assert_eq!(details.len(), 1);
    let details = details.first().unwrap();
    // two flows stored
    assert_eq!(details.num_flows_stored, 2);
    assert_eq!(details.num_flows_with_send_loss, Some(1));
}
