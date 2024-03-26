pub mod db_utils;
use std::sync::Arc;

use clerk_rs::models::User as ClerkUser;
use db_utils::mk_test_db;
use libwebserver::{remotedb_client::RemoteDBClient, users::NetDebugUser};
use tokio_postgres::types::ToSql;

#[tokio::test]
async fn test_user_get_org_id() {
    let (client, db) = mk_test_db("testdb-test-user-get_org_id").await.unwrap();
    let remotedb_client = RemoteDBClient::mk_mock(&db.db_uri);
    // populate with cached production schema
    remotedb_client.create_table_schema(&client).await.unwrap();
    // insert a few example users
    for (user, org) in [("alice", 10i64), ("bob", 20)] {
        let org = &org as &(dyn ToSql + Sync); // sillyness to make type conversion work
        client
            .execute(
                "INSERT INTO users (clerk_id, organization) VALUES ($1, $2)",
                &[&user, org],
            )
            .await
            .unwrap();
    }
    // make sure the user lookup works
    let alice_clerk = clerk_user("alice");
    let random_salt = "test".to_string();
    let client = Arc::new(client);
    let alice = NetDebugUser::from_validated_clerk_user(&alice_clerk, &random_salt, &client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice.organization_id, 10);
    let not_found =
        NetDebugUser::from_validated_clerk_user(&clerk_user("Cathy"), &random_salt, &client)
            .await
            .unwrap();
    assert!(not_found.is_none());
}

/// It would be nice if ClerkUser implemented Default... but it doesn't
/// This code just returned a ClerkUser with all fields as None
pub fn clerk_empty_user() -> ClerkUser {
    serde_json::from_str("{}").unwrap()
}

pub fn clerk_user(id: &str) -> ClerkUser {
    let mut user = clerk_empty_user();
    user.id = Some(id.to_string());
    user
}
