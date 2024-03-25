use std::sync::Arc;

use chrono::{DateTime, Utc};
use gui_types::{OrganizationId, PublicOrganizationInfo};
use tokio_postgres::Client;

use crate::remotedb_client::{RemoteDBClientError, ORGANIZATION_TABLE_NAME};

pub const NETDEBUG_EMPLOYEE_ORG_ID: OrganizationId = 1;

/// A struct with all of the info in the 'organizations' DB table
/// (public and private)
pub(crate) struct OrganizationInfo {
    pub(crate) id: OrganizationId, // NOTE: SQL does not support u64
    pub(crate) name: Option<String>,
    pub(crate) admin_contact: Option<String>,
    /// Created time of an org could be sensitive
    #[allow(dead_code)] // TODO: do something with this field
    pub(crate) created: DateTime<Utc>,
    pub(crate) description: Option<String>,
}

impl OrganizationInfo {
    /// Lookup all of the organization's details from the remote database
    /// Ok(None) means there was no organization matching that id
    pub async fn from_organization_id(
        organization_id: i64,
        client: Arc<Client>,
    ) -> Result<Option<OrganizationInfo>, RemoteDBClientError> {
        let rows = client
            .query(
                &format!(
                    "SELECT id, name, admin_contact, created, description FROM {} WHERE id = $1",
                    ORGANIZATION_TABLE_NAME
                ),
                &[&organization_id],
            )
            .await?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(OrganizationInfo {
                id: rows[0].get::<_, i64>(0),
                name: rows[0].get::<_, Option<String>>(1),
                admin_contact: rows[0].get::<_, Option<String>>(2),
                created: rows[0].get::<_, DateTime<Utc>>(3),
                description: rows[0].get::<_, Option<String>>(4),
            })),
            _ => panic!("Database had multiple entries for organization_id even though it's a primary key!?"),
        }
    }
}

impl From<OrganizationInfo> for PublicOrganizationInfo {
    fn from(value: OrganizationInfo) -> Self {
        // Assume the 'created' field is private info and don't copy into the Public struct
        // this is a weak/arguable point, but let's keep this public struct/private struct
        // pattern to enforce people thinking about privacy
        PublicOrganizationInfo {
            id: value.id,
            name: value.name.clone(),
            description: value.description.clone(),
            admin_contact: value.admin_contact.clone(),
        }
    }
}
