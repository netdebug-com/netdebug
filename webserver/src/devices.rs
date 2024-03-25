use std::sync::Arc;

use chrono::{DateTime, Utc};
use gui_types::{OrganizationId, PublicDeviceInfo};
use tokio_postgres::{Client, Row};
use uuid::Uuid;

use crate::{
    remotedb_client::{RemoteDBClientError, DEVICE_TABLE_NAME},
    users::NetDebugUser,
};

/// A struct with all of the info in the 'organizations' DB table
/// (public and private)
#[derive(Debug, Clone)]
pub(crate) struct DeviceInfo {
    pub(crate) uuid: Uuid,
    pub(crate) organization_id: OrganizationId,
    pub(crate) name: Option<String>,
    /// Created time of an org could be sensitive
    pub(crate) created: DateTime<Utc>,
    pub(crate) description: Option<String>,
    #[allow(dead_code)] // TODO: do something with this field
    pub(crate) crypt: Option<String>,
    #[allow(dead_code)] // TODO: do something with this field
    pub(crate) salt: Option<String>,
}

impl DeviceInfo {
    /// Lookup all of the organization's details from the remote database
    /// Ok(None) means there was no organization matching that id
    pub async fn from_uuid(
        uuid: Uuid,
        user: &NetDebugUser,
        client: Arc<Client>,
    ) -> Result<Option<DeviceInfo>, RemoteDBClientError> {
        let rows = client
            .query(
                &format!(
                    "SELECT uuid, organization, salt, crypt, name, description, created {} WHERE id = $1",
                    DEVICE_TABLE_NAME
                ),
                &[&uuid],
            )
            .await?;

        let devices = DeviceInfo::rows_to_devices(&rows).await;
        match devices.len() {
            0 => Ok(None),
            // weird: rustfmt doesn't want to format this... 
            1 => {
                    if user.check_org_allowed(devices[0].organization_id) {
                        // if user is allowed to see the device, return it
                        Ok(Some(devices[0].clone()))
                    } else {
                        // but if not, return 'None' for 'device not found' to avoid leaking
                        // information
                        Ok(None)
                   }
                }
            _ => panic!("Database had multiple entries for organization_id even though it's a primary key!?"),
        }
    }

    async fn rows_to_devices(rows: &[Row]) -> Vec<DeviceInfo> {
        rows.iter()
            .map(|row| DeviceInfo {
                uuid: row.get::<_, Uuid>(0),
                organization_id: row.get::<_, i64>(1),
                salt: row.get::<_, Option<String>>(2),
                crypt: row.get::<_, Option<String>>(3),
                name: row.get::<_, Option<String>>(4),
                description: row.get::<_, Option<String>>(5),
                created: row.get::<_, DateTime<Utc>>(6),
            })
            .collect::<Vec<DeviceInfo>>()
    }

    pub async fn get_devices(
        org_id: Option<i64>,
        client: Arc<Client>,
    ) -> Result<Vec<DeviceInfo>, RemoteDBClientError> {
        // NOTE: we don't need to worry about input validation as much here as
        // org_id will always be an int and can't be, e.g., a Little-Bobby-Tables-esque SQL statement
        let where_clause = if let Some(org_id) = org_id {
            format!("WHERE organization = {}", org_id)
        } else {
            String::new()
        };
        let rows = client
            .query(
                &format!(
                    "SELECT uuid, organization, salt, crypt, name, description, created {} {}",
                    DEVICE_TABLE_NAME, where_clause
                ),
                &[],
            )
            .await?;

        Ok(DeviceInfo::rows_to_devices(&rows).await)
    }
}

impl From<DeviceInfo> for PublicDeviceInfo {
    fn from(value: DeviceInfo) -> Self {
        // Assume the 'created' field is private info and don't copy into the Public struct
        // this is a weak/arguable point, but let's keep this public struct/private struct
        // pattern to enforce people thinking about privacy
        PublicDeviceInfo {
            uuid: value.uuid,
            name: value.name.clone(),
            organization_id: value.organization_id,
            description: value.description.clone(),
            created: value.created,
        }
    }
}
