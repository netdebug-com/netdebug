use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use gui_types::{OrganizationId, PublicDeviceDetails, PublicDeviceInfo};
use log::warn;
use tokio_postgres::{Client, Row};
use uuid::Uuid;

use crate::{
    remotedb_client::{RemoteDBClientError, CONNECTIONS_TABLE_NAME, DEVICE_TABLE_NAME},
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
                    "SELECT uuid, organization, salt, crypt, name, description, created FROM {} WHERE uuid = $1",
                    DEVICE_TABLE_NAME
                ),
                &[&uuid],
            )
            .await?;

        let devices = DeviceInfo::rows_to_device_infos(&rows).await;
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

    async fn rows_to_device_infos(rows: &[Row]) -> Vec<DeviceInfo> {
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
        user: &NetDebugUser,
        org_id: Option<i64>,
        client: Arc<Client>,
    ) -> Result<Vec<DeviceInfo>, RemoteDBClientError> {
        // NOTE: we don't need to worry about input validation as much here as
        // org_id will always be an int and can't be, e.g., a Little-Bobby-Tables-esque SQL statement
        let where_clause = if let Some(org_id) = org_id {
            if !user.check_org_allowed(org_id) {
                return Err(RemoteDBClientError::PermissionDenied {
                    err: format!(
                        "User {} with org {} tried to access org {}",
                        user.user_id, user.organization_id, org_id
                    ),
                });
            }
            format!("WHERE organization = {}", org_id)
        } else {
            if !user.check_org_superuser() {
                return Err(RemoteDBClientError::PermissionDenied {
                    err: format!(
                        "User {} with org {} tried to access all orgs",
                        user.user_id, user.organization_id
                    ),
                });
            }
            String::new()
        };
        let rows = client
            .query(
                &format!(
                    "SELECT uuid, organization, salt, crypt, name, description, created FROM {} {}",
                    DEVICE_TABLE_NAME, where_clause
                ),
                &[],
            )
            .await?;

        Ok(DeviceInfo::rows_to_device_infos(&rows).await)
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

pub struct DeviceDetails {
    // no state for now
}

/// The shared parts of the DeviceDetails query, e.g., that
/// the [`DeviceDetails::rows_to_device_infos()`] expects
const DEVICE_DETAILS_PARTIAL_QUERY: &str = "SELECT 
            COUNT(*), MIN(time), MAX(time), 
            SUM(CASE WHEN tx_loss > 0 THEN 1 ELSE 0 END), 
            SUM(CASE WHEN rx_loss > 0 THEN 1 ELSE 0 END) ,
            device_uuid";
impl DeviceDetails {
    /// Pull the PublicDeviceDetails struct from the remote database, if the user is allowed to see it
    /// TODO: currently implemented over multiple SQL queries... monitor this to see if it becomes
    /// a perf bottleneck and consider redesign
    pub async fn from_uuid(
        uuid: Uuid,
        user: &NetDebugUser,
        client: Arc<Client>,
    ) -> Result<Option<PublicDeviceDetails>, RemoteDBClientError> {
        // lookup the org_id from the devices table
        let device_info = DeviceInfo::from_uuid(uuid, user, client.clone()).await?;
        if device_info.is_none() {
            return Ok(None); // device either missing or this user is not allowed to see it
        }
        let device = device_info.unwrap();
        let db_statement = client
            .prepare(&format!(
                "{} from {} WHERE device_uuid=$1 GROUP BY device_uuid",
                DEVICE_DETAILS_PARTIAL_QUERY, CONNECTIONS_TABLE_NAME
            ))
            .await?;
        // Do NOT call .query_one() here as if there are no flows in desktop_connections, then zero rows will return
        let rows = client.query(&db_statement, &[&uuid]).await?;
        let mut device_details =
            DeviceDetails::rows_to_device_details(&[device.clone()], &rows).await;
        match device_details.len() {
            // case: no flows recored in desktop_connections
            0 => Ok(Some(PublicDeviceDetails {
                device_info: device.into(),
                num_flows_stored: 0,
                num_flows_with_send_loss: None,
                num_flows_with_recv_loss: None,
                oldest_flow_time: None,
                newest_flow_time: None,
            })),
            // normal case, got exactly one device with flow data
            1 => Ok(Some(device_details.pop().unwrap())),
            _ => Err(RemoteDBClientError::DbInvariateError {
                err: format!("Db returned multiple rows with a single uuid!? {}", uuid),
            }),
        }
    }

    /// Join the data from DeviceInfo's and rows from the Details query into a single unified PublicDeviceDetails struct
    async fn rows_to_device_details(
        device_infos: &[DeviceInfo],
        rows: &[Row],
    ) -> Vec<PublicDeviceDetails> {
        // 1st, build a map from uuid to DeviceInfo
        let uuid2info: HashMap<Uuid, &DeviceInfo> =
            HashMap::from_iter(device_infos.iter().map(|d| (d.uuid, d)));
        rows.iter()
            .filter_map(|row| {
                // we could in theory do a join at the DB level rather than two queries at the rust level
                // but since we already need the data from the first query and I'm a little concerned about
                // the performance of the query once we hit scale anyway, let's leave it as it is...
                let uuid = row.get::<_, Uuid>(5); // extract the device_uuid
                if let Some(device_info) = uuid2info.get(&uuid) {
                    let public_device_info: PublicDeviceInfo = (*device_info).clone().into();
                    Some(PublicDeviceDetails {
                        // convert all of the i64's to u64 to hide Postgres's inability to count that high
                        num_flows_stored: row.get::<_, i64>(0) as u64,
                        oldest_flow_time: row.get::<_, Option<DateTime<Utc>>>(1),
                        newest_flow_time: row.get::<_, Option<DateTime<Utc>>>(2),
                        num_flows_with_send_loss: row.get::<_, Option<i64>>(3).map(|v| v as u64),
                        num_flows_with_recv_loss: row.get::<_, Option<i64>>(4).map(|v| v as u64),
                        device_info: public_device_info,
                    })
                } else {
                    warn!(
                        "Device {} in Table desktop_connections but not in Table 'devices'",
                        uuid
                    );
                    None
                }
            })
            .collect::<Vec<PublicDeviceDetails>>()
    }

    /// Query DB and return a list of complex details about all devices
    /// If org_id is not None, then only return devices in that org_id
    pub(crate) async fn get_devices_details(
        user: &NetDebugUser,
        org_id: Option<i64>,
        client: Arc<Client>,
    ) -> Result<Vec<PublicDeviceDetails>, RemoteDBClientError> {
        let device_infos = DeviceInfo::get_devices(user, org_id, client.clone()).await?;
        // OK to use unescaped formatting here b/c it's just an int
        let org_qualifier = if let Some(org_id) = org_id {
            if !user.check_org_allowed(org_id) {
                return Err(RemoteDBClientError::PermissionDenied {
                    err: format!(
                        "User in org {} tried to access {}",
                        user.organization_id, org_id
                    ),
                });
            }
            format!("WHERE devices.organization = {}", org_id)
        } else {
            if !user.check_org_superuser() {
                return Err(RemoteDBClientError::PermissionDenied {
                    err: format!(
                        "User in org {} tried to access all orgs devices",
                        user.organization_id
                    ),
                });
            }
            "".to_string()
        };
        // TODO: monitor the perf of this JOIN and see if we need to put the 'org_id' directly
        // into the desktop_connections schema
        let db_statement = client
            .prepare(&format!(
                "{} from {} 
                INNER JOIN devices ON desktop_connections.device_uuid = devices.uuid 
                {} -- WHERE clause, if org_id isn't None
                GROUP BY device_uuid",
                DEVICE_DETAILS_PARTIAL_QUERY, CONNECTIONS_TABLE_NAME, org_qualifier
            ))
            .await?;
        let rows = client.query(&db_statement, &[]).await?;
        Ok(DeviceDetails::rows_to_device_details(&device_infos, &rows).await)
    }
}
