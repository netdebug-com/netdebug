use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Utc};
use gui_types::{OrganizationId, PublicDeviceDetails, PublicDeviceInfo};
use itertools::Itertools;
use log::warn;
use tokio_postgres::{Client, Row};
use uuid::Uuid;

use crate::{
    db_utils::{AggregatedFlowCategoryQueryParams, TimeRangeQueryParams},
    flows::{get_aggregated_flow_view, AggregatedFlowCategory, AggregatedFlowRow},
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
        client: &Client,
    ) -> Result<Vec<DeviceInfo>, RemoteDBClientError> {
        user.check_org_allowed_or_fail(org_id)?;
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

fn add_loss_cnt_helper(old_value: &mut Option<u64>, add_loss: i64) {
    let loss = old_value.unwrap_or_default() + add_loss as u64;
    if loss == 0 {
        old_value.take();
    } else {
        old_value.replace(loss);
    };
}

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
        // TODO: currently, `get_aggregated_flow_view()` only filters by org_id, not device
        let agg_rows = get_aggregated_flow_view(
            user,
            Some(device.organization_id),
            TimeRangeQueryParams::default(),
            AggregatedFlowCategoryQueryParams {
                query_total: true,
                ..Default::default()
            },
            &client,
        )
        .await?
        .into_iter()
        .filter(|r| r.category == AggregatedFlowCategory::Total && r.aggregate.device_uuid == uuid)
        .collect_vec();
        let mut device_details =
            DeviceDetails::agg_rows_to_device_details(&[device.clone()], &agg_rows, true);
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

    fn agg_rows_to_device_details(
        device_infos: &[DeviceInfo],
        rows: &[AggregatedFlowRow],
        should_include_no_flows: bool,
    ) -> Vec<PublicDeviceDetails> {
        // 1st, build a map from uuid to DeviceInfo
        let mut uuid2device_details: HashMap<Uuid, PublicDeviceDetails> =
            HashMap::from_iter(device_infos.iter().map(|d| {
                (
                    d.uuid,
                    PublicDeviceDetails {
                        device_info: d.clone().into(),
                        num_flows_stored: 0,
                        num_flows_with_send_loss: None,
                        num_flows_with_recv_loss: None,
                        oldest_flow_time: None,
                        newest_flow_time: None,
                    },
                )
            }));
        for row in rows
            .iter()
            .filter(|r| r.category == AggregatedFlowCategory::Total)
        {
            let uuid = row.aggregate.device_uuid;
            if let Some(device_details) = uuid2device_details.get_mut(&uuid) {
                device_details.num_flows_stored += row.aggregate.num_flows as u64;
                let ts = row.bucket_start;
                device_details.oldest_flow_time = Some(std::cmp::min(
                    device_details.oldest_flow_time.unwrap_or(ts),
                    ts,
                ));
                device_details.newest_flow_time = Some(std::cmp::min(
                    device_details.newest_flow_time.unwrap_or(ts),
                    ts,
                ));

                add_loss_cnt_helper(
                    &mut device_details.num_flows_with_recv_loss,
                    row.aggregate.num_flows_with_rx_loss,
                );
                add_loss_cnt_helper(
                    &mut device_details.num_flows_with_send_loss,
                    row.aggregate.num_flows_with_tx_loss,
                );
            } else {
                warn!(
                    "Device {} in aggregated flow view but not in Table 'devices'",
                    uuid
                );
            }
        }
        uuid2device_details
            .into_values()
            .filter(|dev| should_include_no_flows || dev.num_flows_stored > 0)
            .collect_vec()
    }

    /// Query DB and return a list of complex details about all devices
    /// If org_id is not None, then only return devices in that org_id
    pub(crate) async fn get_devices_details(
        user: &NetDebugUser,
        org_id: Option<i64>,
        client: Arc<Client>,
    ) -> Result<Vec<PublicDeviceDetails>, RemoteDBClientError> {
        let device_infos = DeviceInfo::get_devices(user, org_id, &client).await?;
        user.check_org_allowed_or_fail(org_id)?;

        // TODO: Ideally, we only want to query for `Total` aggregation and not by_app
        // and by_dest_dns_domain.
        let agg_flows = get_aggregated_flow_view(
            user,
            org_id,
            TimeRangeQueryParams::default(),
            AggregatedFlowCategoryQueryParams {
                query_total: true,
                ..Default::default()
            },
            &client,
        )
        .await?;
        // OK to use unescaped formatting here b/c it's just an int
        Ok(DeviceDetails::agg_rows_to_device_details(
            &device_infos,
            &agg_flows,
            false, // don't show devices with no stored flows
        ))
    }
}
