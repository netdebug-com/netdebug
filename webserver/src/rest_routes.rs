use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{Response, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_login::AuthUser;
use gui_types::{
    FirstHopPacketLossReportEntry, FirstHopTimeSeriesData, PublicDeviceDetails, PublicDeviceInfo,
    PublicOrganizationInfo,
};
use libconntrack_wasm::ConnectionMeasurements;
use log::warn;

use uuid::Uuid;

use crate::{
    db_utils::TimeRangeQueryParams,
    devices::{DeviceDetails, DeviceInfo},
    first_hop_analysis::{first_hop_single_device_timeline, first_hop_worst_n_by_packet_loss},
    flows::flow_queries,
    mockable_dbclient::MockableDbClient,
    organizations::OrganizationInfo,
    users::{AuthSession, NetDebugUser},
};

fn check_user(opt_user: Option<NetDebugUser>) -> Result<NetDebugUser, Response<Body>> {
    match opt_user {
        Some(user) => Ok(user),
        None => {
            // warn!("User ")
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Weird - authenticated user not found despite this being a protected route!?"
                    .to_string(),
            )
                .into_response())
        }
    }
}

pub async fn test_auth(
    auth_session: AuthSession,
) -> Result<(axum::http::StatusCode, String), Response<Body>> {
    let user = check_user(auth_session.user)?;
    Ok((StatusCode::OK, format!("Hello {}", user.id())))
}

/// Get a list of devices in the user's org
/// By default, a user can only get devices in their own org
/// Compared to [`get_devices_details()`] this is a cheap call which just reads
/// a single row in the much shorter 'devices' Table
pub async fn get_devices(
    auth_session: AuthSession,
    State(client): State<MockableDbClient>,
) -> Result<Json<Vec<PublicDeviceInfo>>, Response<Body>> {
    let user = check_user(auth_session.user)?;
    match DeviceInfo::get_devices(&user, Some(user.organization_id), client.get_client()).await {
        Ok(devices) => {
            let pub_devices: Vec<PublicDeviceInfo> =
                devices.iter().map(|d| d.clone().into()).collect();
            Ok(Json(pub_devices))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Backend database error: {}", e),
        )
            .into_response()),
    }
}

/// Get a list of devices with flow details in the user's org
/// By default, a user can only get devices in their own org
/// Compared to [`get_devices()`] this is a much more expensive call
/// because it walks the entire desktop_connections Table
pub async fn get_devices_details(
    auth_session: AuthSession,
    State(client): State<MockableDbClient>,
) -> Result<Json<Vec<PublicDeviceDetails>>, Response<Body>> {
    let user = check_user(auth_session.user)?;
    // [`DeviceDetails::get_device_details`] always does auth checks
    // even if in this case, a user is always allowed to see the devices
    // in their own org
    match DeviceDetails::get_devices_details(&user, Some(user.organization_id), client.get_client())
        .await
    {
        Ok(devices) => Ok(Json(devices)),
        Err(e) => {
            warn!("/api/get_devices_detail {:?} :: {}", user, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Backend database error: {}", e),
            )
                .into_response())
        }
    }
}

/// Get a list of devices in the user's org
/// By default, a user can only get devices in their own org
pub async fn get_device(
    Path(uuid): Path<Uuid>,
    auth_session: AuthSession,
    State(client): State<MockableDbClient>,
) -> Result<Json<PublicDeviceDetails>, Response<Body>> {
    let user = check_user(auth_session.user)?;
    // security check is done inside DeviceInfo::from_uuid()
    match DeviceDetails::from_uuid(uuid, &user, client.get_client()).await {
        Ok(d_opt) => match d_opt {
            Some(d) => Ok(Json(d)),
            None => Err((
                StatusCode::NOT_FOUND,
                format!("Uuid {} not found for your org", uuid),
            )
                .into_response()),
        },
        Err(e) => {
            warn!("/api/get_device {} {:?} --> {}", uuid, user, e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Backend database error: {}", e),
            )
                .into_response())
        }
    }
}

pub async fn get_device_flows(
    Path(uuid): Path<Uuid>,
    Query(params): Query<TimeRangeQueryParams>,
    auth_session: AuthSession,
    State(client): State<MockableDbClient>,
) -> Result<Json<Vec<ConnectionMeasurements>>, Response<Body>> {
    let user = check_user(auth_session.user)?;
    match flow_queries(client.get_client(), &user, uuid, params, &[]).await {
        Ok(measurements) => Ok(Json(measurements)),
        Err(e) => {
            warn!("/api/get_device_flows/{}: {}", uuid, e);
            // TODO: don't return the raw error to caller
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Backend database error: {}", e),
            )
                .into_response())
        }
    }
}

pub async fn get_organization_info(
    auth_session: AuthSession,
    State(client): State<MockableDbClient>,
) -> Result<Json<PublicOrganizationInfo>, Response<Body>> {
    let client = client.get_client();
    let user = check_user(auth_session.user)?;
    let organization =
        match OrganizationInfo::from_organization_id(user.organization_id, client).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                warn!("User has no organization info!? {:?}", user);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Missing company info !?".to_string(),
                )
                    .into_response());
            }
            Err(e) => {
                warn!(
                    "Error processing get_organization_info({}):: {}",
                    user.organization_id, e
                );
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database problem".to_string(),
                )
                    .into_response());
            }
        };
    let pub_org: PublicOrganizationInfo = organization.into();
    Ok(Json(pub_org))
}

/// Query for the worst devices by packet_loss for this users's org
pub async fn get_first_hop_top_five_worst_by_packet_loss(
    auth_session: AuthSession,
    Query(params): Query<TimeRangeQueryParams>,
    State(client): State<MockableDbClient>,
) -> Result<Json<Vec<FirstHopPacketLossReportEntry>>, Response<Body>> {
    let client = client.get_client();
    const N: u32 = 5; // const for now
    let user = check_user(auth_session.user)?;
    match first_hop_worst_n_by_packet_loss(&client, N, user.organization_id, &params).await {
        Ok(data) => Ok(Json(data)),
        Err(e) => {
            warn!(
                "Problem running first_hop_worst_n_by_packet_loss(client, n={}, org={}, time={:?}) :: {}",
                N, user.organization_id, params, e
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database Problem".to_string(),
            )
                .into_response())
        }
    }
}

/// Used to ensure any call to /api/WrongUrl doesn't fall down to the default
/// URL handler which just serves an empty index.html and confuses poor developers
pub async fn catchall_api_404(
    _auth_session: AuthSession,
    Path(catchall): Path<String>,
    State(_client): State<MockableDbClient>,
) -> Result<Json<Vec<FirstHopPacketLossReportEntry>>, Response<Body>> {
    Err((
        StatusCode::NOT_FOUND,
        format!("API URL Not Found : /api/{}", catchall),
    )
        .into_response())
}

/// Query for one device's timeseries first-hop data
pub async fn get_first_hop_time_series_data(
    auth_session: AuthSession,
    Path(device_uuid): Path<Uuid>,
    State(client): State<MockableDbClient>,
) -> Result<Json<Vec<Vec<FirstHopTimeSeriesData>>>, Response<Body>> {
    let client = client.get_client();
    let user = check_user(auth_session.user)?;
    // is this user allowed to see this device?
    match DeviceDetails::from_uuid(device_uuid, &user, client.clone()).await {
        Ok(Some(_)) => {
            // device exists and allowed to read; continue
            // we only get here if the user is allowed to access this device
            match first_hop_single_device_timeline(&client, device_uuid).await {
                Ok(data) => Ok(Json(data)),
                Err(e) => {
                    warn!(
                "Problem running first_hop_single_device_timeline(client, device_uuid={}) :: {}",
                device_uuid, e
            );
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Database Problem".to_string(),
                    )
                        .into_response())
                }
            }
        }
        // Ok(None) can mean 'device not found' or 'exists, but this user not allowed to see it'
        // in either case, return 404
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            format!("No such device {}", device_uuid),
        )
            .into_response()),
        Err(e) => {
            warn!(
                "Called DeviceDetails::from_uuid(device_uuid={}, user={:?}, client) :: got {}",
                device_uuid, user, e
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database Problem".to_string(),
            )
                .into_response())
        }
    }
}

#[cfg(test)]
mod test {
    use chrono::DateTime;

    use super::*;

    #[test]
    fn test_time_range_query_param() {
        assert_eq!(
            TimeRangeQueryParams {
                start: None,
                end: None,
            }
            .to_sql_where(),
            ""
        );
        assert_eq!(
            TimeRangeQueryParams {
                start: Some(
                    DateTime::parse_from_rfc3339("2024-01-05T12:34:56.123Z")
                        .unwrap()
                        .into()
                ),
                end: None,
            }
            .to_sql_where(),
            "(start_tracking_time >= '2024-01-05T12:34:56.123Z')"
        );
        assert_eq!(
            TimeRangeQueryParams {
                start: None,
                end: Some(
                    DateTime::parse_from_rfc3339("2024-01-05T12:34:56.123Z")
                        .unwrap()
                        .into()
                ),
            }
            .to_sql_where(),
            "(last_packet_time < '2024-01-05T12:34:56.123Z')"
        );
        assert_eq!(
            TimeRangeQueryParams {
                start: Some(
                    DateTime::parse_from_rfc3339("2024-02-02T01:01:01.123456Z")
                        .unwrap()
                        .into()
                ),
                end: Some(
                    DateTime::parse_from_rfc3339("2024-01-05T12:34:56.123Z")
                        .unwrap()
                        .into()
                ),
            }
            .to_sql_where(),
            "(start_tracking_time >= '2024-02-02T01:01:01.123456Z' AND last_packet_time < '2024-01-05T12:34:56.123Z')"
        );
    }
}
