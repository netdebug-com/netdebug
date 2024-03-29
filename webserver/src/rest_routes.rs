use axum::{
    body::Body,
    extract::{Path, State},
    http::{Response, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_login::AuthUser;
use gui_types::{PublicDeviceDetails, PublicDeviceInfo, PublicOrganizationInfo};
use log::warn;
use uuid::Uuid;

use crate::{
    devices::{DeviceDetails, DeviceInfo},
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
