use axum::{
    body::Body,
    extract::State,
    http::{Response, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_login::AuthUser;
use gui_types::PublicOrganizationInfo;
use log::{info, warn};

use crate::{
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
    info!("Testauth");
    let user = check_user(auth_session.user)?;
    info!("Testauth: {}", user.user_id);
    Ok((StatusCode::OK, format!("Hello {}", user.id())))
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
