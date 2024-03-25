use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::context::Context;
use crate::mockable_dbclient::MockableDbClient;
use crate::remotedb_client::RemoteDBClient;
use crate::rest_routes::{get_device, get_devices, get_organization_info, test_auth};
use crate::secrets_db::Secrets;
use crate::users::{AuthCredentials, AuthSession, NetDebugUserBackend, UserServiceData};
use crate::{desktop_websocket, webtest};
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Router;
use axum::{routing, Form};
use axum_extra::TypedHeader;
use axum_login::tower_sessions::{MemoryStore, SessionManagerLayer, SessionStore};
use axum_login::{predicate_required, AuthManagerLayer, AuthManagerLayerBuilder, AuthnBackend};
use common_wasm::timeseries_stats::{CounterProvider, CounterProviderWithTimeUpdate};
#[cfg(not(test))]
use log::{info, warn};
#[cfg(test)]
use std::{println as info, println as warn};
use tower_http::cors::CorsLayer;

use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use uuid::Uuid;
/* TODO: remove. These are used for the cookie stuff with axum
use axum::http::header::SET_COOKIE;
use asum::response;
use axum::response::Html;
*/

type BearerAuthHeader = headers::Authorization<headers::authorization::Bearer>;

pub fn serve_dir_and_check_path<S: AsRef<str>>(path: S) -> ServeDir {
    let path = path.as_ref();
    assert!(
        std::path::Path::new(path).is_dir(),
        "Directory `{}` does not exist",
        path
    );
    ServeDir::new(path)
}

pub async fn setup_axum_http_routes(context: Context) -> Router {
    let html_root = context.read().await.html_root.clone();
    assert!(
        std::path::Path::new(&html_root).is_dir(),
        "HTML root directory `{}` does not exist",
        html_root
    );
    let wasm_root = context.read().await.wasm_root.clone();
    assert!(
        std::path::Path::new(&wasm_root).is_dir(),
        "WASM root directory `{}` does not exist",
        wasm_root
    );

    let index_html_service = ServeFile::new(html_root.clone() + "/index.html");
    // Basic Request logging
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(tracing::Level::DEBUG));

    Router::new()
        // Webtest related routes
        .nest_service(
            "/webtest_static",
            serve_dir_and_check_path(html_root.clone() + "/webtest_static"),
        )
        .nest_service(
            "/static",
            serve_dir_and_check_path(html_root.clone() + "/webtest_static"),
        )
        .nest_service("/webclient", serve_dir_and_check_path(&wasm_root))
        // maybe we should just statically serve / as a fallback if no more spe
        .route_service("/index.html", index_html_service.clone())
        .route_service("/", index_html_service)
        .route_service(
            "/webtest",
            ServeFile::new(html_root.clone() + "/webtest.html"),
        )
        .route_service(
            "/webtest_8338550042",
            ServeFile::new(html_root.clone() + "/webtest.html"),
        )
        // WebSocket for webtest
        .route("/ws", routing::get(webtest_ws_handler))
        // counters
        .route("/counters/get_counters", routing::get(get_counters_handler))
        // websocket from desktop
        .route("/desktop", routing::get(desktop_ws_handler))
        // Console / Auth stuff
        .nest_service(
            "/console",
            // HACK! Assume the webui directory is always relative to the HTML one
            serve_dir_and_check_path(html_root.clone() + "/../../frontend/console/dist"),
        )
        .nest_service(
            "/assets",
            // HACK! Assume the webui directory is always relative to the HTML one
            serve_dir_and_check_path(html_root.clone() + "/../../frontend/console/dist/assets"),
        )
        .nest("/api", setup_protected_rest_routes(context.clone()).await)
        .layer(trace_layer)
        .with_state(context)
    /*
    .route("/setcookie", routing::get(setcookie))
    .route("/checkcookie", routing::get(checkcookie))
    */
}

pub async fn setup_protected_rest_routes(context: Context) -> Router<Context> {
    // TODO: move the session store into the data base layer like in
    // https://github.com/maxcountryman/axum-login/blob/main/examples/sqlite/src/web/app.rs#L34
    let (production, secrets) = {
        let lock = context.read().await;
        (lock.production, lock.secrets.clone())
    };

    let (service_secret, prod) = {
        if production {
            (secrets.clerk_auth_prod_secret.clone(), "production")
        } else {
            (secrets.clerk_auth_dev_secret.clone(), "dev")
        }
    };
    let service_secret = match service_secret {
        Some(s) => s,
        None => panic!(
            "Tried to connect to clerk without the {} secret in the secrets file",
            prod
        ),
    };
    let user_service = UserServiceData::new_locked(service_secret).await;
    let backend = NetDebugUserBackend::new(user_service, &secrets)
        .await
        .expect("Errors from RemoteDBClient");
    let session_store = MemoryStore::default();
    // this sets or doesn't set the 'Secure' line in the SetCookie :
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
    let secure_cookie = production;
    let session_layer = SessionManagerLayer::new(session_store)
        .with_name("netdebug_session_cookie")
        .with_secure(secure_cookie);

    // Auth layer
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();
    let routes = setup_protected_rest_routes_with_auth_layer(auth_layer, secrets).await;
    if production {
        // production routes always have all of the CORS checks
        routes
    } else {
        // relax CORS checks for local testing; allows us to run frontend in 'npm run dev' mode
        info!("Relaxing CORS Permissions in Development mode for 'cd frontend/console && npm run dev'");
        routes.layer(CorsLayer::very_permissive())
    }
}

pub async fn db_client_loop_until_connect(secrets: &Secrets) -> MockableDbClient {
    if cfg!(test) {
        // TODO: decide if we always want a mock when cfg!(test) is true
        // NOTE: cfg!(test) is false during integration tests
        MockableDbClient::new_mock()
    } else {
        // reconnect infinitely with expoential backoff
        let mut sleep_time = Duration::from_millis(100);
        let max_sleep_time = Duration::from_secs(15);
        loop {
            match RemoteDBClient::make_read_only_client(secrets).await {
                Ok(client) => return MockableDbClient::from(client),
                Err(e) => {
                    warn!(
                        "Failed to connect to backend DB - retrying in {:?}- {}",
                        sleep_time, e
                    );
                    tokio::time::sleep(sleep_time).await;
                    sleep_time = std::cmp::min(2 * sleep_time, max_sleep_time);
                }
            }
        }
    }
}

pub async fn setup_protected_rest_routes_with_auth_layer<
    Backend: AuthnBackend + Clone + 'static,
    Session: SessionStore + Clone,
>(
    auth_layer: AuthManagerLayer<Backend, Session>,
    secrets: Secrets,
) -> Router<Context> {
    // This is a helper function copied out of login_requred!() macro which
    // didn't support generic types
    async fn is_authenticated<Backend2: AuthnBackend + Clone + 'static>(
        auth_session: axum_login::AuthSession<Backend2>,
    ) -> bool {
        auth_session.user.is_some()
    }

    let client = db_client_loop_until_connect(&secrets).await;
    Router::new()
        // list the paths that need authentication here
        .route("/test_auth", routing::get(test_auth))
        .route("/get_device/:uuid", routing::get(get_device))
        .route("/get_devices", routing::get(get_devices))
        .route("/organization_info", routing::get(get_organization_info))
        // don't use the login_required!() macro : can't figure out generic types so manually expand
        .route_layer(predicate_required!(
            is_authenticated::<Backend>,
            StatusCode::UNAUTHORIZED
        ))
        // these are unauthenticated routes to get the auth token
        .route("/login", routing::post(console_login))
        // TODO: decide whether having a login() function as a GET is a CSRV vulnerability
        .route("/login", routing::get(console_login))
        .layer(auth_layer)
        .with_state(client)
}

/// The handler for the HTTP request (this gets called when the HTTP GET lands at the start
/// of websocket negotiation). After this completes, the actual switching from HTTP to
/// websocket protocol will occur.
/// This is the last point where we can extract TCP/IP metadata such as IP address of the client
/// as well as things from HTTP headers such as user-agent of the browser etc.
async fn webtest_ws_handler(
    ws: WebSocketUpgrade,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(context): State<Context>,
) -> impl IntoResponse {
    let user_agent = if let Some(TypedHeader(user_agent)) = user_agent {
        user_agent.to_string()
    } else {
        String::from("Unknown browser")
    };
    // finalize the upgrade process by returning upgrade callback.
    ws.on_upgrade(move |socket| webtest::handle_websocket(socket, context, user_agent, addr))
}

fn make_uuid_from_ip(ip: IpAddr) -> Uuid {
    Uuid::new_v3(&Uuid::NAMESPACE_DNS, ip.to_string().as_bytes())
}

async fn desktop_ws_handler(
    ws: WebSocketUpgrade,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    auth: Option<TypedHeader<BearerAuthHeader>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(context): State<Context>,
) -> impl IntoResponse {
    let user_agent = if let Some(TypedHeader(user_agent)) = user_agent {
        user_agent.to_string()
    } else {
        String::from("Unknown browser")
    };
    // for now, just warn!() if there's no auth and make up a device_uuid; later we will enforce
    let device_uuid = if let Some(auth) = auth {
        if let Ok(device_uuid) = Uuid::try_parse(auth.token()) {
            info!(
                "Desktop Websocket request from {}, device_uuid {}",
                addr.ip(),
                device_uuid
            );
            device_uuid
        } else {
            let device_uuid = make_uuid_from_ip(addr.ip());
            warn!(
                "Received an invalid UUID from {}. Bad ID: `{}` - making an IP-based one {}",
                addr.ip(),
                auth.token(),
                device_uuid
            );
            device_uuid
        }
    } else {
        let device_uuid = make_uuid_from_ip(addr.ip());
        warn!(
            "Received no auth header / client UUID from {} - making up an IP-based one - {}",
            addr.ip(),
            device_uuid
        );
        device_uuid
    };
    // finalize the upgrade process by returning upgrade callback.
    ws.on_upgrade(move |socket| {
        desktop_websocket::handle_desktop_websocket(socket, context, device_uuid, user_agent, addr)
    })
}

async fn get_counters_handler(State(context): State<Context>) -> String {
    let registries = context.read().await.counter_registries.clone();
    // IndexMap iterates over entries in insertion order
    let mut map = indexmap::IndexMap::<String, u64>::new();
    registries.lock().unwrap().update_time();
    registries.lock().unwrap().append_counters(&mut map);
    serde_json::to_string_pretty(&map).unwrap()
}

async fn console_login(
    mut auth_session: AuthSession,
    Form(creds): Form<AuthCredentials>,
) -> impl IntoResponse {
    let user = match auth_session.authenticate(creds.clone()).await {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => {
            warn!("console_login error: {}", e);
            // don't return the error message to the user for 'security' reasons
            return (StatusCode::INTERNAL_SERVER_ERROR, "".to_string()).into_response();
        }
    };

    if auth_session.login(&user).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Redirect::to("/protected").into_response()
    StatusCode::OK.into_response()
}

/*
TODO: keeping this for now since it shows how to set and get cookies with axum.
That being said. There are a lot of higher level abstractions in axum to handle
cookies, sessions, etc. So this low level mucking around is not the way to go
long term

pub async fn checkcookie(TypedHeader(raw_cookie): TypedHeader<headers::Cookie>) -> String {
    let value = raw_cookie.get(COOKIE_LOGIN_NAME);
    format!("The cookie is: {:?}", value)
}

pub async fn setcookie() -> impl IntoResponse {
    let cookie = format!(
        "{}=SUCCESS; Path=/; HttpOnly; Max-Age=1209600",
        COOKIE_LOGIN_NAME
    );
    let headers = [(SET_COOKIE, cookie)];
    let content = Html("<h1>Hello, World!</h1>");
    (headers, content)
}
*/
