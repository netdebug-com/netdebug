use std::net::{IpAddr, SocketAddr};

use crate::context::Context;
use crate::users::{AuthCredentials, AuthSession, NetDebugUserBackend, UserServiceData};
use crate::{desktop_websocket, webtest};
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Router;
use axum::{routing, Form};
use axum_extra::TypedHeader;
use axum_login::tower_sessions::{MemoryStore, SessionManagerLayer};
use axum_login::{login_required, AuthManagerLayerBuilder, AuthUser};
use common_wasm::timeseries_stats::{CounterProvider, CounterProviderWithTimeUpdate};
use log::{info, warn};
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

    // Session layer.
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store);

    // Auth layer
    let service_secret = context.read().await.user_service_secret.clone();
    let user_service = UserServiceData::new_locked(service_secret).await;
    let backend = NetDebugUserBackend::new(user_service);
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    Router::new()
        // list the paths that need authentication here
        .route("/test_auth", routing::get(test_auth))
        .route_layer(login_required!(NetDebugUserBackend))
        .route("/login", routing::post(console_login))
        .route("/login", routing::get(console_login))
        .layer(auth_layer)
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
    // for now, just warn!() if there's no auth and make up a client_id; later we will enforce
    let client_id = if let Some(auth) = auth {
        if let Ok(client_id) = Uuid::try_parse(auth.token()) {
            info!(
                "Desktop Websocket request from {}, client_id {}",
                addr.ip(),
                client_id
            );
            client_id
        } else {
            let client_id = make_uuid_from_ip(addr.ip());
            warn!(
                "Received an invalid UUID from {}. Bad ID: `{}` - making an IP-based one {}",
                addr.ip(),
                auth.token(),
                client_id
            );
            client_id
        }
    } else {
        let client_id = make_uuid_from_ip(addr.ip());
        warn!(
            "Received no auth header / client UUID from {} - making up an IP-based one - {}",
            addr.ip(),
            client_id
        );
        client_id
    };
    // finalize the upgrade process by returning upgrade callback.
    ws.on_upgrade(move |socket| {
        desktop_websocket::handle_desktop_websocket(socket, context, client_id, user_agent, addr)
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

async fn test_auth(auth_session: AuthSession) -> impl IntoResponse {
    match auth_session.user {
        Some(user) => (StatusCode::OK, format!("Hello {}", user.id())),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Weird - authenticated user not found!?".to_string(),
        ),
    }
    .into_response()
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
