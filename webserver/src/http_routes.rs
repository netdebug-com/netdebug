use std::fs;
use std::net::SocketAddr;

use crate::context::{Context, LoginInfo, COOKIE_LOGIN_NAME};
use crate::{desktop_websocket, webtest};
use common_wasm::timeseries_stats::{
    CounterProvider, CounterProviderWithTimeUpdate, SharedExportedStatRegistries,
};
use log::debug;
use warp::filters::log::{custom as warp_log, Info};
use warp::http::StatusCode;
use warp::{cookie::cookie, Filter, Reply};

/**
 * This library is used by both desktop and webserver apps but
 * this function is only for the webserver (e.g., is passwd protected), thus the name.
 */

pub async fn make_webserver_http_routes(
    context: Context,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    // cache these so we don't need a lock every time to access
    let wasm_root = context.read().await.wasm_root.clone();
    let html_root = context.read().await.html_root.clone();
    let counter_registries = context.read().await.counter_registries.clone();

    let login = make_login_route(&context).with(warp_log(|i| custom_logger1("login", i)));
    let webtest = make_webtest_route(&context).with(warp_log(|i| custom_logger1("webtest", i)));
    let webtest_no_auth = make_webtest_no_auth_route(&context, &html_root)
        .with(warp_log(|i| custom_logger1("webtest_no_auth", i)));
    let webclient =
        make_webclient_route(&wasm_root).with(warp_log(|i| custom_logger1("webclient", i)));
    let webclient_ws =
        make_webclient_ws_route(&context).with(warp_log(|i| custom_logger1("websocket", i)));
    let desktop_ws =
        make_desktop_ws_route(&context).with(warp_log(|i| custom_logger1("desktop_ws", i)));
    let web_console = warp::path("console")
        .and(warp::fs::dir(
            // HACK! Assume the webui directory is always relative to the HTML one
            format!("{}/../netdebug_webui/dist", html_root),
        ))
        .with(warp_log(|i| custom_logger1("console", i)));
    let web_assets = warp::path("assets")
        .and(warp::fs::dir(
            // HACK! Assume the webui directory is always relative to the HTML one
            format!("{}/../netdebug_webui/dist/assets", html_root),
        ))
        .with(warp_log(|i| custom_logger1("console", i)));
    let static_path = warp::path("webtest_static")
        .and(warp::fs::dir(format!("{}/webtest_static", html_root)))
        .with(warp_log(|i| custom_logger1("static", i)));

    // can only access if there's an auth cookie
    let root = make_root_route(&context).with(warp_log(|i| custom_logger1("root", i)));

    // default where we direct people with no auth cookie to get one
    let login_form =
        make_login_form_route(&context, &html_root).with(warp_log(|i| custom_logger1("login", i)));

    let counters =
        make_counter_routes(counter_registries).with(warp_log(|i| custom_logger1("counters", i)));

    // this is the order that the filters try to match; it's important that
    // it's in this order to make sure the cookie auth works right

    webtest
        .or(webtest_no_auth)
        .or(web_console)
        .or(web_assets)
        .or(desktop_ws)
        .or(webclient_ws)
        .or(counters)
        .or(webclient)
        .or(static_path)
        .or(root)
        .or(login)
        .or(login_form)
}

/**
 * warp tells us all of the routes that DON'T match which creates a lot of noise.
 * Show anything that didn't match as debug!() and anything else as info!()
 *
 * DOESN'T COMPLILE - so frustrating!!
 */
/*
fn custom_logger<F>(module: &str) -> warp::filters::log::Log<F>
where
    F: Fn(warp::filters::log::Info<'_>),
{
    warp::log::custom(|info: warp::filters::log::Info<'_>| {
        {
            if info.status() == warp::http::StatusCode::NOT_FOUND {
                debug!("{} :: {:?}", module, format_log_info(&info));
            } else {
                log::info!("{} :: {:?}", module, format_log_info(&info));
            }
        }
        .into()
    })
}
*/

fn custom_logger1(module: &str, info: Info<'_>) {
    if info.status() == warp::http::StatusCode::NOT_FOUND {
        debug!("{} :: {:?}", module, format_log_info(&info));
    } else {
        log::info!("{} :: {:?}", module, format_log_info(&info));
    }
}

// why doesn't just just implement Debug like a sane struct?
fn format_log_info(info: &warp::filters::log::Info<'_>) -> String {
    format!(
        "{:?} {:?} {:?} refer={:?} status={} user-agent=\"{:?}\"",
        info.remote_addr(),
        info.method(),
        info.path(),
        info.referer(),
        info.status(),
        info.user_agent(),
        // don't log the request headers as they might have a password, but might be useful too
    )
}

pub fn make_counter_routes(
    registries: SharedExportedStatRegistries,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    // FIXME: Should we put this route behind the loging? Probably yes.
    warp::path!("counters" / "get_counters").map(move || {
        // IndexMap iterates over entries in insertion order
        let mut map = indexmap::IndexMap::<String, u64>::new();
        registries.lock().unwrap().update_time();
        registries.lock().unwrap().append_counters(&mut map);
        serde_json::to_string_pretty(&map).unwrap()
    })
}

fn make_webclient_ws_route(
    context: &Context,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("ws")
        .and(with_context(context))
        .and(warp::header("user-agent"))
        .and(warp::ws())
        .and(warp::filters::addr::remote())
        .and_then(webclient_websocket_handler)
}
fn make_desktop_ws_route(
    context: &Context,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("desktop")
        .and(with_context(context))
        .and(warp::header("user-agent"))
        .and(warp::ws())
        .and(warp::filters::addr::remote())
        .and_then(desktop_websocket_handler)
}

fn make_login_route(
    context: &Context,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    // POST login data to http://localhost/login to get auth cookie
    warp::post()
        .and(warp::path("login"))
        .and(with_context(context))
        .and(warp::body::json())
        .and_then(login_handler)
}

fn make_root_route(
    context: &Context,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::any()
        .and(with_context(context))
        .and(cookie(COOKIE_LOGIN_NAME))
        .and_then(root)
}

fn make_webtest_route(
    context: &Context,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("webtest")
        .and(with_context(context))
        .and(cookie(COOKIE_LOGIN_NAME))
        .and_then(webtest)
}

// Temp. hack so we can access the webtewst from the desktop
fn make_webtest_no_auth_route(
    _context: &Context,
    html_root: &String,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("webtest_8338550042") // just a random string. High security ;-)
        .and(warp::get())
        .and(warp::fs::file(format!("{}/webtest.html", html_root)))
}

pub fn make_webclient_route(
    wasm_root: &str,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    /* First pass, with cookie checking
    warp::path("webclient")
        .and(with_context(&context))
        .and(cookie(COOKIE_LOGIN_NAME))
        .and(with_string(&wasm_root))
        .and(warp::path::param::<String>())
        .and_then(webclient)
    */
    // second pass, with no cookie checking
    if !std::path::Path::new(wasm_root).is_dir() {
        // if wasm-pack didn't run, just die horribly; otherwise
        // we will just serve the wrong pages and it gets confusing
        panic!("Wasm directory doesn't exist!? - {}", wasm_root);
    }
    warp::path("webclient").and(warp::fs::dir(wasm_root.to_owned()))
}

fn make_login_form_route(
    _context: &Context,
    html_root: &String,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::get())
        .and(warp::fs::file(format!("{}/login.html", html_root)))
}

fn with_context(
    context: &Context,
) -> impl Filter<Extract = (Context,), Error = std::convert::Infallible> + Clone {
    let context = context.clone();
    warp::any().map(move || context.clone())
}

/*
fn with_handler(
    handler: WebSocketHandler,
) -> impl Filter<Extract = (WebSocketHandler,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || handler.clone())
}
*/

fn _with_string(
    s: &str,
) -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Clone {
    let s = s.to_owned();
    warp::any().map(move || s.clone())
}

/**
 * Check cookie and if good, serve the file
 *
 * TODO: cache the 'html_root' upstream to remove the lock for perf
 */
async fn serve_file_if_cookie_ok(
    context: Context,
    cookie: String,
    file: &str,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ctx = context.read().await;
    if ctx.user_db.validate_cookie(cookie) {
        // this is fugly - can;t figure out how to return warp::fs::file(..) after cookie check
        // seems related to https://github.com/seanmonstar/warp/issues/1038
        // so I'm hacking around
        let html = fs::read_to_string(format!("{}/{}", ctx.html_root, file)).unwrap();
        let resp = warp::http::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html")
            .body(html)
            .unwrap();
        Ok(resp)
    } else {
        let html = fs::read_to_string(format!("{}/errs/403.html", ctx.html_root)).unwrap();
        let resp = warp::http::Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "text/html")
            .body(html)
            .unwrap();
        Ok(resp)
    }
}

async fn root(context: Context, cookie: String) -> Result<impl warp::Reply, warp::Rejection> {
    serve_file_if_cookie_ok(context, cookie, "index.html").await
}

async fn webtest(context: Context, cookie: String) -> Result<impl warp::Reply, warp::Rejection> {
    serve_file_if_cookie_ok(context, cookie, "webtest.html").await
}

async fn login_handler(
    context: Context,
    login: LoginInfo,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ctx = context.read().await;
    // TODO: figure out if we need to validate lenghts/input - don't think so, but...
    if ctx.user_db.validate_password(&login.user, &login.passwd) {
        let cookie = ctx.user_db.generate_auth_cooke(&login.user);
        let reply = warp::reply::with_header(
            StatusCode::OK.into_response(),
            "set-cookie",
            format!(
                // TODO: add back 'Secure;' when TLS is enabled!
                "{}={}; Path=/; HttpOnly; Max-Age=1209600",
                COOKIE_LOGIN_NAME, cookie
            ),
        )
        .into_response();
        Ok(reply)
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

pub async fn webclient_websocket_handler(
    context: Context,
    user_agent: String,
    ws: warp::ws::Ws,
    addr: Option<SocketAddr>,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(ws.on_upgrade(move |websocket| {
        webtest::handle_websocket(context, user_agent, websocket, addr)
    }))
}

pub async fn desktop_websocket_handler(
    context: Context,
    user_agent: String,
    ws: warp::ws::Ws,
    addr: Option<SocketAddr>,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(ws.on_upgrade(move |websocket| {
        desktop_websocket::handle_desktop_websocket(context, user_agent, websocket, addr)
    }))
}
/*

Can't figure out how to make this work - let's just serve without passwd check the webclient

async fn webclient(context: Context, cookie: String, wasm_root: String, file: String) -> Result<impl warp::Reply, warp::Rejection> {
    let allowed_files= vec![
        "web_client.js",
        "web_client_bg.wasm",
    ];
    let ctx = context.lock().await;
    if allowed_files.contains(&file.as_str()) {
        serve_file_if_cookie_ok(context, cookie, file.as_str()).await
    } else {
        let html = fs::read_to_string(format!("{}/errs/404.html", ctx.html_root)).unwrap();
        let resp = warp::http::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "text/html")
            .body(html)
            .unwrap();
        Ok(resp)
    }
}

*/

#[cfg(test)]
mod test {
    use super::*;
    use crate::context::test::{make_test_context, TEST_PASSWD};

    /**
     * Step through each possible URL permuation and make sure it hits the right route/filter
     */
    #[tokio::test]
    async fn test_no_cookies() {
        let context = crate::context::test::make_test_context();
        let all_routes = make_webserver_http_routes(context);

        let resp = warp::test::request()
            .path("/garbage")
            .reply(&all_routes.await)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.body().escape_ascii().to_string();
        // verify we get the login page, no matter what we ask for
        assert!(body.contains("Demo is password protected!"));
    }

    #[tokio::test]
    async fn test_passwords() {
        let context = make_test_context();
        let all_routes = make_webserver_http_routes(context.clone()).await;

        // now verify that a bad passwd gets a 403
        let resp = warp::test::request()
            .path("/login")
            .json(&LoginInfo {
                user: "ignore".to_string(),
                passwd: "wrong!".to_string(),
            })
            .method("POST")
            .reply(&all_routes)
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let login_form = make_login_route(&context);
        // now verify that the right passwd gets a 200 and a cookie
        assert!(
            warp::test::request()
                .path("/login")
                .json(&LoginInfo {
                    user: "ignore".to_string(),
                    passwd: TEST_PASSWD.to_string()
                })
                .method("POST")
                .matches(&login_form)
                .await
        );
        let resp = warp::test::request()
            .path("/login")
            .json(&LoginInfo {
                user: "ignore".to_string(),
                passwd: TEST_PASSWD.to_string(),
            })
            .method("POST")
            .reply(&all_routes)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // useful for debugging : cargo t -- --show-output
        for (k, v) in resp.headers().into_iter() {
            println!("{} = {}", k, v.to_str().unwrap());
        }
        assert!(resp.headers().contains_key("set-cookie"));
        let cookie = resp.headers().get("set-cookie").unwrap();
        let cookie_values = cookie.to_str().unwrap().to_string();
        assert!(cookie_values.contains(&format!("{}=SUCCESS", COOKIE_LOGIN_NAME)));
    }

    #[tokio::test]
    async fn test_postauth_badcookie() {
        let context = make_test_context();
        let all_routes = make_webserver_http_routes(context.clone()).await;

        // now verify that a bad cookie gets a 403
        let resp = warp::test::request()
            .path("/anything")
            .header("cookie", format!("{}=GARBAGE", COOKIE_LOGIN_NAME))
            .method("GET")
            .reply(&all_routes)
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_postauth_goodcookie() {
        let context = make_test_context();
        let all_routes = make_webserver_http_routes(context.clone());

        // now verify that a good cookie gets a 200
        let resp = warp::test::request()
            .path("/anything")
            .header("cookie", format!("{}=SUCCESS", COOKIE_LOGIN_NAME))
            .method("GET")
            .reply(&all_routes.await)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_postauth_webclient_goodcookie() {
        let context = make_test_context();
        let all_routes = make_webserver_http_routes(context.clone());

        // now verify that a good cookie gets a 200
        let resp = warp::test::request()
            .path("/webclient/web_client.js")
            // add back once we get cookie auth working
            // .header("cookie", format!("{}=SUCCESS", COOKIE_LOGIN_NAME))
            .method("GET")
            .reply(&all_routes.await)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.body().escape_ascii().to_string();
        // verify we get the login page, no matter what we ask for
        println!("Body = {}", body);
        assert!(body.contains("web_client_bg.wasm"));
    }
}
