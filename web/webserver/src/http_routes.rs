use std::fs;

use crate::context::{Context, LoginInfo, COOKIE_LOGIN_NAME};
use warp::http::StatusCode;
use warp::{cookie::cookie, Filter, Reply};

pub async fn make_http_routes(
    context: Context,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let log = warp::log("http");
    let login = make_login_route(&context).with(log);
    let webtest = make_webtest_route(&context).with(log);

    // can only access if there's an auth cookie
    let root = make_root_route(&context).with(log);

    // default where we direct people with no auth cookie to get one
    //let html_root = context.lock().await.html_root.clone();
    let html_root = "html".to_string();
    let login_form = make_login_form_route(&context, &html_root).with(log);

    let routes = webtest.or(root).or(login).or(login_form);
    routes
}

fn make_login_route(
    context: &Context,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    // POST login data to http://localhost/login to get auth cookie
    warp::post()
        .and(warp::path("login"))
        .and(with_context(&context))
        .and(warp::body::json())
        .and_then(login_handler)
}

fn make_root_route(
    context: &Context,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::any()
        .and(with_context(&context))
        .and(cookie(COOKIE_LOGIN_NAME))
        .and_then(root)
}

fn make_webtest_route(
    context: &Context,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::any()
        .and(with_context(&context))
        .and(cookie(COOKIE_LOGIN_NAME))
        .and_then(webtest)
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

fn _with_string(
    s: &String,
) -> impl Filter<Extract = (String,), Error = std::convert::Infallible> + Clone {
    let s = s.clone();
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
    let ctx = context.lock().await;
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
    let ctx = context.lock().await;
    // TODO: figure out if we need to validate lenghts/input - don't think so, but...
    if ctx.user_db.validate_password(&login.user, &login.passwd) {
        let cookie = ctx.user_db.generate_auth_cooke(&login.user);
        let reply = warp::reply::with_header(
            StatusCode::OK.into_response(),
            "set-cookie",
            format!(
                "{}={}; Path=/; HttpOnly; Secure; Max-Age=1209600",
                COOKIE_LOGIN_NAME, cookie
            ),
        )
        .into_response();
        Ok(reply)
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::context::{UserDb, WebServerContext};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    const TEST_PASSWD: &str = "test";
    fn make_test_context() -> Context {
        let test_pass = TEST_PASSWD;
        let test_hash = UserDb::new_password(&test_pass.to_string()).unwrap();
        Arc::new(Mutex::new(WebServerContext {
            user_db: UserDb::testing_demo(test_hash),
            html_root: "html".to_string(),
            wasm_root: "web-client/pkg".to_string(),
        }))
    }

    /**
     * Step through each possible URL permuation and make sure it hits the right route/filter
     */
    #[tokio::test]
    async fn test_no_cookies() {
        let context = make_test_context();
        let all_routes = make_http_routes(context);

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
        let all_routes = make_http_routes(context.clone()).await;

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
            println!("{} = {}", k, v.to_str().unwrap().to_string());
        }
        assert!(resp.headers().contains_key("set-cookie"));
        let cookie = resp.headers().get("set-cookie").unwrap();
        let cookie_values = cookie.to_str().unwrap().to_string();
        assert!(cookie_values.contains(&format!("{}=SUCCESS", COOKIE_LOGIN_NAME)));
    }

    #[tokio::test]
    async fn test_postauth_badcookie() {
        let context = make_test_context();
        let all_routes = make_http_routes(context.clone()).await;

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
        let all_routes = make_http_routes(context.clone());

        // now verify that a good cookie gets a 200
        let resp = warp::test::request()
            .path("/anything")
            .header("cookie", format!("{}=SUCCESS", COOKIE_LOGIN_NAME))
            .method("GET")
            .reply(&all_routes.await)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
