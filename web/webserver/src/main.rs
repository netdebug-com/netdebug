use std::sync::Arc;

use libwebserver::context::{Context, LoginInfo, WebServerContext, COOKIE_LOGIN_NAME};

use clap::Parser;
use log::info;
use tokio::sync::Mutex;
use warp::filters::cookie::cookie;
use warp::{http::StatusCode, Filter, Reply};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Used to enable production flags vs. (default) dev mode
    #[arg(long)]
    production: bool,

    #[arg(long, default_value = "html")]
    html_root: String,
}

#[tokio::main]
async fn main() {
    // if RUST_LOG isn't set explicitly, set RUST_LOG=info as a default
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "info");
    }
    // if RUST_BACKTRACE isn't set explicitly, set RUST_BACKTRACE=1 as a default
    if let Err(_) = std::env::var("RUST_BACKTRACE") {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    pretty_env_logger::init();

    // init webserver state
    let context = Arc::new(Mutex::new(WebServerContext::new()));

    let args = Args::parse();

    // POST login data to http://.../login to get auth cookie
    let login = warp::post()
        .and(warp::path("login"))
        .and(with_context(&context))
        .and(warp::body::json())
        .and_then(login_handler);

    // can only access if there's an auth cookie
    let hello = warp::any()
        .and(with_context(&context))
        .and(cookie(COOKIE_LOGIN_NAME))
        .and_then(hello);

    // default where we direct people with no auth cookie to get one
    let login_form = warp::any()
        .and(warp::get())
        .and(warp::fs::file(format!("{}/login.html", args.html_root)));

    let routes = hello.or(login).or(login_form);

    let listen_addr = if args.production {
        info!("Running in production mode");
        ([0, 0, 0, 0], 0)
    } else {
        info!("Running in development mode");
        ([127, 0, 0, 1], 3030)
    };

    warp::serve(routes).run(listen_addr).await;
}

fn with_context(
    context: &Context,
) -> impl Filter<Extract = (Context,), Error = std::convert::Infallible> + Clone {
    let context = context.clone();
    warp::any().map(move || context.clone())
}

async fn hello(context: Context, cookie: String) -> Result<impl warp::Reply, warp::Rejection> {
    let ctx = context.lock().await;
    if ctx.user_db.validate_cookie(cookie) {
        Ok("hello world!".into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
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
