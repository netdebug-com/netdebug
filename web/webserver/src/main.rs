use std::sync::Arc;

use libwebserver::context::WebServerContext;

use clap::Parser;
use libwebserver::http_routes::make_http_routes;
use log::info;
use tokio::sync::Mutex;

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

    let listen_addr = if args.production {
        info!("Running in production mode");
        ([0, 0, 0, 0], 0)
    } else {
        info!("Running in development mode");
        ([127, 0, 0, 1], 3030)
    };

    warp::serve(make_http_routes(context, &args.html_root))
        .run(listen_addr)
        .await;
}
