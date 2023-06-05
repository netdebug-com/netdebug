use std::sync::Arc;

use libwebserver::context::{Context, WebServerContext};

use clap::Parser;
use log::info;
use tokio::sync::Mutex;
use warp::Filter;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Used to enable production flags vs. (default) dev mode
    #[arg(long)]
    production: bool,
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
    let routes = warp::any().and(with_context(context)).and_then(hello);

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
    context: Context,
) -> impl Filter<Extract = (Context,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || context.clone())
}

async fn hello(_context: Context) -> Result<impl warp::Reply, warp::Rejection> {
    Ok("hello world!".to_string())
}
