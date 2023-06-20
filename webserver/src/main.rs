use std::error::Error;
use std::sync::Arc;

use libwebserver::context::{Args, WebServerContext};
use libwebserver::pcap::start_pcap_stream;

use clap::Parser;
use libwebserver::http_routes::make_http_routes;
use log::info;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // if RUST_LOG isn't set explicitly, set RUST_LOG=info as a default
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "info");
    }
    // if RUST_BACKTRACE isn't set explicitly, set RUST_BACKTRACE=1 as a default
    if let Err(_) = std::env::var("RUST_BACKTRACE") {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    pretty_env_logger::init();

    let args = Args::parse();

    // init webserver state
    let context = Arc::new(RwLock::new(WebServerContext::new(&args)?));
    let context_clone = context.clone();
    if !args.web_server_only {
        tokio::spawn(async move {
            // unwrap() should be fine here as we should panic if this fails
            if let Err(e) = start_pcap_stream(context_clone).await {
                log::error!("start_pcap_stream() returned {} -- exiting", e);
                // this is fatal, just exit
                std::process::exit(1);
            }
        });
    }
    let listen_addr = if args.production {
        info!("Running in production mode");
        ([0, 0, 0, 0], args.listen_port)
    } else {
        info!("Running in development mode");
        ([127, 0, 0, 1], args.listen_port)
    };

    warp::serve(make_http_routes(context).await)
        .run(listen_addr)
        .await;
    Ok(())
}
