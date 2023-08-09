use std::error::Error;
use std::sync::Arc;

use libconntrack::pcap::start_pcap_stream;
use libwebserver::context::{Args, WebServerContext};

use clap::Parser;
use libwebserver::http_routes::make_webserver_http_routes;
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
            let (device, local_tcp_port, tx) = {
                let ctx = context_clone.read().await;
                (
                    ctx.pcap_device.clone(),
                    ctx.local_tcp_listen_port,
                    ctx.connection_tracker.clone(),
                )
            };
            // unwrap() should be fine here as we should panic if this fails
            if let Err(e) = start_pcap_stream(device, local_tcp_port, tx).await {
                log::error!("start_pcap_stream() returned {} -- exiting", e);
                // this is fatal, just exit
                std::process::exit(1);
            }
        });
    }

    info!(
        "Running webserver version: {}",
        common::get_git_hash_version()
    );
    let listen_addr = if args.production {
        info!("Running in production mode");
        ([0, 0, 0, 0], args.listen_port)
    } else {
        info!("Running in development mode");
        ([127, 0, 0, 1], args.listen_port)
    };

    warp::serve(make_webserver_http_routes(context).await)
        .run(listen_addr)
        .await;
    Ok(())
}
