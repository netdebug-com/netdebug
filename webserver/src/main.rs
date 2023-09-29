#[cfg(not(windows))]
use libconntrack::pcap::start_pcap_stream;
#[cfg(not(windows))]
use libwebserver::context::{Args, WebServerContext};
use std::error::Error;
#[cfg(not(windows))]
use std::sync::Arc;

#[cfg(not(windows))]
use clap::Parser;
#[cfg(not(windows))]
use libwebserver::http_routes::make_webserver_http_routes;
#[cfg(not(windows))]
use log::info;
#[cfg(not(windows))]
use tokio::sync::RwLock;

#[cfg(not(windows))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    utils::init::netdebug_init();

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
    let ip: std::net::IpAddr = match args.production {
        true => {
            info!("Running in production mode");
            "::"
        }
        false => {
            info!("Running in development mode");
            "::1"
        }
    }
    .parse()?;
    let listen_addr = std::net::SocketAddr::new(ip, args.listen_port);

    warp::serve(make_webserver_http_routes(context).await)
        .run(listen_addr)
        .await;
    Ok(())
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    panic!("Webserver not supported on windows - even if some of it compiles");
}
