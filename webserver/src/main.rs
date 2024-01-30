use libwebserver::context::{Args, WebServerContext};
use std::error::Error;
use std::sync::Arc;

use clap::Parser;
use libwebserver::http_routes::make_webserver_http_routes;
use log::{info, warn};
use tokio::sync::RwLock;

const NON_DNS_PAYLOAD_LEN: usize = 512;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    common::init::netdebug_init();

    let args = Args::parse();

    // init webserver state
    let context = Arc::new(RwLock::new(WebServerContext::new(&args)?));
    if !args.web_server_only {
        let (device_name, tcp_listen_port, connection_tx) = {
            let ctx = context.read().await;
            (
                ctx.pcap_device.name.clone(),
                ctx.local_tcp_listen_port,
                ctx.connection_tracker.clone(),
            )
        };
        let _pcap_thread = libconntrack::pcap::run_blocking_pcap_loop_in_thread(
            device_name,
            Some(format!("tcp port {} or icmp or icmp6", tcp_listen_port)),
            connection_tx,
            NON_DNS_PAYLOAD_LEN,
            None,
            None,
        );
    }

    info!(
        "Running webserver version: {}",
        common_wasm::get_git_hash_version()
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

    let server = warp::serve(make_webserver_http_routes(context).await);
    let run_encrypted = if args.production {
        if !args.force_unencrypted {
            info!("Running with TLS/Encypted mode");
            true
        } else {
            warn!("--force-unencrypted set, running unencrypted in prod!?");
            false
        }
    } else {
        false // dev mode is ok to be unencrypted
    };
    if run_encrypted {
        server
            .tls()
            .cert_path(args.tls_cert)
            .key_path(args.tls_key)
            .run(listen_addr)
            .await
    } else {
        server.run(listen_addr).await;
    }
    Ok(())
}
