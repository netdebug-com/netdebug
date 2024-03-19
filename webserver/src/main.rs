use axum_server::tls_rustls::RustlsConfig;
use libwebserver::{
    context::{Args, WebServerContext},
    http_routes::setup_axum_http_routes,
};
use std::sync::Arc;
use std::{error::Error, net::SocketAddr};

use clap::Parser;
use log::{info, warn};
use tokio::sync::RwLock;

const NON_DNS_PAYLOAD_LEN: usize = 512;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    common::init::netdebug_init();
    console_subscriber::init();

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

    // info_make_service_with_connect_info is needed so that we can extract the remote
    // socket addr
    let routes = setup_axum_http_routes(context)
        .await
        .into_make_service_with_connect_info::<SocketAddr>();
    if run_encrypted {
        let tls_config = RustlsConfig::from_pem_file(args.tls_cert, args.tls_key)
            .await
            .expect("Error reading SSL cert and/or key");
        axum_server::bind_rustls(listen_addr, tls_config)
            .serve(routes)
            .await
            .unwrap();
    } else {
        axum_server::bind(listen_addr).serve(routes).await.unwrap();
    }
    Ok(())
}
