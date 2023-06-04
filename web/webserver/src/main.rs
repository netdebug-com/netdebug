use log::info;
use warp::Filter;

use clap::Parser;

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
    pretty_env_logger::init();

    let args = Args::parse();
    let routes = warp::any().map(|| "Hello, World!");

    let listen_addr = if args.production {
        info!("Running in production mode");
        ([0, 0, 0, 0], 0)
    } else {
        info!("Running in development mode");
        ([127, 0, 0, 1], 3030)
    };

    warp::serve(routes).run(listen_addr).await;
}
