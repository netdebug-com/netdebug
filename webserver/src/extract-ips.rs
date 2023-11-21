use std::{collections::HashSet, process::ExitCode};

use clap::Parser;
use libconntrack_wasm::ConnectionMeasurements;
use log::{error, info};
use rusqlite::{Connection, OpenFlags};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg()]
    pub sqlite_filenames: Vec<String>,
}

type BoxError = Box<dyn std::error::Error>;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    common::init::netdebug_init();
    let args = Args::parse();
    let mut router_ips = HashSet::new();
    let mut remote_ips = HashSet::new();
    for fname in &args.sqlite_filenames {
        info!("Reading sqlite file: {}", fname);
        let db = Connection::open_with_flags(fname, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut stmt = db
            .prepare("SELECT saved_at, pb_storage_entry FROM connections")
            .expect("Could not prepare statement");
        let entries = stmt.query_and_then::<ConnectionMeasurements, BoxError, _, _>([], |row| {
            let json = row.get::<usize, String>(1)?;
            Ok(serde_json::from_str::<ConnectionMeasurements>(&json)?)
        })?;
        for entry in entries {
            let entry = entry?;
            remote_ips.insert(entry.key.remote_ip);
            for probe_round in entry.probe_report_summary.raw_reports {
                for probe in probe_round.probes.values() {
                    if let Some(sender_ip) = probe.get_ip() {
                        router_ips.insert(sender_ip);
                    }
                }
            }
        }
        for ip in &router_ips {
            println!("router {}", ip);
        }
        for ip in &remote_ips {
            println!("remote {}", ip);
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{:?}", e);
            ExitCode::FAILURE
        }
    }
}
