use std::{collections::HashSet, process::ExitCode};

use clap::Parser;
use log::{error, info};
use pb_conntrack_types::ConnectionStorageEntry;
use prost::Message;
use rusqlite::{Connection, OpenFlags};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg()]
    pub sqlite_filenames: Vec<String>,
}

type BoxError = Box<dyn std::error::Error>;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    utils::init::netdebug_init();
    let args = Args::parse();
    let mut router_ips = HashSet::new();
    let mut remote_ips = HashSet::new();
    for fname in &args.sqlite_filenames {
        info!("Reading sqlite file: {}", fname);
        let db = Connection::open_with_flags(fname, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut stmt = db
            .prepare("SELECT saved_at, pb_storage_entry FROM connections")
            .expect("Could not prepare statement");
        let entries = stmt.query_and_then::<ConnectionStorageEntry, BoxError, _, _>([], |row| {
            let buf = row.get::<usize, Vec<u8>>(1)?;
            Ok(ConnectionStorageEntry::decode(buf.as_slice())?)
        })?;
        for entry in entries {
            let entry = entry?;
            remote_ips.insert(entry.remote_ip);
            for probe_round in entry.probe_rounds {
                for probe in &probe_round.probes {
                    if let Some(sender_ip) = probe.sender_ip.clone() {
                        use pb_conntrack_types::ProbeType::*;
                        match probe.probe_type() {
                            RouterReplyFound | RouterReplyNoProbe | NatReplyFound
                            | NatReplyNoProbe => {
                                // XXX: the match is probably redundant since `sender_ip` is only
                                // populated for the above variants. But better to explicit here.
                                router_ips.insert(sender_ip);
                            }
                            EndHostReplyFound | EndHostReplyNoProbe | NoReply | NoOutgoing
                            | UnspecifiedProbeType => (),
                        }
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
