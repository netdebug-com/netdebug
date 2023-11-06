use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::io::Cursor;
use std::io::Write;
use std::net::IpAddr;

use bgp_rs::PathAttribute;
use clap::Parser;
//use libflate::gzip::Decoder;
use mrt_rs::bgp4mp::BGP4MP;
use mrt_rs::tabledump::RIB_AFI;
use mrt_rs::tabledump::TABLE_DUMP_V2;
use mrt_rs::Record;

use mrt_stuff::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to an MRT file containing TABLE_DUMP_V2
    #[arg()]
    pub mrt_file: String,
    /// Outoput filename. Default is stdout
    #[arg(long, default_value=None)]
    pub outfile: Option<String>,
}

pub fn process_rib(mut data: RIB_AFI, is_ipv6: bool) -> Vec<RouteEntry> {
    let prefix = if is_ipv6 {
        data.prefix.resize(16, 0);
        let octets = <[u8; 16]>::try_from(data.prefix).unwrap();
        IpAddr::from(octets)
    } else {
        data.prefix.resize(4, 0);
        let octets = <[u8; 4]>::try_from(data.prefix).unwrap();
        IpAddr::from(octets)
    };
    // Loop over each route for this particular prefix.
    let mut origin_as_set = HashSet::new();
    for entry in data.entries {
        let length = entry.attributes.len() as u64;
        let mut cursor = Cursor::new(entry.attributes);

        // Parse each PathAttribute in each route.
        while cursor.position() < length {
            let attr = PathAttribute::parse(&mut cursor, &Default::default()).unwrap();
            match attr {
                PathAttribute::AS_PATH(path) | PathAttribute::AS4_PATH(path) => {
                    origin_as_set.insert(path.origin().unwrap_or(0));
                    break;
                }
                _ => {}
            }
        }
    }
    let mut retval = Vec::with_capacity(origin_as_set.len());
    for origin_as in origin_as_set {
        retval.push(RouteEntry {
            prefix,
            prefix_len: data.prefix_length,
            origin_as,
        });
    }
    retval
}

pub fn main() {
    let args = Args::parse();

    eprintln!("Using file {}", args.mrt_file);

    // Open output. We do this before doing any parsing to terminate early if we
    // can't open the file (before spending seconds parsing the MRT file)
    let writer: Box<dyn Write> = match args.outfile {
        Some(fname) => Box::new(File::create(fname).expect("Opening output file")),
        None => Box::new(std::io::stdout()),
    };
    let mut csv_writer = csv::Writer::from_writer(writer);

    // Open input
    let mut buffered = BufReader::new(input_reader(&args.mrt_file).expect("Opening input file"));

    // Keep reading MRT (Header, Record) tuples till the end of the file has been reached.
    let mut entries = Vec::new();
    while let Ok(Some((_, record))) = mrt_rs::read(&mut buffered) {
        match record {
            Record::BGP4MP(BGP4MP::MESSAGE(_)) => {
                eprintln!("MSG");
            }
            Record::BGP4MP(BGP4MP::MESSAGE_AS4(_)) => {
                eprintln!("MSG_AS4");
            }
            Record::TABLE_DUMP_V2(dump) => match dump {
                TABLE_DUMP_V2::RIB_IPV4_UNICAST(x) => {
                    entries.extend(process_rib(x, false));
                }
                TABLE_DUMP_V2::RIB_IPV6_UNICAST(x) => {
                    entries.extend(process_rib(x, true));
                }
                TABLE_DUMP_V2::PEER_INDEX_TABLE(_) => {
                    // ignore
                }
                _ => {
                    eprintln!("OTHER {:?}", dump);
                }
            },
            Record::TABLE_DUMP(_) => {
                eprintln!("DUMP");
            }
            _ => {
                eprintln!("FOO. Other type: {:?}", record);
            }
        }
    }
    for entry in &entries {
        csv_writer.serialize(entry).unwrap();
    }
}
