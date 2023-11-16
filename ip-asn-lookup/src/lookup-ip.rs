use std::io::BufRead;
use std::net::IpAddr;
use std::str::FromStr;

use clap::Parser;
use ip_asn_lookup::*;
use ip_network_table_deps_treebitmap::IpLookupTable;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to an MRT file containing TABLE_DUMP_V2
    #[arg()]
    pub csv_file: String,
}

pub fn main() {
    let args = Args::parse();
    let mut csv_reader =
        csv::Reader::from_reader(input_reader(&args.csv_file).expect("Opening csv input"));
    let mut lookup_v4 = IpLookupTable::new();
    let mut lookup_v6 = IpLookupTable::new();
    for result in csv_reader.deserialize() {
        let entry: RouteEntry = result.unwrap();
        match entry.prefix {
            IpAddr::V4(ip4) => lookup_v4.insert(ip4, entry.prefix_len as u32, entry.origin_as),
            IpAddr::V6(ip6) => lookup_v6.insert(ip6, entry.prefix_len as u32, entry.origin_as),
        };
    }
    eprintln!(
        "Finished reading CSV file {}. {} IPv4 prefixes and {} IPv6 prefixes",
        args.csv_file,
        lookup_v4.len(),
        lookup_v6.len(),
    );

    eprintln!("Enter IPs to lookup");
    for line_res in std::io::stdin().lock().lines() {
        let ip = match line_res {
            Ok(line) => match IpAddr::from_str(&line) {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("Error parsing IP {}: {}", line, e);
                    continue;
                }
            },
            Err(e) => {
                eprintln!("Error reading IP: {}", e);
                continue;
            }
        };
        let lookup_res = match ip {
            IpAddr::V4(ip4) => lookup_v4
                .longest_match(ip4)
                .map(|(prefix, len, asn)| (IpAddr::V4(prefix), len, *asn)),
            IpAddr::V6(ip6) => lookup_v6
                .longest_match(ip6)
                .map(|(prefix, len, asn)| (IpAddr::V6(prefix), len, *asn)),
        };
        match lookup_res {
            Some((prefix, len, asn)) => {
                println!("{} ==> OriginAS: {}, Prefix: {}/{}", ip, asn, prefix, len);
            }
            None => {
                println!("{} ==> Not Found", ip);
            }
        }
    }
}
