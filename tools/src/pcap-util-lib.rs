use pcap::{Capture, Offline};
use std::path::Path;

pub fn open_pcap_or_die(fname: &str) -> Capture<Offline> {
    pcap::Capture::from_file(Path::new(&fname)).unwrap_or_else(|err| {
        panic!("Error trying to open pcap file `{}`: {}", fname, err);
    })
}

pub mod sumdump;
pub use sumdump::*;
pub mod hacky;
pub use hacky::*;
