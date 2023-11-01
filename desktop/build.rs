#[cfg(windows)]
use std::env;
use std::path::Path;

use desktop_common::GuiToServerMessages;

use libconntrack_wasm::{
    aggregate_counters::TrafficCounters, ConnectionMeasurements, DnsTrackerEntry,
};
use typescript_type_def::{write_definition_file, DefinitionFileOptions};

/**
 * NOTE: ServerToGuiMessages is a pain to type def because of the
 * Hash<IpAddr, DnsTrackerEntry>
 *
 * Just list the elements out manually for most of the value
 */
type ExportedTypes = (
    ConnectionMeasurements,
    DnsTrackerEntry,
    TrafficCounters,
    GuiToServerMessages,
);

const TYPESCRIPT_OUT_FILE: &str = "../electron/src/netdebug_types.ts";

/**
 * This command generates the typescript bindings from the types listed in
 * ExportedTypes to the file in the src directory of the electron code.
 *
 * That TYPESCRIPT_OUT_FILE is checked in so we should be able to track changes of it.
 */

fn generate_typescript_types() {
    // NOTE: if we use Path::new(), things magically work with windows
    // if we just use the raw &str, they do not
    let mut outfile = std::fs::File::create(Path::new(TYPESCRIPT_OUT_FILE)).expect(
        format!(
            "Can't write to {} from {}",
            TYPESCRIPT_OUT_FILE,
            std::env::current_dir()
                .unwrap()
                .to_string_lossy()
                .to_string()
        )
        .as_str(),
    );
    let mut options = DefinitionFileOptions::default();
    options.root_namespace = None;
    write_definition_file::<_, ExportedTypes>(&mut outfile, options).unwrap();
}
fn main() {
    #[cfg(windows)]
    {
        let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        println!(
            "cargo:rustc-link-search=native={}",
            Path::new(&dir).join("../win32_pcap_libs/x64").display()
        );
    }
    generate_typescript_types();
}
