use desktop_common::GuiApiTypes;
#[cfg(windows)]
use std::env;
use std::path::Path;

use typescript_type_def::{write_definition_file, DefinitionFileOptions};

// FIXME: should refactor the typescript output into a shared crate, not
// separately in webserver/build.rs and desktop/build.rs
const TYPESCRIPT_OUT_FILE: &str = "../frontend/console/src/netdebug_types.ts";

/**
 * This command generates the typescript bindings from the types listed in
 * ExportedTypes to the file in the src directory of the electron code.
 *
 * That TYPESCRIPT_OUT_FILE is checked in so we should be able to track changes of it.
 */

fn generate_typescript_types() {
    // NOTE: if we use Path::new(), things magically work with windows
    // if we just use the raw &str, they do not
    let mut outfile = std::fs::File::create(Path::new(TYPESCRIPT_OUT_FILE)).unwrap_or_else(|_| {
        panic!(
            "Can't write to {} from {}",
            TYPESCRIPT_OUT_FILE,
            std::env::current_dir().unwrap().to_string_lossy()
        )
    });
    let options = DefinitionFileOptions {
        root_namespace: None,
        ..Default::default()
    };
    write_definition_file::<_, GuiApiTypes>(&mut outfile, options).unwrap();
}

fn main() {
    generate_typescript_types();
    #[cfg(windows)]
    {
        let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        println!(
            "cargo:rustc-link-search=native={}",
            Path::new(&dir).join("../win32_pcap_libs/x64").display()
        );
    }
}
