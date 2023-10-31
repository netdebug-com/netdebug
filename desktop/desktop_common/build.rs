use libconntrack_wasm::{DnsTrackerEntry, RateEstimator};
use std::{path::Path, process::Command};
use typescript_type_def::{write_definition_file, DefinitionFileOptions};

type ExportedTypes = (DnsTrackerEntry, RateEstimator);

const TYPESCRIPT_OUT_FILE: &str = "../../electron/src/netdebug_types.ts";

fn main() {
    emit_git_hash();
    generate_typescript_types();
}

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

fn emit_git_hash() {
    // from: https://stackoverflow.com/questions/43753491/include-git-commit-hash-as-string-into-rust-program
    // assumes this is built from inside the git folder - which should be always true
    let output = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
}
