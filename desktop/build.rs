use std::env;
use std::path::Path;

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    #[cfg(windows)]
    println!(
        "cargo:rustc-link-search=native={}",
        Path::new(&dir).join("../lib/x64").display()
    );
}
