use std::env;
#[cfg(windows)]
use std::path::Path;

fn main() {
    #[cfg(windows)]
    {
        let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        println!(
            "cargo:rustc-link-search=native={}",
            Path::new(&dir).join("../lib/x64").display()
        );
    }
}