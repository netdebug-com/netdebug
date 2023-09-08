#[cfg(windows)]
use std::env;
#[cfg(windows)]
use std::path::Path;
/*
use std::process::Command;
*/

fn main() {
    /***
     * What a fucking waste of time
     *
     * it's really hard to get this to work right - check out :
     *
     * https://github.com/rustwasm/wasm-pack/issues/251
     *
     * this code as written actually hangs trying to lock target/debug/.cargo-lock
        let src_dir = "web-client";
        // println!("cargo:rerun-if-changed={}/src/",src_dir);
        let out_dir = env::var_os("OUT_DIR").unwrap();
        let build_type = if "release".to_string() == env::var("PROFILE").unwrap() {
            "--release"
        } else {
            "--dev"
        };
        let dest_path = Path::new(&out_dir).join("pkg");
        let dest_path_str = dest_path.clone().into_os_string().into_string().unwrap();
        println!("mydebug={}-outdir={}", build_type, dest_path_str);
        let mut cmd = Command::new("wasm-pack");
        let mut cmd = cmd.args(&["build", "--target", "web", build_type,
                               // "--out-dir", &dest_path_str,
                               src_dir]);
        println!("mydebug={:?}", cmd);
        let output = cmd
            .output()
            .expect("To build wasm files successfully");

        println!("mydebug={:?}", output);

        if !output.status.success() {
            panic!(
                "Error while compiling:\n{}\n\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let js_file = dest_path.join("web_client.js");
        let wasm_file = dest_path.join("web_client_bg.wasm");

        for file in &[&js_file, &wasm_file] {
            let file = std::fs::metadata(file).expect("file to exist");
            assert!(file.is_file());
        }

        println!("cargo:rustc-env=PROJECT_NAME_JS={}", js_file.display());
        println!("cargo:rustc-env=PROJECT_NAME_WASM={}", wasm_file.display());
    */

    #[cfg(windows)]
    {
        let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        println!(
            "cargo:rustc-link-search=native={}",
            Path::new(&dir).join("../win32_pcap_libs/x64").display()
        );
    }
}
