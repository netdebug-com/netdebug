use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed={}/", "webserver/web-client");
    println!("cargo:rerun-if-changed={}/", "webserver/web-client/pkg");
    // don't write into the targets directory for now - figure that out later
    // let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&dir).join("pkg");
    let output = Command::new("wasm-pack")
        .args(&["build", "--target", "web"])
        .arg(dir)
        .output()
        .expect("To build wasm files successfully");

    if !output.status.success() {
        panic!(
            "Error while compiling:\n{}",
            String::from_utf8_lossy(&output.stdout)
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

    emit_git_hash();
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
