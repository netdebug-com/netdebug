use std::process::Command;

fn main() {
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
