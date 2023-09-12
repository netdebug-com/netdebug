extern crate prost_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(&["measurements.proto"], &["src/"]).unwrap();
    Ok(())
}
