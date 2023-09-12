extern crate prost_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(&["conntrack.proto"], &["."]).unwrap();
    Ok(())
}
