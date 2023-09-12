fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .extern_path(".conntrack", "::pb-conntrack-types")
        .compile(&["storage_service.proto"], &[".", "../"])?;
    Ok(())
}
