fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure().compile_protos(
        &[
            "../../../proto/ui.proto",
            "../../../proto/subscriptions.proto",
        ],
        &["../../../proto"],
    )?;

    println!("cargo:rerun-if-changed=../../../proto/ui.proto");
    println!("cargo:rerun-if-changed=../../../proto/subscriptions.proto");

    Ok(())
}
