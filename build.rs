use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "src/bfsp.proto",
            "src/bfsp.ipc.proto",
            "src/bfsp.cli.proto",
            "src/bfsp.internal.proto",
        ],
        &["src/"],
    )?;
    Ok(())
}
