use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/bfsp.proto"], &["src/"])?;
    prost_build::compile_protos(&["src/bfsp.ipc.proto"], &["src/"])?;
    prost_build::compile_protos(&["src/bfsp.cli.proto"], &["src/"])?;
    Ok(())
}
