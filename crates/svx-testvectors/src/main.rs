//! Regenerate the published test vectors:
//!
//! ```sh
//! cargo run -p svx-testvectors -- test-vectors/v1
//! ```

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "test-vectors/v1".into()),
    );
    std::fs::create_dir_all(&dir)?;
    let files = svx_testvectors::generate();
    for (name, bytes) in &files {
        std::fs::write(dir.join(name), bytes)?;
    }
    println!("wrote {} files to {}", files.len(), dir.display());
    Ok(())
}
