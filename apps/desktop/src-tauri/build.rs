fn main() {
    // `generate_context!` embeds the built UI and fails if it is missing.
    // Workspace-wide `cargo build/test/clippy` should not need Node, so
    // provide a placeholder page when the UI has not been built
    // (`npm run build` replaces it; `dist/` is git-ignored).
    let dist = std::path::Path::new("../dist");
    if !dist.join("index.html").exists() {
        std::fs::create_dir_all(dist).expect("create ../dist");
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><meta charset=\"utf-8\"><title>Secure Verified Exchange</title>\
             <p>The user interface has not been built. Run <code>npm run build</code> in apps/desktop.</p>",
        )
        .expect("write placeholder UI");
    }
    tauri_build::build()
}
