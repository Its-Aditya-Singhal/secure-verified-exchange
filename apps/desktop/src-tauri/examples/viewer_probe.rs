//! Phase 7, step 0: does the OS really hide a content-protected window from
//! screenshots and screen recordings? Not part of the app (examples aren't
//! bundled). Run it and try to capture the red window:
//!
//!   cargo run -p svx-desktop --example viewer_probe
//!
//! A protected window shows up black (or missing) in the capture. A second,
//! unprotected window is opened as a control, so you can tell "capture
//! works" from "capture is broken".
#![forbid(unsafe_code)]

use tauri::{WebviewUrl, WebviewWindowBuilder};

const PAGE: &str = r#"
document.addEventListener('DOMContentLoaded', () => {
  document.body.innerHTML = '<div style="font:700 44px system-ui;color:#fff;background:%COLOR%;' +
    'height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px">' +
    '%TEXT%</div>';
});
"#;

fn page(color: &str, text: &str) -> String {
    PAGE.replace("%COLOR%", color).replace("%TEXT%", text)
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let protected =
                WebviewWindowBuilder::new(app, "protected", WebviewUrl::App("index.html".into()))
                    .title("PROTECTED (should be black in captures)")
                    .inner_size(520.0, 320.0)
                    .position(60.0, 80.0)
                    .content_protected(true)
                    .initialization_script(page(
                        "#b00020",
                        "PROTECTED<br>this must NOT appear in a capture",
                    ))
                    .build()?;
            let _ = protected;
            WebviewWindowBuilder::new(app, "control", WebviewUrl::App("index.html".into()))
                .title("CONTROL (should appear in captures)")
                .inner_size(520.0, 320.0)
                .position(620.0, 80.0)
                .content_protected(false)
                .initialization_script(page(
                    "#1b5e20",
                    "CONTROL<br>this should appear in a capture",
                ))
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("viewer probe failed");
}
