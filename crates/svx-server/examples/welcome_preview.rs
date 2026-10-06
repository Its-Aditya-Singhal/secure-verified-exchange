//! Write the welcome email as a stand-alone HTML file (images inlined as
//! data: URLs) to look at in a browser:
//!
//! ```sh
//! cargo run -p svx-server --example welcome_preview -- /tmp/welcome.html [First]
//! ```

use base64::Engine as _;

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let out = args.next().unwrap_or_else(|| "welcome-preview.html".into());
    let name = args.next();
    let email = svx_server::welcome::welcome_email("alice@example.com", name.as_deref());
    let html = email.html.expect("the welcome email has an HTML version");
    let mut page = html.body;
    for img in html.images {
        let data = base64::engine::general_purpose::STANDARD.encode(img.data);
        page = page.replace(
            &format!("cid:{}", img.cid),
            &format!("data:{};base64,{data}", img.content_type),
        );
    }
    std::fs::write(&out, page)?;
    println!("wrote {out}");
    Ok(())
}
