//! The one-time welcome email to a new account: an HTML version with the
//! brand banner (inline images, nothing fetched from a server) and a plain
//! text version. Like every SVX email it has no links, so people learn that
//! an "SVX" email asking them to click something isn't from SVX.

use crate::AppState;
use crate::limits::{ANNOUNCE_CEILING, MailKind, take_email};
use crate::notify::{Email, Html, InlineImage};

const TEMPLATE: &str = include_str!("welcome/welcome.html");
const BANNER: &[u8] = include_bytes!("welcome/banner.png");
const ICON: &[u8] = include_bytes!("welcome/icon.png");

const TIPS: [(&str, &str); 3] = [
    (
        "Send by email address",
        "Pick a file or a folder and type the person's email address. They need SVX too; the app finds their keys.",
    ),
    (
        "You decide who opens it",
        "Ask to approve each open, allow one open per person, set an expiry, or revoke a file at any time.",
    ),
    (
        "Save your key backup",
        "In the app: Settings, then Save a backup. Without it, a new computer can't open files sent to you.",
    ),
];

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            // Keeps mail apps from turning an address into a link by
            // itself ("@" and "." stay readable).
            '.' => out.push_str("&#8203;."),
            c => out.push(c),
        }
    }
    out
}

/// The welcome email for `email`; `first_name` for email accounts (Google
/// accounts have none).
pub fn welcome_email(email: &str, first_name: Option<&str>) -> Email {
    let name = first_name.map(str::trim).filter(|n| !n.is_empty());
    let greeting = match name {
        Some(n) => format!("Hi {n}, welcome aboard."),
        None => "Hi there, welcome aboard.".to_owned(),
    };
    let tips_html: String = TIPS
        .iter()
        .enumerate()
        .map(|(i, (title, text))| {
            format!(
                "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:0 0 14px;\"><tr>\
                 <td width=\"40\" valign=\"top\" style=\"padding-top:2px;\"><div style=\"width:28px;height:28px;border-radius:14px;background:#16171B;color:#FF6A3D;font-size:14px;font-weight:700;line-height:28px;text-align:center;\">{}</div></td>\
                 <td valign=\"top\" style=\"font-size:15px;line-height:1.55;color:#3A3D44;\"><strong style=\"color:#1D1F24;\">{}</strong><br>{}</td>\
                 </tr></table>",
                i + 1,
                escape(title),
                escape(text)
            )
        })
        .collect();
    let html = TEMPLATE
        .replace("{{GREETING}}", &escape(&greeting))
        .replace("{{EMAIL}}", &escape(email))
        .replace("{{TIPS}}", &tips_html);
    let tips_text: String = TIPS
        .iter()
        .enumerate()
        .map(|(i, (t, x))| format!("{}. {t}: {x}\n", i + 1))
        .collect();
    let body = format!(
        "{greeting}\n\nYour SVX account ({email}) is ready.\n\n\
         Files you send with SVX are encrypted on your computer. Only the people you choose \
         can open them, and you stay in control after you send.\n\n\
         Three things to know\n\n{tips_text}\n\
         Stay safe: SVX emails never ask you to click a link, open an attachment, or give your \
         password or a code. If an email claiming to be from SVX does, it isn't from us.\n\n\
         Questions or ideas? Just reply, or write to support@getsvx.me.\n\
         The SVX team\n\n--\nYou get this once, because an SVX account was just created with this address.\n"
    );
    Email {
        to: email.to_owned(),
        subject: "Welcome to SVX".into(),
        body,
        html: Some(Html {
            body: html,
            images: vec![
                InlineImage {
                    cid: "svx-banner",
                    content_type: "image/png",
                    data: BANNER,
                },
                InlineImage {
                    cid: "svx-icon",
                    content_type: "image/png",
                    data: ICON,
                },
            ],
        }),
    }
}

/// Send the welcome email if today's allowance has room (sign-up codes
/// come first: welcomes stop where announcements do). Never fails the
/// caller; a skipped welcome is only logged.
pub async fn send_welcome(st: &AppState, email: &str, first_name: Option<&str>) {
    match take_email(&st.db, MailKind::Welcome, ANNOUNCE_CEILING).await {
        Ok(true) => st.notifier.deliver(welcome_email(email, first_name)),
        Ok(false) => tracing::warn!("daily email allowance: welcome email skipped"),
        Err(e) => tracing::error!(error = %e, "couldn't count a welcome email"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_welcome_email_is_escaped_and_has_no_links() {
        let e = welcome_email("eve@example.com", Some("<b>Eve</b>"));
        let html = &e.html.as_ref().unwrap().body;
        assert!(html.contains("Hi &lt;b&gt;Eve&lt;/b&gt;, welcome aboard&#8203;."));
        assert!(!html.contains("<b>Eve"));
        assert!(html.contains("eve@example&#8203;.com"));
        for bad in ["href", "http://", "https://", "{{"] {
            assert!(!html.contains(bad), "{bad}");
            assert!(!e.body.contains(bad), "{bad}");
        }
        assert!(html.contains("cid:svx-banner") && html.contains("cid:svx-icon"));
        assert_eq!(e.html.unwrap().images.len(), 2);
        assert!(e.body.starts_with("Hi <b>Eve</b>, welcome aboard."));
        let g = welcome_email("bob@example.com", None);
        assert!(g.body.starts_with("Hi there, welcome aboard."));
    }
}
