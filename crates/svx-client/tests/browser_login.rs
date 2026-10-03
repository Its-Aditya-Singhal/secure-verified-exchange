//! The real RFC 8252 loopback login against the dev IdP. The "browser" is
//! an HTTP client that follows the authorization URL; the IdP redirects it
//! to the client's loopback listener, exactly as a real browser would.

use std::sync::Arc;
use std::time::Duration;

use svx_client::login::{Authenticator, BrowserLogin, Opener};
use svx_mock_idp::{Config, MockIdp, User};
use svx_oidc::{IssuerConfig, Validator};
use svx_protocol::ManagedClient;

async fn idp() -> MockIdp {
    MockIdp::spawn(
        Config {
            client_id: "svx-example-corp".into(),
            users: vec![User {
                sub: "alice".into(),
                email: None,
                groups: vec!["incident-response".into()],
                acr: None,
            }],
            token_ttl_secs: 300,
        },
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap()
}

/// A headless "browser" that logs in as `user` (the dev IdP picks the user
/// from `login_hint`).
fn headless_browser(user: &'static str) -> Opener {
    Arc::new(move |u: &url::Url| {
        let mut u = u.clone();
        u.query_pairs_mut().append_pair("login_hint", user);
        tokio::spawn(async move {
            let _ = reqwest::get(u.as_str()).await;
        });
        Ok(())
    })
}

#[tokio::test]
async fn browser_login_round_trip() {
    let i = idp().await;
    let login = BrowserLogin {
        client: ManagedClient::new(true).unwrap(),
        issuer: i.issuer().into(),
        client_id: i.client_id().into(),
        opener: headless_browser("alice"),
        timeout: Duration::from_secs(10),
    };
    let token = login.id_token("nonce-1").await.unwrap();
    let id = Validator::new(true)
        .unwrap()
        .validate(
            &IssuerConfig {
                issuer: i.issuer().into(),
                client_id: i.client_id().into(),
                group_claim: "groups".into(),
            },
            &token,
            Some("nonce-1"),
        )
        .await
        .unwrap();
    assert_eq!(id.sub, "alice");
}

#[tokio::test]
async fn browser_login_times_out_when_nobody_signs_in() {
    let i = idp().await;
    let login = BrowserLogin {
        client: ManagedClient::new(true).unwrap(),
        issuer: i.issuer().into(),
        client_id: i.client_id().into(),
        opener: Arc::new(|_| Ok(())),
        timeout: Duration::from_millis(300),
    };
    assert!(login.id_token("n").await.is_err());
}

#[tokio::test]
async fn browser_login_fails_for_unknown_user() {
    let i = idp().await;
    let login = BrowserLogin {
        client: ManagedClient::new(true).unwrap(),
        issuer: i.issuer().into(),
        client_id: i.client_id().into(),
        opener: headless_browser("mallory"),
        timeout: Duration::from_millis(1500),
    };
    // The IdP refuses (no redirect), so no callback ever arrives.
    assert!(login.id_token("n").await.is_err());
}
