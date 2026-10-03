//! OIDC authorization-code flow with PKCE (RFC 7636, S256) for the client
//! side. `svx login` (Phase 3) drives this through a browser and a loopback
//! redirect listener; [`dev_auto_login`] drives it headlessly against the
//! auto-approving dev IdP for tests and demos.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use svx_core::crypto::random_bytes;

use crate::client::{ManagedClient, ProtocolError, Result, check_url};

#[derive(Clone, Debug, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// PKCE verifier and S256 challenge.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn new() -> Self {
        let verifier = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Pkce {
            verifier,
            challenge,
        }
    }
}

impl Default for Pkce {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn discover(client: &ManagedClient, issuer: &str) -> Result<Discovery> {
    let d: Discovery = client
        .get_json(issuer, "/.well-known/openid-configuration")
        .await?;
    // OIDC Discovery §4.3: the issuer in the document must match exactly.
    if d.issuer != issuer {
        return Err(ProtocolError::BadResponse(
            "discovery issuer mismatch".into(),
        ));
    }
    for u in [&d.authorization_endpoint, &d.token_endpoint, &d.jwks_uri] {
        check_url(u, client.allow_dev_http())?;
    }
    Ok(d)
}

pub struct AuthorizeParams<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    pub pkce: &'a Pkce,
    pub login_hint: Option<&'a str>,
}

pub fn authorize_url(d: &Discovery, p: &AuthorizeParams<'_>) -> Result<url::Url> {
    let mut u = url::Url::parse(&d.authorization_endpoint)
        .map_err(|_| ProtocolError::BadResponse("authorization endpoint".into()))?;
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", p.client_id)
            .append_pair("redirect_uri", p.redirect_uri)
            .append_pair("scope", "openid email")
            .append_pair("state", p.state)
            .append_pair("nonce", p.nonce)
            .append_pair("code_challenge", &p.pkce.challenge)
            .append_pair("code_challenge_method", "S256");
        if let Some(h) = p.login_hint {
            q.append_pair("login_hint", h);
        }
    }
    Ok(u)
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

pub async fn exchange_code(
    client: &ManagedClient,
    d: &Discovery,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    pkce: &Pkce,
) -> Result<String> {
    let resp = client
        .http()
        .post(&d.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", pkce.verifier.as_str()),
        ])
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(ProtocolError::Status(resp.status().as_u16()));
    }
    let t: TokenResponse = resp
        .json()
        .await
        .map_err(|e| ProtocolError::BadResponse(e.to_string()))?;
    Ok(t.id_token)
}

/// Run the whole flow against an IdP that approves immediately (the SVX
/// dev IdP). Never use against a real IdP: it bypasses the browser.
pub async fn dev_auto_login(
    client: &ManagedClient,
    issuer: &str,
    client_id: &str,
    login_hint: &str,
    nonce: &str,
) -> Result<String> {
    let d = discover(client, issuer).await?;
    let pkce = Pkce::new();
    let state = hex::encode(random_bytes::<16>());
    let redirect_uri = "http://127.0.0.1:9/callback";
    let url = authorize_url(
        &d,
        &AuthorizeParams {
            client_id,
            redirect_uri,
            state: &state,
            nonce,
            pkce: &pkce,
            login_hint: Some(login_hint),
        },
    )?;
    let resp = client.http().get(url).send().await?;
    if !resp.status().is_redirection() {
        return Err(ProtocolError::Status(resp.status().as_u16()));
    }
    let loc = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ProtocolError::BadResponse("no redirect".into()))?;
    let loc =
        url::Url::parse(loc).map_err(|_| ProtocolError::BadResponse("bad redirect".into()))?;
    let mut code = None;
    let mut got_state = None;
    for (k, v) in loc.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => got_state = Some(v.into_owned()),
            _ => {}
        }
    }
    if got_state.as_deref() != Some(state.as_str()) {
        return Err(ProtocolError::BadResponse("state mismatch".into()));
    }
    let code = code.ok_or_else(|| ProtocolError::BadResponse("no code".into()))?;
    exchange_code(client, &d, client_id, redirect_uri, &code, &pkce).await
}
