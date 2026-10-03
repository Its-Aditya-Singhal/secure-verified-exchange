//! Login choices, the admin session lifecycle and identity checks, shared by
//! the CLI and the SDKs.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use svx_oidc::Validator;
use svx_protocol::ManagedClient;

use crate::config::ClientConfig;
use crate::error::{ClientError, Result};
use crate::login::{Authenticator, BrowserLogin, DevLogin, Opener};
use crate::session::{self, Session};

/// How long to wait for the user to finish signing in in the browser.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

/// How the user signs in.
pub enum LoginMethod {
    /// RFC 8252 browser login; `opener` presents the authorization URL.
    Browser(Opener),
    /// Auto-approving development IdP; only for `dev` configurations.
    Dev(String),
}

/// Build the authenticator for `method`, enforcing that dev logins are only
/// used with dev configurations.
pub fn authenticator(
    cfg: &ClientConfig,
    client: &ManagedClient,
    method: LoginMethod,
) -> Result<Box<dyn Authenticator>> {
    Ok(match method {
        LoginMethod::Dev(user) => {
            if !cfg.dev {
                return Err(ClientError::Config(
                    "dev login is only available with a dev configuration".into(),
                ));
            }
            Box::new(DevLogin {
                client: client.clone(),
                issuer: cfg.idp_issuer.clone(),
                client_id: cfg.idp_client_id.clone(),
                user,
            })
        }
        LoginMethod::Browser(opener) => Box::new(BrowserLogin {
            client: client.clone(),
            issuer: cfg.idp_issuer.clone(),
            client_id: cfg.idp_client_id.clone(),
            opener,
            timeout: LOGIN_TIMEOUT,
        }),
    })
}

/// A validated identity, safe to display.
#[derive(Clone, Debug, Serialize)]
pub struct WhoAmI {
    pub sub: String,
    pub org_id: String,
    pub issuer: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub acr: Option<String>,
    /// Session expiry, Unix seconds.
    pub expires_at: i64,
}

fn validator(cfg: &ClientConfig) -> Result<Validator> {
    Validator::new(cfg.dev).map_err(|e| ClientError::Other(e.to_string()))
}

/// Sign in and cache an admin session at `session_path`. The cached token
/// is a bearer for admin endpoints only; it can never release key shares.
pub async fn login(
    cfg: &ClientConfig,
    auth: &dyn Authenticator,
    session_path: &Path,
) -> Result<WhoAmI> {
    // A fresh random nonce prevents replaying an older token into this login.
    let nonce = hex::encode(svx_core::crypto::random_bytes::<16>());
    let token = auth.id_token(&nonce).await?;
    save_session(cfg, token, &nonce, session_path).await
}

/// Validate a freshly obtained ID token (issued for `nonce`) and cache it as
/// the admin session.
pub(crate) async fn save_session(
    cfg: &ClientConfig,
    token: String,
    nonce: &str,
    session_path: &Path,
) -> Result<WhoAmI> {
    let id = validator(cfg)?
        .validate(&cfg.issuer_config(), &token, Some(nonce))
        .await
        .map_err(|e| ClientError::Login(format!("the IdP returned an invalid token: {e}")))?;
    let exp =
        session::token_exp(&token).ok_or_else(|| ClientError::Login("token has no exp".into()))?;
    session::save(
        session_path,
        &Session {
            id_token: token,
            issuer: id.issuer.clone(),
            sub: id.sub.clone(),
            exp,
        },
    )?;
    Ok(WhoAmI {
        sub: id.sub,
        org_id: cfg.org_id.clone(),
        issuer: id.issuer,
        email: id.email,
        groups: id.groups,
        acr: id.acr,
        expires_at: exp,
    })
}

/// Re-validate the cached session. An invalid session is deleted and
/// reported as [`ClientError::NotLoggedIn`].
pub async fn whoami(cfg: &ClientConfig, session_path: &Path) -> Result<WhoAmI> {
    let s = session::require(session_path, crate::now())?;
    match validator(cfg)?
        .validate(&cfg.issuer_config(), &s.id_token, None)
        .await
    {
        Ok(id) => Ok(WhoAmI {
            sub: id.sub,
            org_id: cfg.org_id.clone(),
            issuer: id.issuer,
            email: id.email,
            groups: id.groups,
            acr: id.acr,
            expires_at: s.exp,
        }),
        Err(_) => {
            let _ = session::clear(session_path);
            Err(ClientError::NotLoggedIn)
        }
    }
}

/// The cached admin bearer token.
pub fn bearer(session_path: &Path) -> Result<String> {
    Ok(session::require(session_path, crate::now())?.id_token)
}
