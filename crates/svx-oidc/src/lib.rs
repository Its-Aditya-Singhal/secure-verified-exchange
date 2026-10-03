//! OpenID Connect ID-token validation.
//!
//! What is checked, in order:
//!
//! 1. Size limit and JOSE header: `alg` must be on an asymmetric allow-list
//!    (`none` and all HMAC algorithms are rejected); embedded `jwk`/`jku`
//!    headers are ignored — keys come only from the issuer's JWKS.
//! 2. Keys: discovered from `<issuer>/.well-known/openid-configuration`
//!    (whose `issuer` must match exactly), fetched over https, cached, and
//!    refreshed at most every 30 s on an unknown `kid`.
//! 3. Signature, `iss` (exact), `aud` (must contain the client ID),
//!    `exp`/`nbf` (60 s leeway), and presence of `sub` and `iat`.
//! 4. Freshness: `iat` no older than `max_token_age`.
//! 5. `nonce`, when the caller binds one (key release always does).
//!
//! Claims supplied by users ("username=alice") are never trusted; only the
//! verified token is.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;
use svx_protocol::oidc_login::discover;
use svx_protocol::{ManagedClient, unix_now};
use tokio::sync::RwLock;

/// Tokens larger than this are rejected before parsing.
pub const MAX_TOKEN_LEN: usize = 16 * 1024;
/// Default maximum age of an ID token (`now - iat`).
pub const DEFAULT_MAX_TOKEN_AGE: i64 = 10 * 60;
const LEEWAY_SECS: u64 = 60;
const JWKS_TTL: Duration = Duration::from_secs(10 * 60);
const JWKS_MIN_REFRESH: Duration = Duration::from_secs(30);

const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::EdDSA,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

/// How to validate tokens for one organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerConfig {
    pub issuer: String,
    pub client_id: String,
    /// Claim carrying group memberships (string or array of strings).
    pub group_claim: String,
}

/// A validated user identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub issuer: String,
    pub sub: String,
    pub groups: Vec<String>,
    pub acr: Option<String>,
    pub email: Option<String>,
    /// The issuer vouches that `email` belongs to this user
    /// (`email_verified`, a boolean or Apple's `"true"`).
    pub email_verified: bool,
    pub iat: i64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcError {
    #[error("token malformed")]
    Malformed,
    #[error("token algorithm not allowed")]
    AlgorithmNotAllowed,
    #[error("signing key not found in issuer JWKS")]
    KeyNotFound,
    #[error("token invalid: {0}")]
    Invalid(String),
    #[error("token too old")]
    Stale,
    #[error("nonce mismatch")]
    Nonce,
    #[error("issuer unavailable: {0}")]
    Unavailable(String),
}

pub type Result<T> = std::result::Result<T, OidcError>;

struct CachedJwks {
    set: JwkSet,
    fetched: Instant,
}

/// Validates ID tokens; caches JWKS per issuer. Cheap to share via `Arc`.
pub struct Validator {
    client: ManagedClient,
    cache: RwLock<HashMap<String, CachedJwks>>,
    max_token_age: i64,
}

impl Validator {
    /// `allow_dev_http` permits plain-http issuers on loopback only.
    pub fn new(allow_dev_http: bool) -> Result<Self> {
        Ok(Validator {
            client: ManagedClient::new(allow_dev_http)
                .map_err(|e| OidcError::Unavailable(e.to_string()))?,
            cache: RwLock::new(HashMap::new()),
            max_token_age: DEFAULT_MAX_TOKEN_AGE,
        })
    }

    pub fn with_max_token_age(mut self, secs: i64) -> Self {
        self.max_token_age = secs;
        self
    }

    /// Read `iss` from a token *without* verifying it. Only for choosing
    /// which [`IssuerConfig`] to validate against; never for authorization.
    pub fn unverified_issuer(token: &str) -> Option<String> {
        if token.len() > MAX_TOKEN_LEN {
            return None;
        }
        let data = jsonwebtoken::dangerous::insecure_decode::<Value>(token).ok()?;
        data.claims.get("iss")?.as_str().map(str::to_owned)
    }

    async fn fetch_jwks(&self, issuer: &str) -> Result<JwkSet> {
        let d = discover(&self.client, issuer)
            .await
            .map_err(|e| OidcError::Unavailable(e.to_string()))?;
        let resp = self
            .client
            .http()
            .get(&d.jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::Unavailable(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(OidcError::Unavailable(format!(
                "JWKS status {}",
                resp.status()
            )));
        }
        resp.json::<JwkSet>()
            .await
            .map_err(|e| OidcError::Unavailable(e.to_string()))
    }

    async fn key_for(&self, issuer: &str, kid: Option<&str>) -> Result<DecodingKey> {
        let find = |set: &JwkSet| -> Option<DecodingKey> {
            let jwk = match kid {
                Some(k) => set.find(k)?,
                // Without a kid, accept only an unambiguous single-key set.
                None if set.keys.len() == 1 => &set.keys[0],
                None => return None,
            };
            DecodingKey::from_jwk(jwk).ok()
        };

        let mut stale = true;
        if let Some(c) = self.cache.read().await.get(issuer) {
            if let Some(k) = find(&c.set)
                && c.fetched.elapsed() < JWKS_TTL
            {
                return Ok(k);
            }
            stale = c.fetched.elapsed() >= JWKS_MIN_REFRESH;
        }
        if !stale {
            return Err(OidcError::KeyNotFound);
        }
        let set = self.fetch_jwks(issuer).await?;
        let key = find(&set);
        self.cache.write().await.insert(
            issuer.to_owned(),
            CachedJwks {
                set,
                fetched: Instant::now(),
            },
        );
        key.ok_or(OidcError::KeyNotFound)
    }

    /// Validate `token` for `cfg`. If `expected_nonce` is given, the token's
    /// `nonce` claim must equal it.
    pub async fn validate(
        &self,
        cfg: &IssuerConfig,
        token: &str,
        expected_nonce: Option<&str>,
    ) -> Result<Identity> {
        if token.is_empty() || token.len() > MAX_TOKEN_LEN {
            return Err(OidcError::Malformed);
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| OidcError::Malformed)?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(OidcError::AlgorithmNotAllowed);
        }
        let key = self.key_for(&cfg.issuer, header.kid.as_deref()).await?;

        let mut v = Validation::new(header.alg);
        v.set_issuer(&[&cfg.issuer]);
        v.set_audience(&[&cfg.client_id]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        v.leeway = LEEWAY_SECS;
        v.validate_nbf = true;
        let data = jsonwebtoken::decode::<Value>(token, &key, &v)
            .map_err(|e| OidcError::Invalid(e.kind().to_string_lossy()))?;
        let c = data.claims;

        let sub = c
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 255)
            .ok_or_else(|| OidcError::Invalid("sub".into()))?
            .to_owned();
        let iat = c
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| OidcError::Invalid("iat".into()))?;
        let now = unix_now();
        if now - iat > self.max_token_age || iat - now > LEEWAY_SECS as i64 {
            return Err(OidcError::Stale);
        }
        if let Some(n) = expected_nonce
            && c.get("nonce").and_then(Value::as_str) != Some(n)
        {
            return Err(OidcError::Nonce);
        }
        let groups = match c.get(&cfg.group_claim) {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|g| g.as_str().map(str::to_owned))
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        };
        Ok(Identity {
            issuer: cfg.issuer.clone(),
            sub,
            groups,
            acr: c.get("acr").and_then(Value::as_str).map(str::to_owned),
            email: c.get("email").and_then(Value::as_str).map(str::to_owned),
            email_verified: matches!(c.get("email_verified"), Some(Value::Bool(true)))
                || c.get("email_verified").and_then(Value::as_str) == Some("true"),
            iat,
        })
    }
}

trait KindLossy {
    fn to_string_lossy(&self) -> String;
}

impl KindLossy for jsonwebtoken::errors::ErrorKind {
    fn to_string_lossy(&self) -> String {
        format!("{self:?}")
    }
}
