//! **Development-only** OpenID Connect provider.
//!
//! It implements just enough of OIDC for SVX demos and tests:
//!
//! * discovery and JWKS (one Ed25519 key);
//! * authorization-code flow with mandatory PKCE S256, `nonce` and `state`;
//! * loopback-only redirect URIs;
//! * immediate "login" of a configured fictional user chosen by `login_hint`.
//!
//! There are no passwords and no consent screen. It must never be exposed
//! beyond loopback; the binary refuses to bind elsewhere unless forced.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use svx_core::crypto::random_bytes;

/// A fictional user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub client_id: String,
    pub users: Vec<User>,
    #[serde(default = "default_ttl")]
    pub token_ttl_secs: i64,
}

fn default_ttl() -> i64 {
    300
}

const CODE_TTL: Duration = Duration::from_secs(60);

struct PendingCode {
    user: User,
    nonce: String,
    challenge: String,
    redirect_uri: String,
    created: Instant,
}

struct Inner {
    issuer: String,
    config: Config,
    kid: String,
    encoding_key: EncodingKey,
    public_x: String,
    codes: Mutex<HashMap<String, PendingCode>>,
}

/// A running IdP.
#[derive(Clone)]
pub struct MockIdp {
    inner: Arc<Inner>,
}

/// PKCS#8 v1 DER for an Ed25519 private key (RFC 8410).
fn ed25519_pkcs8(seed: &[u8; 32]) -> zeroize::Zeroizing<Vec<u8>> {
    let mut der = zeroize::Zeroizing::new(
        hex::decode("302e020100300506032b657004220420").expect("static hex"),
    );
    der.extend_from_slice(seed);
    der
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn is_loopback_redirect(uri: &str) -> bool {
    let Ok(u) = url::Url::parse(uri) else {
        return false;
    };
    let host_ok = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    };
    host_ok && matches!(u.scheme(), "http" | "https") && u.fragment().is_none()
}

impl MockIdp {
    /// Bind `addr` and serve. The issuer is `http://<bound addr>`.
    pub async fn spawn(config: Config, addr: SocketAddr) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let issuer = format!("http://{}", listener.local_addr()?);
        let seed: [u8; 32] = random_bytes();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_x = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
        let encoding_key = EncodingKey::from_ed_der(&ed25519_pkcs8(&seed));
        let kid = hex::encode(&Sha256::digest(sk.verifying_key().to_bytes())[..8]);
        let idp = MockIdp {
            inner: Arc::new(Inner {
                issuer,
                config,
                kid,
                encoding_key,
                public_x,
                codes: Mutex::new(HashMap::new()),
            }),
        };
        let app = idp.router();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(idp)
    }

    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    pub fn client_id(&self) -> &str {
        &self.inner.config.client_id
    }

    /// Sign arbitrary claims with this IdP's key. For negative tests only.
    pub fn mint(&self, claims: &Value) -> String {
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some(self.inner.kid.clone());
        jsonwebtoken::encode(&h, claims, &self.inner.encoding_key).expect("signing succeeds")
    }

    /// Standard claims for `user` with `nonce`, valid now.
    pub fn claims_for(&self, user: &User, nonce: &str) -> Value {
        let t = now();
        json!({
            "iss": self.inner.issuer,
            "aud": self.inner.config.client_id,
            "sub": user.sub,
            "email": user.email,
            "groups": user.groups,
            "acr": user.acr,
            "nonce": nonce,
            "iat": t,
            "auth_time": t,
            "exp": t + self.inner.config.token_ttl_secs,
        })
    }

    pub fn user(&self, sub: &str) -> Option<&User> {
        self.inner.config.users.iter().find(|u| u.sub == sub)
    }

    fn router(&self) -> Router {
        Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(self.clone())
    }
}

async fn discovery(State(idp): State<MockIdp>) -> Json<Value> {
    let i = &idp.inner.issuer;
    Json(json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "jwks_uri": format!("{i}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
    }))
}

async fn jwks(State(idp): State<MockIdp>) -> Json<Value> {
    Json(json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": idp.inner.public_x,
            "kid": idp.inner.kid,
            "alg": "EdDSA",
            "use": "sig",
        }]
    }))
}

fn oauth_error(code: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": code }))).into_response()
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    login_hint: Option<String>,
}

async fn authorize(State(idp): State<MockIdp>, Query(q): Query<AuthorizeQuery>) -> Response {
    if q.client_id != idp.inner.config.client_id || !is_loopback_redirect(&q.redirect_uri) {
        // Never redirect to an unvalidated URI.
        return oauth_error("invalid_request");
    }
    if q.response_type != "code" {
        return oauth_error("unsupported_response_type");
    }
    let (Some(challenge), Some("S256")) = (q.code_challenge, q.code_challenge_method.as_deref())
    else {
        return oauth_error("invalid_request");
    };
    let Some(nonce) = q.nonce.filter(|n| !n.is_empty() && n.len() <= 256) else {
        return oauth_error("invalid_request");
    };
    if challenge.len() != 43 || q.state.is_empty() || q.state.len() > 256 {
        return oauth_error("invalid_request");
    }
    let Some(user) = q.login_hint.as_deref().and_then(|h| idp.user(h)).cloned() else {
        return oauth_error("access_denied");
    };
    let code = hex::encode(random_bytes::<32>());
    {
        let mut codes = idp.inner.codes.lock().expect("lock");
        codes.retain(|_, c| c.created.elapsed() < CODE_TTL);
        codes.insert(
            code.clone(),
            PendingCode {
                user,
                nonce,
                challenge,
                redirect_uri: q.redirect_uri.clone(),
                created: Instant::now(),
            },
        );
    }
    let mut loc = url::Url::parse(&q.redirect_uri).expect("validated above");
    loc.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &q.state);
    (StatusCode::FOUND, [(header::LOCATION, loc.to_string())]).into_response()
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
}

async fn token(State(idp): State<MockIdp>, Form(f): Form<TokenForm>) -> Response {
    if f.grant_type != "authorization_code" {
        return oauth_error("unsupported_grant_type");
    }
    // Single use: the code is removed whether or not the rest succeeds.
    let pending = idp.inner.codes.lock().expect("lock").remove(&f.code);
    let Some(p) = pending else {
        return oauth_error("invalid_grant");
    };
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(f.code_verifier.as_bytes()));
    if p.created.elapsed() >= CODE_TTL
        || f.client_id != idp.inner.config.client_id
        || f.redirect_uri != p.redirect_uri
        || challenge != p.challenge
    {
        return oauth_error("invalid_grant");
    }
    let id_token = idp.mint(&idp.claims_for(&p.user, &p.nonce));
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "access_token": hex::encode(random_bytes::<16>()),
            "token_type": "Bearer",
            "expires_in": idp.inner.config.token_ttl_secs,
            "id_token": id_token,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_policy() {
        assert!(is_loopback_redirect("http://127.0.0.1:9/cb"));
        assert!(is_loopback_redirect("http://localhost:1234/cb"));
        assert!(is_loopback_redirect("http://[::1]:1/cb"));
        assert!(!is_loopback_redirect("https://evil.example/cb"));
        assert!(!is_loopback_redirect("http://127.0.0.1.evil.example/cb"));
        assert!(!is_loopback_redirect("javascript:alert(1)"));
        assert!(!is_loopback_redirect("http://127.0.0.1/cb#frag"));
    }
}
