//! OIDC login for the client.
//!
//! [`BrowserLogin`] implements the native-app flow from RFC 8252: an
//! authorization-code request with PKCE (S256), `state` and `nonce`,
//! redirected to a one-shot HTTP listener on `127.0.0.1`. [`DevLogin`]
//! drives the auto-approving development IdP headlessly.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use svx_core::crypto::random_bytes;
use svx_protocol::ManagedClient;
use svx_protocol::oidc_login::{
    AuthorizeParams, Pkce, authorize_url, dev_auto_login, discover, exchange_code,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{ClientError, Result};

/// Produces an ID token from the user's organization IdP carrying `nonce`.
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn id_token(&self, nonce: &str) -> Result<String>;
}

/// Development IdP login (no browser). Only for `dev` configurations.
pub struct DevLogin {
    pub client: ManagedClient,
    pub issuer: String,
    pub client_id: String,
    pub user: String,
}

#[async_trait]
impl Authenticator for DevLogin {
    async fn id_token(&self, nonce: &str) -> Result<String> {
        dev_auto_login(
            &self.client,
            &self.issuer,
            &self.client_id,
            &self.user,
            nonce,
        )
        .await
        .map_err(|e| ClientError::Login(e.to_string()))
    }
}

/// How to send the user to the authorization URL.
pub type Opener = Arc<dyn Fn(&url::Url) -> std::result::Result<(), String> + Send + Sync>;

/// Open the system browser; if that fails, print the URL.
pub fn system_browser() -> Opener {
    Arc::new(|u: &url::Url| {
        if webbrowser::open(u.as_str()).is_err() {
            eprintln!("Open this URL in your browser to sign in:\n  {u}");
        }
        Ok(())
    })
}

/// Print the URL only (`--no-browser`, e.g. over SSH with port forwarding).
pub fn print_url() -> Opener {
    Arc::new(|u: &url::Url| {
        eprintln!("Open this URL in your browser to sign in:\n  {u}");
        Ok(())
    })
}

/// RFC 8252 loopback-redirect login.
pub struct BrowserLogin {
    pub client: ManagedClient,
    pub issuer: String,
    pub client_id: String,
    /// Only for providers that give desktop apps a (non-secret) one.
    pub client_secret: Option<String>,
    pub opener: Opener,
    pub timeout: Duration,
}

const MAX_REQUEST: usize = 8 * 1024;
const DONE_PAGE: &str = "<!doctype html><meta charset=utf-8><title>SVX</title>\
<p>Sign-in complete. You can close this tab and return to SVX.</p>";
const FAIL_PAGE: &str = "<!doctype html><meta charset=utf-8><title>SVX</title>\
<p>Sign-in failed. Return to SVX for details.</p>";

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Read the request line of one HTTP request (bounded).
async fn read_request_target(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        if buf.len() >= MAX_REQUEST {
            return None;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line = std::str::from_utf8(&buf).ok()?.lines().next()?.to_owned();
    let mut parts = line.split(' ');
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(target)) => Some(target.to_owned()),
        _ => None,
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Outcome of the loopback callback.
#[derive(Debug, PartialEq, Eq)]
enum Callback {
    Code(String),
    Error(String),
}

/// Accept connections until the `/callback` request arrives (other paths,
/// e.g. `/favicon.ico`, get 404). The first callback decides: a wrong
/// `state` fails the login rather than waiting for another attempt.
async fn await_callback(listener: TcpListener, state: &str) -> Result<Callback> {
    loop {
        let (mut stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let Some(target) = read_request_target(&mut stream).await else {
            respond(&mut stream, "400 Bad Request", FAIL_PAGE).await;
            continue;
        };
        let Ok(u) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
            respond(&mut stream, "400 Bad Request", FAIL_PAGE).await;
            continue;
        };
        if u.path() != "/callback" {
            respond(&mut stream, "404 Not Found", "").await;
            continue;
        }
        let q: std::collections::HashMap<String, String> = u.query_pairs().into_owned().collect();
        if !q.get("state").is_some_and(|s| ct_eq(s, state)) {
            respond(&mut stream, "400 Bad Request", FAIL_PAGE).await;
            return Err(ClientError::Login("state mismatch in callback".into()));
        }
        if let Some(err) = q.get("error") {
            respond(&mut stream, "200 OK", FAIL_PAGE).await;
            return Ok(Callback::Error(err.clone()));
        }
        match q.get("code") {
            Some(c) if !c.is_empty() => {
                respond(&mut stream, "200 OK", DONE_PAGE).await;
                return Ok(Callback::Code(c.clone()));
            }
            _ => {
                respond(&mut stream, "400 Bad Request", FAIL_PAGE).await;
                return Err(ClientError::Login("callback without code".into()));
            }
        }
    }
}

#[async_trait]
impl Authenticator for BrowserLogin {
    async fn id_token(&self, nonce: &str) -> Result<String> {
        let d = discover(&self.client, &self.issuer)
            .await
            .map_err(|e| ClientError::Login(format!("IdP discovery: {e}")))?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let redirect_uri = format!(
            "http://127.0.0.1:{}/callback",
            listener.local_addr()?.port()
        );
        let pkce = Pkce::new();
        let state = hex::encode(random_bytes::<16>());
        let url = authorize_url(
            &d,
            &AuthorizeParams {
                client_id: &self.client_id,
                redirect_uri: &redirect_uri,
                state: &state,
                nonce,
                pkce: &pkce,
                login_hint: None,
            },
        )
        .map_err(|e| ClientError::Login(e.to_string()))?;
        (self.opener)(&url).map_err(ClientError::Login)?;

        let cb = tokio::time::timeout(self.timeout, await_callback(listener, &state))
            .await
            .map_err(|_| ClientError::Login("timed out waiting for sign-in".into()))??;
        let code = match cb {
            Callback::Code(c) => c,
            Callback::Error(e) => {
                return Err(ClientError::Login(format!("IdP returned error: {e}")));
            }
        };
        exchange_code(
            &self.client,
            &d,
            &self.client_id,
            self.client_secret.as_deref(),
            &redirect_uri,
            &code,
            &pkce,
        )
        .await
        .map_err(|e| ClientError::Login(format!("code exchange: {e}")))
    }
}

/// Sign-in relayed through the SVX service, for providers that don't
/// allow desktop apps' loopback redirects (Apple). The service receives the
/// provider's callback; this side keeps a random secret (only its hash is
/// sent) and collects the ID token with it. The token's `nonce` is still
/// chosen here, so it binds this device's keys as with any other sign-in.
pub struct RelayLogin {
    pub client: ManagedClient,
    pub service_url: String,
    pub issuer: String,
    pub opener: Opener,
    pub timeout: Duration,
}

#[async_trait]
impl Authenticator for RelayLogin {
    async fn id_token(&self, nonce: &str) -> Result<String> {
        use svx_protocol::personal::{
            RelayPollRequest, RelayPollResponse, RelayStartRequest, RelayStartResponse,
            relay_secret_hash,
        };
        let secret = zeroize::Zeroizing::new(random_bytes::<32>());
        let start: RelayStartResponse = self
            .client
            .post_json(
                &self.service_url,
                "/v1/auth/relay/start",
                &RelayStartRequest {
                    issuer: self.issuer.clone(),
                    nonce: nonce.to_owned(),
                    secret_hash: relay_secret_hash(&secret),
                },
                None,
            )
            .await?;
        // Only ever send the person to an https sign-in page.
        let url = svx_protocol::check_url(&start.authorize_url, self.client.allow_dev_http())
            .map_err(|_| ClientError::Login("the service gave an insecure sign-in URL".into()))?;
        (self.opener)(&url).map_err(ClientError::Login)?;
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let r: RelayPollResponse = self
                .client
                .post_json(
                    &self.service_url,
                    "/v1/auth/relay/poll",
                    &RelayPollRequest {
                        relay_id: start.relay_id,
                        secret: *secret,
                    },
                    None,
                )
                .await?;
            match r {
                RelayPollResponse::Done { id_token } => return Ok(id_token),
                RelayPollResponse::Failed { reason } => return Err(ClientError::Login(reason)),
                RelayPollResponse::Pending if tokio::time::Instant::now() >= deadline => {
                    return Err(ClientError::Login("timed out waiting for sign-in".into()));
                }
                RelayPollResponse::Pending => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(port: u16, path: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    async fn listener() -> (TcpListener, u16) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        (l, p)
    }

    #[tokio::test]
    async fn callback_accepts_matching_state_after_noise() {
        let (l, port) = listener().await;
        let h = tokio::spawn(async move { await_callback(l, "abc").await });
        assert!(get(port, "/favicon.ico").await.starts_with("HTTP/1.1 404"));
        assert!(
            get(port, "/callback?code=xyz&state=abc")
                .await
                .starts_with("HTTP/1.1 200")
        );
        assert_eq!(h.await.unwrap().unwrap(), Callback::Code("xyz".into()));
    }

    #[tokio::test]
    async fn callback_rejects_wrong_state_once_and_for_all() {
        let (l, port) = listener().await;
        let h = tokio::spawn(async move { await_callback(l, "abc").await });
        assert!(
            get(port, "/callback?code=xyz&state=abd")
                .await
                .starts_with("HTTP/1.1 400")
        );
        assert!(matches!(h.await.unwrap(), Err(ClientError::Login(_))));
    }

    #[tokio::test]
    async fn callback_reports_idp_error() {
        let (l, port) = listener().await;
        let h = tokio::spawn(async move { await_callback(l, "s").await });
        get(port, "/callback?error=access_denied&state=s").await;
        assert_eq!(
            h.await.unwrap().unwrap(),
            Callback::Error("access_denied".into())
        );
    }

    #[tokio::test]
    async fn oversized_request_is_ignored() {
        let (l, port) = listener().await;
        let h = tokio::spawn(async move { await_callback(l, "s").await });
        // The listener drops an oversized request unread, so the client may
        // see a reset (macOS does); only the server's behavior matters here.
        let long = format!("/callback?pad={}", "a".repeat(10_000));
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await {
            let _ = s
                .write_all(format!("GET {long} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await;
            let mut sink = Vec::new();
            let _ = s.read_to_end(&mut sink).await;
        }
        get(port, "/callback?code=c&state=s").await;
        assert_eq!(h.await.unwrap().unwrap(), Callback::Code("c".into()));
    }
}
