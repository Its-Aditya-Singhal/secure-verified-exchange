//! Configuration of relayed sign-ins (see `routes::relay`).

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

/// Apple's issuer.
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// What the service needs to relay sign-ins.
#[derive(Default)]
pub struct RelayConfig {
    /// `<public URL>/v1/auth/relay/callback`, registered with each relayed
    /// provider. Without it, relayed providers can't be used.
    pub redirect_uri: Option<String>,
    /// Signs Apple's client secret (a short-lived ES256 JWT).
    pub apple: Option<AppleKey>,
}

/// An Apple "Sign in with Apple" private key (`AuthKey_<key_id>.p8`).
pub struct AppleKey {
    pub team_id: String,
    pub key_id: String,
    key: EncodingKey,
}

#[derive(Serialize)]
struct AppleClaims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
    aud: &'a str,
    sub: &'a str,
}

impl AppleKey {
    pub fn from_pem(team_id: &str, key_id: &str, pem: &[u8]) -> anyhow::Result<Self> {
        Ok(AppleKey {
            team_id: team_id.to_owned(),
            key_id: key_id.to_owned(),
            key: EncodingKey::from_ec_pem(pem)
                .map_err(|e| anyhow::anyhow!("the Apple key must be an ES256 .p8 PEM: {e}"))?,
        })
    }

    /// The client secret for `client_id` (the Services ID), valid 5 minutes.
    pub fn client_secret(&self, client_id: &str) -> anyhow::Result<String> {
        let now = svx_protocol::unix_now();
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some(self.key_id.clone());
        Ok(jsonwebtoken::encode(
            &h,
            &AppleClaims {
                iss: &self.team_id,
                iat: now,
                exp: now + 300,
                aud: APPLE_ISSUER,
                sub: client_id,
            },
            &self.key,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fictional P-256 test key (not used anywhere real).
    const PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDHYIN5YGe4OIqR0I
GdNg6169JZdoXSPVwqK/Mc0MLAuhRANCAAQ6i0iDukEDclthF/dJptgy+LXYaK5i
57kjwf1qdYTvfmjgZApcDZpfJuekfC2QIxrs5aakKSwsn0lve9o7alNh
-----END PRIVATE KEY-----
";

    #[test]
    fn apple_client_secret_is_an_es256_jwt() {
        let k = AppleKey::from_pem("TEAM123456", "KEY1234567", PEM.as_bytes()).unwrap();
        let jwt = k.client_secret("org.svx.signin").unwrap();
        let h = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(h.alg, Algorithm::ES256);
        assert_eq!(h.kid.as_deref(), Some("KEY1234567"));
        assert!(AppleKey::from_pem("T", "K", b"not a key").is_err());
    }
}
