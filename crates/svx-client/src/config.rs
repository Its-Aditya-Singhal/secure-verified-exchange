//! Client configuration (`config.toml`).
//!
//! The only trust anchor is `registry_key`: the fingerprint of the managed
//! service's SVX-2 (Ed25519 + ML-DSA-87 + SLH-DSA) registry key, pinned at `svx init`
//! time from an out-of-band source (the organization's admin, the service's
//! published fingerprint). Setup saves the full key in `registry_public`
//! only after it matched the fingerprint, and every load checks it again.
//! Every org and service key the client uses is verified against that key.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use svx_core::crypto::{KeyKind, VerifyingKey};
use svx_core::format::Identifier;
use svx_oidc::IssuerConfig;
use svx_protocol::check_url;

use crate::error::{ClientError, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Managed service base URL (https).
    pub service_url: String,
    /// Pinned fingerprint of the registry key (hex, 32 bytes).
    pub registry_key: String,
    /// The registry's SVX-2 public key (hex), saved by setup after it
    /// matched `registry_key`.
    #[serde(default)]
    pub registry_public: String,
    /// The user's organization.
    pub org_id: String,
    /// The organization's OIDC issuer (from its verified registry record).
    pub idp_issuer: String,
    /// Client ID registered for SVX at the org's IdP.
    pub idp_client_id: String,
    /// Claim carrying groups (only used to display `whoami`).
    #[serde(default = "default_group_claim")]
    pub group_claim: String,
    /// Development mode: allows plain-http loopback URLs and dev login.
    #[serde(default)]
    pub dev: bool,
    /// Where `svx open` writes files when `-o` is not given.
    #[serde(default)]
    pub default_output_dir: Option<PathBuf>,
    /// A (non-secret) client secret some providers give desktop apps
    /// (Google). PKCE protects the sign-in either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idp_client_secret: Option<String>,
    /// Set for a personal account (Google or email sign-in); `org_id` is
    /// then the account ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountConfig>,
}

/// A personal account's identity and where its device keys are.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// The verified email of the account.
    pub email: String,
    /// The device's SVX-2 signing key (`keychain:<account>/<key_id>`).
    pub signing_key: String,
    /// The key ID (hex) of the device's MLKEM1024-P384 key in the keychain.
    pub kem_key: String,
}

fn default_group_claim() -> String {
    "groups".into()
}

/// Where configuration and the session cache live.
#[derive(Clone, Debug)]
pub struct Paths {
    pub config: PathBuf,
    pub session: PathBuf,
}

impl Paths {
    /// `explicit` (from `--config`), else `$SVX_CONFIG`, else the platform
    /// config directory (e.g. `~/.config/svx/config.toml`).
    pub fn resolve(explicit: Option<&Path>) -> Result<Paths> {
        let config = match explicit {
            Some(p) => p.to_path_buf(),
            None => match std::env::var_os("SVX_CONFIG") {
                Some(p) => PathBuf::from(p),
                None => directories::ProjectDirs::from("org", "svx", "svx")
                    .ok_or_else(|| ClientError::Config("cannot determine config directory".into()))?
                    .config_dir()
                    .join("config.toml"),
            },
        };
        let session = config.with_file_name("session.json");
        Ok(Paths { config, session })
    }
}

impl ClientConfig {
    pub fn validate(&self) -> Result<()> {
        check_url(&self.service_url, self.dev)
            .map_err(|_| ClientError::Config("service_url must be https".into()))?;
        // Email accounts sign in with the service itself, not an IdP.
        let email_account =
            self.account.is_some() && self.idp_issuer == svx_protocol::email_account::EMAIL_ISSUER;
        if !email_account {
            check_url(&self.idp_issuer, self.dev)
                .map_err(|_| ClientError::Config("idp_issuer must be https".into()))?;
        }
        Identifier::new(&self.org_id).map_err(|_| ClientError::Config("invalid org_id".into()))?;
        if self.idp_client_id.is_empty() {
            return Err(ClientError::Config("idp_client_id is empty".into()));
        }
        self.registry_key()?;
        if let Some(a) = &self.account {
            if !self.org_id.starts_with("u.") {
                return Err(ClientError::Config(
                    "a personal account's ID starts with u.".into(),
                ));
            }
            crate::keystore::KeyRef::parse(&a.signing_key)?;
            if a.kem_key.len() != 32 || hex::decode(&a.kem_key).is_err() {
                return Err(ClientError::Config("invalid kem_key".into()));
            }
        }
        Ok(())
    }

    /// Whether this is a personal account (not a company).
    pub fn is_personal(&self) -> bool {
        self.account.is_some()
    }

    /// The registry key, checked against the pinned fingerprint.
    pub fn registry_key(&self) -> Result<VerifyingKey> {
        let pinned = parse_registry_fingerprint(&self.registry_key)?;
        if self.registry_public.is_empty() {
            return Err(ClientError::Config(
                "this setup predates post-quantum registry signatures: run `svx init` again \
                 (or Setup in the app) with the service's registry key fingerprint"
                    .into(),
            ));
        }
        let bytes = hex::decode(self.registry_public.trim())
            .map_err(|_| ClientError::Config("registry_public is not hex".into()))?;
        let key = VerifyingKey::from_kind_bytes(KeyKind::MaxSigning, &bytes).map_err(|_| {
            ClientError::Config(
                "this setup predates SVX-2 registry signatures: run `svx init` again (or Setup \
                 in the app) with the service's registry key fingerprint"
                    .into(),
            )
        })?;
        if key.fingerprint() != pinned {
            return Err(ClientError::Config(
                "registry_public does not match the pinned registry key fingerprint".into(),
            ));
        }
        Ok(key)
    }

    pub fn issuer_config(&self) -> IssuerConfig {
        IssuerConfig {
            issuer: self.idp_issuer.clone(),
            client_id: self.idp_client_id.clone(),
            group_claim: self.group_claim.clone(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            ClientError::Config(format!(
                "cannot read {} ({e}); run `svx init`",
                path.display()
            ))
        })?;
        let c: ClientConfig = toml::from_str(&text)
            .map_err(|e| ClientError::Config(format!("{}: {e}", path.display())))?;
        c.validate()?;
        Ok(c)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let text = toml::to_string_pretty(self).map_err(|e| ClientError::Other(e.to_string()))?;
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        std::io::Write::write_all(&mut tmp, text.as_bytes())?;
        tmp.persist(path).map_err(|e| ClientError::Io(e.error))?;
        Ok(())
    }
}

/// Default output directory for opened artifacts: `~/SVX`. Used when
/// neither `-o` nor `default_output_dir` is set, so file-manager launches
/// never write into an arbitrary working directory. The open flow creates
/// it (owner-only) only once access has been approved.
pub fn default_open_dir() -> Result<PathBuf> {
    Ok(directories::UserDirs::new()
        .ok_or_else(|| ClientError::Config("cannot determine home directory".into()))?
        .home_dir()
        .join("SVX"))
}

/// Parse a registry key fingerprint (64 hex characters).
pub fn parse_registry_fingerprint(hex_fp: &str) -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    hex::decode_to_slice(hex_fp.trim(), &mut b).map_err(|_| {
        ClientError::Config("the registry key fingerprint must be 64 hex characters".into())
    })?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use svx_core::crypto::SigningKey;

    fn registry() -> VerifyingKey {
        // One fixed key, so `registry_key` and `registry_public` match.
        SigningKey::from_secret_bytes(KeyKind::MaxSigning, &[1; 160])
            .unwrap()
            .verifying_key()
    }

    fn cfg() -> ClientConfig {
        ClientConfig {
            service_url: "https://svx.example".into(),
            registry_key: hex::encode(registry().fingerprint()),
            registry_public: hex::encode(registry().to_vec()),
            org_id: "example-corp".into(),
            idp_issuer: "https://login.example-corp.example".into(),
            idp_client_id: "svx".into(),
            group_claim: "groups".into(),
            dev: false,
            default_output_dir: None,
            idp_client_secret: None,
            account: None,
        }
    }

    #[test]
    fn validation() {
        cfg().validate().unwrap();
        let mut c = cfg();
        c.service_url = "http://svx.example".into();
        assert!(c.validate().is_err());
        let mut c = cfg();
        c.service_url = "http://127.0.0.1:8443".into();
        assert!(c.validate().is_err(), "loopback http needs dev");
        c.dev = true;
        c.validate().unwrap();
        let mut c = cfg();
        c.registry_key = "00".repeat(31);
        assert!(c.validate().is_err());
        let mut c = cfg();
        c.org_id = "Example Corp".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn registry_key_is_checked_against_the_pin() {
        assert_eq!(cfg().registry_key().unwrap(), registry());
        // Another key in registry_public: refused.
        let mut c = cfg();
        c.registry_public = hex::encode(
            SigningKey::from_secret_bytes(KeyKind::MaxSigning, &[3; 160])
                .unwrap()
                .verifying_key()
                .to_vec(),
        );
        assert!(c.validate().is_err());
        // An older (hybrid) key whose fingerprint was pinned: refused.
        let old = SigningKey::hybrid_from_seeds(&[3; 32], &[4; 32]).verifying_key();
        let mut c = cfg();
        c.registry_key = hex::encode(old.fingerprint());
        c.registry_public = hex::encode(old.to_vec());
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("svx init"), "{e}");
        // A classical key whose fingerprint was pinned: refused.
        let ed = SigningKey::from_bytes(&[5; 32]).verifying_key();
        let mut c = cfg();
        c.registry_key = hex::encode(ed.fingerprint());
        c.registry_public = hex::encode(ed.to_vec());
        assert!(c.validate().is_err());
        // A configuration from before post-quantum registry signatures: asked to set up again.
        let mut c = cfg();
        c.registry_key = hex::encode(ed.to_bytes());
        c.registry_public.clear();
        let e = c.validate().unwrap_err().to_string();
        assert!(e.contains("svx init"), "{e}");
    }

    #[test]
    fn save_load_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("nested/config.toml");
        let c = cfg();
        c.save(&p).unwrap();
        assert_eq!(ClientConfig::load(&p).unwrap(), c);
        std::fs::write(&p, "service_url = 'https://x'\nunknown = 1\n").unwrap();
        assert!(ClientConfig::load(&p).is_err());
    }
}
