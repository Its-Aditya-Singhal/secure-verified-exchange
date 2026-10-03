//! Client configuration (`config.toml`).
//!
//! The only trust anchor is `registry_key`: the managed service's registry
//! public key, pinned at `svx init` time from an out-of-band source (the
//! organization's admin, the service's published fingerprint). Every org
//! and service key the client uses is verified against it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use svx_core::crypto::VerifyingKey;
use svx_core::format::Identifier;
use svx_oidc::IssuerConfig;
use svx_protocol::check_url;

use crate::error::{ClientError, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Managed service base URL (https).
    pub service_url: String,
    /// Pinned registry public key (hex, 32 bytes).
    pub registry_key: String,
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
        check_url(&self.idp_issuer, self.dev)
            .map_err(|_| ClientError::Config("idp_issuer must be https".into()))?;
        Identifier::new(&self.org_id).map_err(|_| ClientError::Config("invalid org_id".into()))?;
        if self.idp_client_id.is_empty() {
            return Err(ClientError::Config("idp_client_id is empty".into()));
        }
        self.registry_key()?;
        Ok(())
    }

    pub fn registry_key(&self) -> Result<VerifyingKey> {
        parse_registry_key(&self.registry_key)
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

pub fn parse_registry_key(hex_key: &str) -> Result<VerifyingKey> {
    let mut b = [0u8; 32];
    hex::decode_to_slice(hex_key.trim(), &mut b)
        .map_err(|_| ClientError::Config("registry_key must be 64 hex characters".into()))?;
    VerifyingKey::from_bytes(&b)
        .map_err(|_| ClientError::Config("registry_key is not a valid Ed25519 key".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use svx_core::crypto::{SigningKey, os_rng};

    fn cfg() -> ClientConfig {
        ClientConfig {
            service_url: "https://svx.example".into(),
            registry_key: hex::encode(
                SigningKey::generate(&mut os_rng())
                    .verifying_key()
                    .to_bytes(),
            ),
            org_id: "example-corp".into(),
            idp_issuer: "https://login.example-corp.example".into(),
            idp_client_id: "svx".into(),
            group_claim: "groups".into(),
            dev: false,
            default_output_dir: None,
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
