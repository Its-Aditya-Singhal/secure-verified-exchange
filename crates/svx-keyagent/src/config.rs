//! Key agent configuration: an `agent.toml` file (for containers and
//! services), with command-line flags taking precedence.
//!
//! ```toml
//! database_url = "postgres://svx_agent@db/svx_agent"
//! org_id = "example-corp"
//! idp_issuer = "https://login.example-corp.example"
//! idp_client_id = "svx"
//! service_id = "svx.example"
//! service_grant_key = "/run/secrets/service-grant.sign.pub"
//! kem_keys = ["/run/secrets/example.kem.key"]
//! listen = "0.0.0.0:9443"
//! tls_cert = "/run/secrets/tls.crt"
//! tls_key = "/run/secrets/tls.key"
//! # Optional: lets `svx-keyagent check` compare these keys with the registry.
//! service_url = "https://svx.example"
//! registry_key = "<registry key fingerprint, 64 hex>"
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use svx_core::crypto::{KemSecretKey, KeyKind, VerifyingKey};
use svx_core::format::Identifier;
use svx_core::keyfile;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:9443";

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub database_url: Option<String>,
    pub org_id: Option<String>,
    pub idp_issuer: Option<String>,
    pub idp_client_id: Option<String>,
    pub group_claim: Option<String>,
    pub service_id: Option<String>,
    pub service_grant_key: Option<PathBuf>,
    #[serde(default)]
    pub kem_keys: Vec<PathBuf>,
    pub listen: Option<SocketAddr>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    #[serde(default)]
    pub dev: bool,
    pub service_url: Option<String>,
    pub registry_key: Option<String>,
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// Fill unset fields from `other` (the file); fields set here win.
    pub fn or(self, other: AgentConfig) -> AgentConfig {
        AgentConfig {
            database_url: self.database_url.or(other.database_url),
            org_id: self.org_id.or(other.org_id),
            idp_issuer: self.idp_issuer.or(other.idp_issuer),
            idp_client_id: self.idp_client_id.or(other.idp_client_id),
            group_claim: self.group_claim.or(other.group_claim),
            service_id: self.service_id.or(other.service_id),
            service_grant_key: self.service_grant_key.or(other.service_grant_key),
            kem_keys: if self.kem_keys.is_empty() {
                other.kem_keys
            } else {
                self.kem_keys
            },
            listen: self.listen.or(other.listen),
            tls_cert: self.tls_cert.or(other.tls_cert),
            tls_key: self.tls_key.or(other.tls_key),
            dev: self.dev || other.dev,
            service_url: self.service_url.or(other.service_url),
            registry_key: self.registry_key.or(other.registry_key),
        }
    }

    pub fn require<'a, T>(v: &'a Option<T>, name: &str) -> Result<&'a T> {
        v.as_ref()
            .with_context(|| format!("missing `{name}` (flag or config file)"))
    }

    pub fn listen(&self) -> SocketAddr {
        self.listen
            .unwrap_or_else(|| DEFAULT_LISTEN.parse().expect("valid default"))
    }

    /// TLS is required except for `dev` on a loopback address.
    pub fn check_tls(&self) -> Result<()> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(_), Some(_)) => Ok(()),
            (None, None) if self.dev && self.listen().ip().is_loopback() => Ok(()),
            (None, None) => bail!(
                "TLS is required (tls_cert and tls_key); plain HTTP only in dev mode on loopback"
            ),
            _ => bail!("set both tls_cert and tls_key"),
        }
    }
}

/// The keys the agent runs with.
pub struct LoadedKeys {
    pub org_id: Identifier,
    pub kem_keys: Vec<KemSecretKey>,
    pub service_grant_key: VerifyingKey,
}

/// Load and check every key: secret key files must be owner-only and owned
/// by this organization, at least one must be MLKEM1024-P384 (suite SVX-2)
/// so new files can be opened, and the service grant key must be an SVX-2
/// (Ed25519 + ML-DSA-87 + SLH-DSA) key.
pub fn load_keys(cfg: &AgentConfig) -> Result<LoadedKeys> {
    let org_id =
        Identifier::new(AgentConfig::require(&cfg.org_id, "org_id")?).context("invalid org_id")?;
    if cfg.kem_keys.is_empty() {
        bail!("no encryption keys configured (kem_keys / --kem-key)");
    }
    let mut kem_keys = Vec::new();
    for p in &cfg.kem_keys {
        check_private(p)?;
        let (owner, sk) =
            keyfile::load_kem_secret(p).with_context(|| format!("loading {}", p.display()))?;
        if owner != org_id {
            bail!("{} belongs to {owner}, not {org_id}", p.display());
        }
        kem_keys.push(sk);
    }
    if !kem_keys.iter().any(|k| k.kind() == KeyKind::MaxKem) {
        bail!(
            "no MLKEM1024-P384 (SVX-2) encryption key configured; new files can't be opened \
             without one (svx keygen --kind kem)"
        );
    }
    let grant = AgentConfig::require(&cfg.service_grant_key, "service_grant_key")?;
    let (_, service_grant_key) = keyfile::load_verifying_key(grant)
        .with_context(|| format!("loading {}", grant.display()))?;
    if service_grant_key.kind() != KeyKind::MaxSigning {
        bail!(
            "the service grant key must be an SVX-2 key (Ed25519 + ML-DSA-87 + SLH-DSA); \
             get the current one from your SVX service"
        );
    }
    Ok(LoadedKeys {
        org_id,
        kem_keys,
        service_grant_key,
    })
}

/// Refuse secret key files that other users could read.
#[cfg(unix)]
fn check_private(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(p)
        .with_context(|| format!("reading {}", p.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} is readable by other users (mode {:o}); run chmod 600 on it",
            p.display(),
            mode & 0o777
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use svx_core::crypto::{SigningKey, os_rng};

    fn write_keys(dir: &Path, current: bool) -> AgentConfig {
        write_keys_with_grant(dir, current, SigningKey::generate_max(&mut os_rng()))
    }

    fn write_keys_with_grant(dir: &Path, current: bool, grant: SigningKey) -> AgentConfig {
        let org = Identifier::new("example-corp").unwrap();
        let kem = if current {
            KemSecretKey::generate_max(&mut os_rng())
        } else {
            KemSecretKey::generate_hybrid(&mut os_rng())
        };
        keyfile::write_kem_pair(&dir.join("example"), &org, &kem).unwrap();
        let svc = Identifier::new("svx.example").unwrap();
        keyfile::write_signing_pair(&dir.join("grant"), &svc, &grant).unwrap();
        AgentConfig {
            org_id: Some("example-corp".into()),
            kem_keys: vec![dir.join("example.kem.key")],
            service_grant_key: Some(dir.join("grant.sign.pub")),
            ..Default::default()
        }
    }

    #[test]
    fn config_file_and_flags_merge() {
        let file: AgentConfig = toml::from_str(
            r#"
            org_id = "example-corp"
            kem_keys = ["/keys/a.kem.key"]
            listen = "0.0.0.0:9443"
            dev = false
            "#,
        )
        .unwrap();
        let flags = AgentConfig {
            org_id: Some("other".into()),
            ..Default::default()
        };
        let c = flags.or(file);
        assert_eq!(c.org_id.as_deref(), Some("other"));
        assert_eq!(c.kem_keys, vec![PathBuf::from("/keys/a.kem.key")]);
        assert_eq!(c.listen().port(), 9443);
        assert!(c.check_tls().is_err(), "TLS required off loopback");
        assert!(toml::from_str::<AgentConfig>("unknown = 1").is_err());
    }

    #[test]
    fn keys_are_checked() {
        let d = tempfile::tempdir().unwrap();
        let cfg = write_keys(d.path(), true);
        let k = load_keys(&cfg).unwrap();
        assert_eq!(k.kem_keys.len(), 1);

        // Wrong owner.
        let mut other = cfg.clone();
        other.org_id = Some("acme-security".into());
        assert!(load_keys(&other).is_err());

        // Only an older (X-Wing) key: refused.
        let d2 = tempfile::tempdir().unwrap();
        let older = write_keys(d2.path(), false);
        let e = load_keys(&older).err().unwrap().to_string();
        assert!(e.contains("MLKEM1024-P384"), "{e}");

        // An older (hybrid) service grant key: refused.
        let d3 = tempfile::tempdir().unwrap();
        let old_grant =
            write_keys_with_grant(d3.path(), true, SigningKey::generate_hybrid(&mut os_rng()));
        let e = load_keys(&old_grant).err().unwrap().to_string();
        assert!(e.contains("SVX-2"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn readable_secret_keys_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let cfg = write_keys(d.path(), true);
        std::fs::set_permissions(&cfg.kem_keys[0], std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = load_keys(&cfg).err().unwrap().to_string();
        assert!(e.contains("chmod 600"), "{e}");
    }
}
