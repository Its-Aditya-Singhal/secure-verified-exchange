//! [`Client`]: one object bundling configuration, session cache and HTTP
//! client, with one method per user-facing operation. The language SDKs
//! bind this type so they share exactly the CLI's behavior.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use svx_core::format::Identifier;
use svx_protocol::admin::{AuditPage, OrgOverview, UpdateOrgRequest};
use svx_protocol::{AgentKeys, KeyEntry, KeyStatus, ManagedClient, OrgRecord, Policy};

use crate::account::{self, LoginMethod, WhoAmI};
use crate::config::{ClientConfig, Paths, default_open_dir};
use crate::error::{ClientError, Result};
use crate::keystore::{KeyRef, SecretStore};
use crate::open::{OpenOutcome, Output, Step};
use crate::pack::ManagedPack;
use crate::registry::Registry;
use crate::{admin, info, keyadmin, session};

pub struct Client {
    pub paths: Paths,
    pub cfg: ClientConfig,
    pub http: ManagedClient,
    /// Where keychain signing keys live (the OS keychain by default).
    pub secrets: Arc<dyn SecretStore>,
}

/// Options for [`Client::pack`].
pub struct PackOptions {
    /// A file, or a folder (zipped, and extracted again on open).
    pub input: PathBuf,
    /// Default: `input` with the extension `.svx` (`<folder>.svx` for a folder).
    pub output: Option<PathBuf>,
    pub overwrite: bool,
    /// The sending organization's signing key: a `*.sign.key` file or a
    /// keychain key.
    pub signing_key: KeyRef,
    pub recipient: String,
    pub policy: String,
    pub expires_at: Option<i64>,
    pub classification: Option<String>,
    pub description: Option<String>,
    /// File name recorded in the encrypted manifest (default: input's name).
    pub name: Option<String>,
    /// Register with the service using the cached admin session.
    pub register: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackResult {
    pub path: PathBuf,
    pub artifact_id: String,
    pub sender_org: String,
    pub recipient_org: String,
    pub service_id: String,
    pub policy: String,
    pub expires_at: Option<i64>,
    pub signing_key_id: String,
    pub registered: bool,
    /// Human-readable protection level (always post-quantum hybrid for new files).
    pub protection: String,
}

impl Client {
    /// Load the configuration from `config`, `$SVX_CONFIG` or the platform
    /// default, like the CLI.
    pub fn load(config: Option<&Path>) -> Result<Client> {
        let paths = Paths::resolve(config)?;
        let cfg = ClientConfig::load(&paths.config)?;
        Client::with_config(paths, cfg)
    }

    pub fn with_config(paths: Paths, cfg: ClientConfig) -> Result<Client> {
        cfg.validate()?;
        let http = ManagedClient::new(cfg.dev)?;
        Ok(Client {
            paths,
            cfg,
            http,
            secrets: crate::keystore::os_keychain(),
        })
    }

    /// Use another secret store for keychain keys (tests).
    pub fn with_secret_store(mut self, secrets: Arc<dyn SecretStore>) -> Self {
        self.secrets = secrets;
        self
    }

    pub async fn status(&self, path: &Path) -> Result<info::Status> {
        info::status(&self.cfg, &self.http, path).await
    }

    /// Open into `output_dir` (default: configured or `~/SVX`), or into a
    /// writer. Always performs a fresh login bound to this open.
    pub async fn open(
        &self,
        path: &Path,
        output: Option<Output>,
        login: LoginMethod,
        progress: &mut (dyn FnMut(Step) + Send),
    ) -> Result<OpenOutcome> {
        if self.cfg.is_personal() {
            // Personal accounts authenticate with the device key instead.
            let never = std::sync::atomic::AtomicBool::new(false);
            return self.open_personal(path, output, progress, &never).await;
        }
        let output = match output {
            Some(o) => o,
            None => Output::Dir {
                dir: match &self.cfg.default_output_dir {
                    Some(d) => d.clone(),
                    None => default_open_dir()?,
                },
                overwrite: false,
            },
        };
        let auth = account::authenticator(&self.cfg, &self.http, login)?;
        crate::open(&self.cfg, &self.http, auth.as_ref(), path, output, progress).await
    }

    pub async fn pack(&self, o: PackOptions) -> Result<PackResult> {
        let (sender_org, signing_key) =
            crate::keystore::load_signing(self.secrets.as_ref(), &o.signing_key)?;
        let input = crate::pack::prepare_input(&o.input, o.name)?;
        let output = o.output.unwrap_or_else(|| input.default_output.clone());
        let id = |s: &str, what: &str| {
            Identifier::new(s).map_err(|_| ClientError::Config(format!("invalid {what} {s:?}")))
        };
        let recipient_org = id(&o.recipient, "recipient")?;
        let policy = id(&o.policy, "policy")?;
        if o.expires_at.is_some_and(|t| t <= crate::now()) {
            return Err(ClientError::Config("expiry is in the past".into()));
        }
        let packed = crate::pack::pack(
            &self.cfg,
            &self.http,
            ManagedPack {
                input: &input.path,
                output,
                overwrite: o.overwrite,
                signing_key: &signing_key,
                sender_org: sender_org.clone(),
                recipient_org,
                policy,
                expires_at: o.expires_at,
                classification: o.classification,
                description: o.description,
                name: input.name.clone(),
                content_type: input.content_type.clone(),
                chunk_size: None,
            },
        )
        .await?;
        if o.register {
            let bearer = account::bearer(&self.paths.session)?;
            crate::pack::register(&self.cfg, &self.http, &packed.path, &bearer).await?;
        }
        Ok(PackResult {
            path: packed.path,
            artifact_id: hex::encode(packed.summary.artifact_id),
            sender_org: sender_org.to_string(),
            recipient_org: o.recipient,
            service_id: packed.service_id,
            policy: o.policy,
            expires_at: o.expires_at,
            signing_key_id: hex::encode(signing_key.verifying_key().key_id()),
            registered: o.register,
            protection: packed.summary.suite.description().into(),
        })
    }

    /// Sign in for administration and cache the session.
    pub async fn login(&self, login: LoginMethod) -> Result<WhoAmI> {
        let auth = account::authenticator(&self.cfg, &self.http, login)?;
        account::login(&self.cfg, auth.as_ref(), &self.paths.session).await
    }

    /// Delete the cached session; `false` if there was none.
    pub fn logout(&self) -> Result<bool> {
        session::clear(&self.paths.session)
    }

    pub async fn whoami(&self) -> Result<WhoAmI> {
        account::whoami(&self.cfg, &self.paths.session).await
    }

    /// Revoke by artifact ID (hex) or artifact file; returns the hex ID.
    pub async fn revoke(&self, target: &str) -> Result<String> {
        let id = info::artifact_id_of(target)?;
        let bearer = account::bearer(&self.paths.session)?;
        admin::revoke(&self.cfg, &self.http, &bearer, &id).await?;
        Ok(hex::encode(id))
    }

    pub async fn policies(&self) -> Result<BTreeMap<String, Policy>> {
        let bearer = account::bearer(&self.paths.session)?;
        admin::list_policies(&self.cfg, &self.http, &bearer).await
    }

    pub async fn set_policy(&self, name: &str, policy: &Policy) -> Result<Policy> {
        policy
            .validate()
            .map_err(|e| ClientError::Config(format!("invalid policy: {e}")))?;
        let bearer = account::bearer(&self.paths.session)?;
        admin::set_policy(&self.cfg, &self.http, &bearer, name, policy).await
    }

    pub async fn audit(&self, limit: u32) -> Result<AuditPage> {
        let bearer = account::bearer(&self.paths.session)?;
        admin::audit(&self.cfg, &self.http, &bearer, limit).await
    }

    pub async fn audit_page(&self, q: &admin::AuditQuery) -> Result<AuditPage> {
        let bearer = account::bearer(&self.paths.session)?;
        admin::audit_page(&self.cfg, &self.http, &bearer, q).await
    }

    /// Settings, administrators and keys of this organization. Admin.
    pub async fn org_overview(&self) -> Result<OrgOverview> {
        let bearer = account::bearer(&self.paths.session)?;
        admin::overview(&self.cfg, &self.http, &bearer).await
    }

    pub async fn update_org(&self, req: &UpdateOrgRequest) -> Result<()> {
        let bearer = account::bearer(&self.paths.session)?;
        admin::update_org(&self.cfg, &self.http, &bearer, req).await
    }

    pub async fn add_admin(&self, subject: &str) -> Result<()> {
        let subject = subject.trim();
        if subject.is_empty() {
            return Err(ClientError::Config("enter the person's user ID".into()));
        }
        let bearer = account::bearer(&self.paths.session)?;
        admin::add_admin(&self.cfg, &self.http, &bearer, subject).await
    }

    pub async fn remove_admin(&self, subject: &str) -> Result<()> {
        let bearer = account::bearer(&self.paths.session)?;
        admin::remove_admin(&self.cfg, &self.http, &bearer, subject).await
    }

    pub async fn delete_policy(&self, name: &str) -> Result<()> {
        let bearer = account::bearer(&self.paths.session)?;
        admin::delete_policy(&self.cfg, &self.http, &bearer, name).await
    }

    /// Create this computer's signing key in the keychain and register it.
    pub async fn create_signing_key(&self) -> Result<keyadmin::NewSigningKey> {
        let bearer = account::bearer(&self.paths.session)?;
        keyadmin::create_signing_key(&self.cfg, &self.http, &bearer, self.secrets.as_ref()).await
    }

    pub async fn register_signing_public(&self, path: &Path) -> Result<KeyEntry> {
        let bearer = account::bearer(&self.paths.session)?;
        keyadmin::register_signing_public(&self.cfg, &self.http, &bearer, path).await
    }

    pub fn export_encryption_key(&self, dir: &Path) -> Result<keyadmin::ExportedKemKey> {
        keyadmin::export_encryption_key(&self.cfg, dir)
    }

    pub async fn activate_encryption_key(&self, public_file: &Path) -> Result<KeyEntry> {
        let bearer = account::bearer(&self.paths.session)?;
        keyadmin::activate_encryption_key(&self.cfg, &self.http, &bearer, public_file).await
    }

    pub async fn set_key_status(&self, key_id: &str, status: KeyStatus) -> Result<KeyEntry> {
        let bearer = account::bearer(&self.paths.session)?;
        keyadmin::set_key_status(&self.cfg, &self.http, &bearer, key_id, status).await
    }

    pub fn import_signing_key(&self, path: &Path) -> Result<keyadmin::NewSigningKey> {
        keyadmin::import_signing_key(&self.cfg, self.secrets.as_ref(), path)
    }

    /// The keys the organization's key agent holds (public; no login).
    pub async fn agent_keys(&self, agent_url: &str) -> Result<AgentKeys> {
        admin::agent_keys(&self.http, agent_url).await
    }

    /// The registry record of `org`, verified with the pinned key.
    pub async fn org_record(&self, org: &str) -> Result<OrgRecord> {
        Registry::new(&self.cfg, &self.http)?.org(org).await
    }
}
