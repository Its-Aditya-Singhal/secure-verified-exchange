//! [`Client`]: one object bundling configuration, session cache and HTTP
//! client, with one method per user-facing operation. The language SDKs
//! bind this type so they share exactly the CLI's behavior.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use svx_core::format::Identifier;
use svx_core::keyfile;
use svx_protocol::admin::AuditPage;
use svx_protocol::{ManagedClient, OrgRecord, Policy};

use crate::account::{self, LoginMethod, WhoAmI};
use crate::config::{ClientConfig, Paths, default_open_dir};
use crate::error::{ClientError, Result};
use crate::open::{OpenOutcome, Output, Step};
use crate::pack::ManagedPack;
use crate::registry::Registry;
use crate::{admin, info, session};

pub struct Client {
    pub paths: Paths,
    pub cfg: ClientConfig,
    pub http: ManagedClient,
}

/// Options for [`Client::pack`].
pub struct PackOptions {
    pub input: PathBuf,
    /// Default: `input` with the extension `.svx`.
    pub output: Option<PathBuf>,
    pub overwrite: bool,
    /// `*.sign.key` file of the sending organization.
    pub signing_key: PathBuf,
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
        Ok(Client { paths, cfg, http })
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
        let (sender_org, signing_key) = keyfile::load_signing_key(&o.signing_key)
            .map_err(|e| ClientError::Config(format!("loading signing key: {e}")))?;
        let name = match o.name {
            Some(n) => n,
            None => o
                .input
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| ClientError::Config("input has no usable file name".into()))?
                .to_owned(),
        };
        let output = o.output.unwrap_or_else(|| o.input.with_extension("svx"));
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
                input: &o.input,
                output,
                overwrite: o.overwrite,
                signing_key: &signing_key,
                sender_org: sender_org.clone(),
                recipient_org,
                policy,
                expires_at: o.expires_at,
                classification: o.classification,
                description: o.description,
                name,
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

    /// The registry record of `org`, verified with the pinned key.
    pub async fn org_record(&self, org: &str) -> Result<OrgRecord> {
        Registry::new(&self.cfg, &self.http)?.org(org).await
    }
}
