//! The command layer of the SVX desktop app.
//!
//! Every operation here is a thin, serializable wrapper over
//! [`svx_client::Client`]. Verification, login binding, key release,
//! decryption and folder extraction all happen inside `svx-client`; this
//! crate only shapes inputs and outputs for a UI, keeps desktop preferences,
//! and remembers which files the app itself produced (the only ones the UI
//! may reveal or open). It has no UI dependency, so it is tested directly.

#![forbid(unsafe_code)]

mod error;
pub mod prefs;

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};
use svx_client::account::{LoginMethod, WhoAmI};
use svx_client::config::{Paths, default_open_dir};
use svx_client::login::Opener;
use svx_client::setup::{self, SetupPreview, SetupRequest};
use svx_client::{Client, ClientConfig, ClientError, Output, PackOptions, PackResult, Step};
use svx_protocol::Policy;
use svx_protocol::admin::AuditPage;

pub use error::{AppError, Result};
pub use prefs::Prefs;

/// Setup form fields (also what "Import config file…" fills in).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupForm {
    pub service_url: String,
    pub registry_key: String,
    pub org_id: String,
    pub idp_client_id: String,
    #[serde(default)]
    pub dev: bool,
    #[serde(default)]
    pub default_output_dir: Option<PathBuf>,
}

impl From<SetupForm> for SetupRequest {
    fn from(f: SetupForm) -> Self {
        SetupRequest {
            service_url: f.service_url.trim().to_owned(),
            registry_key: f.registry_key.trim().to_owned(),
            org_id: f.org_id.trim().to_owned(),
            idp_client_id: f.idp_client_id.trim().to_owned(),
            dev: f.dev,
            default_output_dir: f.default_output_dir,
        }
    }
}

/// What the app shows on start.
#[derive(Clone, Debug, Serialize)]
pub struct AppState {
    pub configured: bool,
    pub config_path: PathBuf,
    /// Why an existing configuration could not be loaded.
    pub config_error: Option<String>,
    pub org_id: Option<String>,
    pub service_url: Option<String>,
    pub idp_issuer: Option<String>,
    pub dev: bool,
    pub output_dir: Option<PathBuf>,
    pub prefs: Prefs,
}

/// A verified artifact, before any login.
#[derive(Clone, Debug, Serialize)]
pub struct StatusView {
    pub artifact_id: String,
    pub sender_org: String,
    pub recipient_org: String,
    pub my_org: String,
    pub for_you: bool,
    pub expired: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub policy: String,
    pub service_id: String,
    /// Human-readable protection level of the file's suite.
    pub protection: String,
    /// Whether the file resists quantum attacks (suite SVX-1H).
    pub post_quantum: bool,
}

/// One progress event of [`App::open`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Progress {
    /// [`Step::name`].
    pub step: &'static str,
    /// 1-based position in the 7-step timeline.
    pub index: u8,
    pub sender: Option<String>,
}

impl From<&Step> for Progress {
    fn from(s: &Step) -> Self {
        let index = match s {
            Step::Verifying => 1,
            Step::SignatureValid { .. } => 2,
            Step::Connecting => 3,
            Step::Authenticating => 4,
            Step::CheckingAuthorization => 5,
            Step::AccessApproved => 6,
            Step::Decrypting => 7,
        };
        Progress {
            step: s.name(),
            index,
            sender: match s {
                Step::SignatureValid { sender } => Some(sender.clone()),
                _ => None,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenResult {
    pub path: PathBuf,
    /// File or folder name.
    pub name: String,
    pub is_folder: bool,
    pub size: u64,
    pub sender_org: String,
    pub artifact_id: String,
    pub classification: Option<String>,
    pub description: Option<String>,
    /// Whether the UI may offer "Open" (a document type that does not run
    /// code); otherwise only "Show in folder".
    pub can_open: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SendRequest {
    /// File or folder.
    pub input: PathBuf,
    #[serde(default)]
    pub output: Option<PathBuf>,
    pub recipient: String,
    pub policy: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub classification: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub signing_key: PathBuf,
    #[serde(default)]
    pub register: bool,
}

/// A recipient organization from its verified registry record.
#[derive(Clone, Debug, Serialize)]
pub struct Recipient {
    pub org_id: String,
    pub display_name: String,
    pub domain: String,
    /// Has a key agent and an active encryption key.
    pub can_receive: bool,
}

/// The app: configuration paths, the loaded client and preferences.
pub struct App {
    paths: Paths,
    client: RwLock<Option<Arc<Client>>>,
    config_error: RwLock<Option<String>>,
    prefs: Mutex<Prefs>,
    /// Files and folders this app wrote (opened outputs, packed artifacts).
    produced: Mutex<HashSet<PathBuf>>,
}

impl App {
    /// `config`: explicit config path, else `$SVX_CONFIG`, else the platform
    /// default (shared with the `svx` CLI).
    pub fn new(config: Option<&Path>) -> Result<App> {
        let paths = Paths::resolve(config)?;
        let prefs = Prefs::load(&prefs_path(&paths));
        let app = App {
            paths,
            client: RwLock::new(None),
            config_error: RwLock::new(None),
            prefs: Mutex::new(prefs),
            produced: Mutex::new(HashSet::new()),
        };
        app.reload();
        Ok(app)
    }

    /// (Re)load the configuration from disk.
    pub fn reload(&self) {
        let (client, err) = if self.paths.config.exists() {
            match ClientConfig::load(&self.paths.config)
                .and_then(|cfg| Client::with_config(self.paths.clone(), cfg))
            {
                Ok(c) => (Some(Arc::new(c)), None),
                Err(e) => (None, Some(e.to_string())),
            }
        } else {
            (None, None)
        };
        *self.client.write().unwrap() = client;
        *self.config_error.write().unwrap() = err;
    }

    fn client(&self) -> Result<Arc<Client>> {
        self.client
            .read()
            .unwrap()
            .clone()
            .ok_or_else(AppError::not_configured)
    }

    pub fn state(&self) -> AppState {
        let client = self.client.read().unwrap().clone();
        let cfg = client.as_ref().map(|c| &c.cfg);
        AppState {
            configured: client.is_some(),
            config_path: self.paths.config.clone(),
            config_error: self.config_error.read().unwrap().clone(),
            org_id: cfg.map(|c| c.org_id.clone()),
            service_url: cfg.map(|c| c.service_url.clone()),
            idp_issuer: cfg.map(|c| c.idp_issuer.clone()),
            dev: cfg.is_some_and(|c| c.dev),
            output_dir: cfg.and_then(|c| configured_output_dir(c).ok()),
            prefs: self.prefs.lock().unwrap().clone(),
        }
    }

    // ----- Setup -----

    /// Verify the service and organization against the pinned key.
    pub async fn setup_verify(&self, form: SetupForm) -> Result<SetupPreview> {
        Ok(setup::verify(form.into()).await?)
    }

    /// Verify again (never trust a preview round-tripped through the UI),
    /// save, and load the new configuration.
    pub async fn setup_save(&self, form: SetupForm, replace: bool) -> Result<SetupPreview> {
        let p = setup::verify(form.into()).await?;
        setup::write(&self.paths, &p.config, replace)?;
        self.reload();
        Ok(p)
    }

    /// Read an existing `config.toml` into the setup form (it is verified
    /// when the user saves it).
    pub fn read_config_file(&self, path: &Path) -> Result<SetupForm> {
        let c = ClientConfig::load(path)?;
        Ok(SetupForm {
            service_url: c.service_url,
            registry_key: c.registry_key,
            org_id: c.org_id,
            idp_client_id: c.idp_client_id,
            dev: c.dev,
            default_output_dir: c.default_output_dir,
        })
    }

    /// How to sign in: the system browser, or a dev user (dev configs only;
    /// `svx-client` refuses it otherwise).
    pub fn login_method(dev_user: Option<String>, opener: Opener) -> LoginMethod {
        match dev_user.filter(|u| !u.trim().is_empty()) {
            Some(u) => LoginMethod::Dev(u.trim().to_owned()),
            None => LoginMethod::Browser(opener),
        }
    }

    // ----- Open -----

    /// Verify against the registry; no login.
    pub async fn status(&self, path: &Path) -> Result<StatusView> {
        let c = self.client()?;
        let s = c.status(path).await?;
        Ok(StatusView {
            artifact_id: s.info.artifact_id,
            sender_org: s.info.sender_org,
            recipient_org: s.info.recipient_org,
            my_org: c.cfg.org_id.clone(),
            for_you: s.for_you,
            expired: s.expired,
            created_at: s.info.created_at,
            expires_at: s.info.expires_at,
            policy: s.info.policy_ref,
            service_id: s.info.service_id,
            protection: s.info.protection,
            post_quantum: s.info.post_quantum,
        })
    }

    /// The full fail-closed open flow. `output_dir` overrides the configured
    /// folder (e.g. after `output_exists`).
    pub async fn open(
        &self,
        path: &Path,
        output_dir: Option<PathBuf>,
        login: LoginMethod,
        progress: &mut (dyn FnMut(Progress) + Send),
    ) -> Result<OpenResult> {
        let c = self.client()?;
        let dir = match output_dir {
            Some(d) => d,
            None => configured_output_dir(&c.cfg)?,
        };
        let mut on_step = |s: Step| progress(Progress::from(&s));
        let o = c
            .open(
                path,
                Some(Output::Dir {
                    dir,
                    overwrite: false,
                }),
                login,
                &mut on_step,
            )
            .await?;
        let out = o
            .path
            .clone()
            .ok_or_else(|| AppError::other("no output path"))?;
        let is_folder = o.is_folder();
        self.produced.lock().unwrap().insert(out.clone());
        Ok(OpenResult {
            name: out
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            can_open: !is_folder && is_document(&out),
            is_folder,
            size: o.manifest.total_size(),
            sender_org: o.sender_org,
            artifact_id: o.artifact_id,
            classification: o.manifest.classification,
            description: o.manifest.description,
            path: out,
        })
    }

    // ----- Send -----

    pub async fn recipient(&self, org: &str) -> Result<Recipient> {
        let c = self.client()?;
        let rec = c.org_record(org.trim()).await?;
        let can_receive = rec.key_agent_url.is_some()
            && svx_client::registry::active_hybrid_kem_key(&rec).is_ok();
        Ok(Recipient {
            org_id: rec.org_id,
            display_name: rec.display_name,
            domain: rec.domain,
            can_receive,
        })
    }

    pub async fn send(&self, req: SendRequest) -> Result<PackResult> {
        let c = self.client()?;
        let opt = |s: Option<String>| s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
        let r = c
            .pack(PackOptions {
                input: req.input,
                output: req.output,
                overwrite: false,
                signing_key: req.signing_key.clone(),
                recipient: req.recipient.trim().to_owned(),
                policy: req.policy.trim().to_owned(),
                expires_at: req.expires_at,
                classification: opt(req.classification),
                description: opt(req.description),
                name: None,
                register: req.register,
            })
            .await?;
        self.produced.lock().unwrap().insert(r.path.clone());
        let mut prefs = self.prefs.lock().unwrap();
        prefs.used(&r.recipient_org, &req.signing_key, &r.policy);
        // Preferences are a convenience: failing to save them is not an error.
        let _ = prefs.save(&prefs_path(&self.paths));
        Ok(r)
    }

    // ----- Account and administration -----

    pub async fn login(&self, login: LoginMethod) -> Result<WhoAmI> {
        Ok(self.client()?.login(login).await?)
    }

    pub fn logout(&self) -> Result<bool> {
        Ok(self.client()?.logout()?)
    }

    /// `None` when not signed in.
    pub async fn whoami(&self) -> Result<Option<WhoAmI>> {
        match self.client()?.whoami().await {
            Ok(w) => Ok(Some(w)),
            Err(ClientError::NotLoggedIn) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Revoke by artifact ID (hex) or `.svx` path; returns the hex ID.
    pub async fn revoke(&self, target: &str) -> Result<String> {
        Ok(self.client()?.revoke(target.trim()).await?)
    }

    pub async fn audit(&self, limit: u32) -> Result<AuditPage> {
        Ok(self.client()?.audit(limit.clamp(1, 1000)).await?)
    }

    pub async fn policies(&self) -> Result<BTreeMap<String, Policy>> {
        Ok(self.client()?.policies().await?)
    }

    // ----- Files the UI may act on -----

    /// `path` if this app produced it in this session. The UI can only ask
    /// to reveal or open such paths, never arbitrary ones.
    pub fn produced(&self, path: &Path) -> Result<PathBuf> {
        if self.produced.lock().unwrap().contains(path) {
            Ok(path.to_path_buf())
        } else {
            Err(AppError::other("not a file produced by this app"))
        }
    }

    /// Like [`App::produced`], and also a document type that is safe to hand
    /// to the system's default app.
    pub fn openable(&self, path: &Path) -> Result<PathBuf> {
        let p = self.produced(path)?;
        if p.is_file() && is_document(&p) {
            Ok(p)
        } else {
            Err(AppError::other(
                "this kind of file is only shown in its folder, not opened",
            ))
        }
    }
}

fn prefs_path(paths: &Paths) -> PathBuf {
    paths.config.with_file_name("desktop.json")
}

fn configured_output_dir(cfg: &ClientConfig) -> Result<PathBuf> {
    Ok(match &cfg.default_output_dir {
        Some(d) => d.clone(),
        None => default_open_dir()?,
    })
}

/// Document types the app may open with the system default app. Anything
/// that can run code (executables, scripts, installers, app bundles,
/// shortcuts, HTML, macro-enabled Office files) is only shown in its folder.
pub fn is_document(path: &Path) -> bool {
    const DOCS: &[&str] = &[
        "pdf", "txt", "md", "csv", "tsv", "log", "json", "xml", "yaml", "yml", "rtf", "png", "jpg",
        "jpeg", "gif", "webp", "heic", "tif", "tiff", "bmp", "docx", "xlsx", "pptx", "odt", "ods",
        "odp", "pages", "numbers", "key", "mp3", "m4a", "wav", "mp4", "mov", "zip",
    ];
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .is_some_and(|e| DOCS.contains(&e.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_follows_the_timeline() {
        let steps = [
            Step::Verifying,
            Step::SignatureValid {
                sender: "acme-security".into(),
            },
            Step::Connecting,
            Step::Authenticating,
            Step::CheckingAuthorization,
            Step::AccessApproved,
            Step::Decrypting,
        ];
        let p: Vec<Progress> = steps.iter().map(Progress::from).collect();
        assert_eq!(
            p.iter().map(|p| p.index).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(p[1].step, "signature_valid");
        assert_eq!(p[1].sender.as_deref(), Some("acme-security"));
        assert_eq!(p[0].sender, None);
    }

    #[test]
    fn errors_keep_their_kind_and_reason() {
        let e = AppError::from(ClientError::Denied(
            svx_protocol::DenyReason::ExpiredOrRevoked,
        ));
        assert_eq!(e.kind, "denied");
        assert_eq!(e.deny_reason.as_deref(), Some("expired_or_revoked"));
        assert_eq!(e.exit_code, 1);
        let e = AppError::from(ClientError::OutputExists("/x/report.txt".into()));
        assert_eq!(e.kind, "output_exists");
        assert_eq!(e.path, Some(PathBuf::from("/x/report.txt")));
        let e = AppError::from(ClientError::Unavailable("down".into()));
        assert_eq!((e.kind.as_str(), e.exit_code), ("unavailable", 3));
        let e = AppError::from(ClientError::NotRecipient {
            recipient: "a".into(),
            mine: "b".into(),
        });
        assert_eq!(e.kind, "not_recipient");
    }

    #[test]
    fn only_documents_are_openable() {
        for ok in ["a.pdf", "b.TXT", "c.docx", "d.tar.zip"] {
            assert!(is_document(Path::new(ok)), "{ok}");
        }
        for bad in [
            "a.exe",
            "b.app",
            "c.command",
            "d.sh",
            "e.bat",
            "f.ps1",
            "g.html",
            "h.docm",
            "i.lnk",
            "j.desktop",
            "k.jar",
            "l.dmg",
            "m.pkg",
            "n.msi",
            "noext",
            ".pdf",
        ] {
            assert!(!is_document(Path::new(bad)), "{bad}");
        }
    }

    #[test]
    fn unconfigured_app_reports_not_configured() {
        let d = tempfile::tempdir().unwrap();
        let app = App::new(Some(&d.path().join("config.toml"))).unwrap();
        let s = app.state();
        assert!(!s.configured);
        assert!(s.config_error.is_none());
        let e = app.logout().unwrap_err();
        assert_eq!(e.kind, "not_configured");
    }

    #[test]
    fn broken_config_is_reported_not_fatal() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.toml");
        std::fs::write(&p, "service_url = 1").unwrap();
        let app = App::new(Some(&p)).unwrap();
        assert!(!app.state().configured);
        assert!(app.state().config_error.is_some());
    }

    #[test]
    fn unknown_paths_cannot_be_revealed() {
        let d = tempfile::tempdir().unwrap();
        let app = App::new(Some(&d.path().join("config.toml"))).unwrap();
        assert!(app.produced(Path::new("/etc/passwd")).is_err());
        assert!(app.openable(Path::new("/bin/sh")).is_err());
    }

    #[test]
    fn dev_login_only_with_a_user() {
        let o = svx_client::login::print_url();
        assert!(matches!(
            App::login_method(Some(" alice ".into()), o.clone()),
            LoginMethod::Dev(u) if u == "alice"
        ));
        assert!(matches!(
            App::login_method(Some("  ".into()), o.clone()),
            LoginMethod::Browser(_)
        ));
        assert!(matches!(
            App::login_method(None, o),
            LoginMethod::Browser(_)
        ));
    }
}
