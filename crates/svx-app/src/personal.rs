//! Personal accounts in the desktop app: sign up with Google or email,
//! backup and restore, send by email, requests, history and per-file rules.
//! Everything forwards to `svx_client::personal`; this module only shapes
//! data for the UI and keeps file names in a local `history.json` (the
//! service never learns them).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};
use svx_client::account::LoginMethod;
use svx_client::defaults::{ServiceTarget, service_target};
use svx_client::personal::{
    self, AccountInfo, Contact, EmailCredentials, KeyChoice, SendOptions, SendResult, SignUpOptions,
};
use svx_protocol::email_account::{CodePurpose, PasswordStrength, password_strength};
use svx_protocol::personal::{
    AccountName, ApprovalRequest, FileRules, FileStatus, ReceivedFile, UpdateFileRequest,
};

use crate::{App, AppError, Result};

/// A sign-in provider to show as a button.
#[derive(Clone, Debug, Serialize)]
pub struct Provider {
    pub name: String,
    pub issuer: String,
}

/// The service a personal account signs up with.
#[derive(Clone, Debug, Serialize)]
pub struct Providers {
    pub service_url: String,
    pub dev: bool,
    pub providers: Vec<Provider>,
}

/// What the email sign-up / sign-in form sends.
#[derive(Clone, Debug, Deserialize)]
pub struct EmailForm {
    pub email: String,
    pub password: String,
    /// Both for a new account; neither to sign in.
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    /// From [`App::request_email_code`] (hex).
    pub challenge: String,
    pub code: String,
}

impl EmailForm {
    fn credentials(self) -> Result<EmailCredentials> {
        let mut challenge = [0u8; 16];
        hex::decode_to_slice(self.challenge.trim(), &mut challenge).map_err(|_| {
            AppError::from(svx_client::ClientError::Invalid(
                "ask for a new code".into(),
            ))
        })?;
        let names = match (self.first_name, self.last_name) {
            (Some(f), Some(l)) => Some((f, l)),
            (None, None) => None,
            _ => {
                return Err(AppError::from(svx_client::ClientError::Invalid(
                    "enter your first and last name".into(),
                )));
            }
        };
        Ok(EmailCredentials {
            email: self.email,
            password: zeroize::Zeroizing::new(self.password),
            names,
            challenge,
            code: self.code,
        })
    }
}

fn purpose(p: &str) -> Result<CodePurpose> {
    Ok(match p {
        "sign_up" => CodePurpose::SignUp,
        "sign_in" => CodePurpose::SignIn,
        "reset_password" => CodePurpose::ResetPassword,
        _ => {
            return Err(AppError::from(svx_client::ClientError::Invalid(
                "unknown code purpose".into(),
            )));
        }
    })
}

/// A code was sent (if the address may receive one).
#[derive(Clone, Debug, Serialize)]
pub struct CodeSent {
    pub challenge: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PersonalSendRequest {
    /// File or folder.
    pub input: PathBuf,
    pub to: Vec<String>,
    pub require_approval: bool,
    pub one_time: bool,
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Recipients can view it in the app but not save it.
    #[serde(default)]
    pub view_only: bool,
    /// For a view-only file: recipients may ask to keep a copy.
    #[serde(default)]
    pub allow_share_requests: bool,
}

/// A request to open one of my files, with the file's local name.
#[derive(Clone, Debug, Serialize)]
pub struct RequestView {
    #[serde(flatten)]
    pub request: ApprovalRequest,
    pub file_name: Option<String>,
}

/// A file I sent, with its local name.
#[derive(Clone, Debug, Serialize)]
pub struct SentView {
    #[serde(flatten)]
    pub file: FileStatus,
    pub file_name: Option<String>,
}

/// A file sent to me, with its local name once opened.
#[derive(Clone, Debug, Serialize)]
pub struct ReceivedView {
    #[serde(flatten)]
    pub file: ReceivedFile,
    pub file_name: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct HistoryView {
    pub sent: Vec<SentView>,
    pub received: Vec<ReceivedView>,
}

/// File names by artifact ID (`history.json`). Names only, never contents
/// or keys; the service never sees them.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct LocalNames {
    names: BTreeMap<String, String>,
}

const MAX_NAMES: usize = 5000;

impl LocalNames {
    pub(crate) fn load(path: &Path) -> LocalNames {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn get(&self, id: &str) -> Option<String> {
        self.names.get(id).cloned()
    }

    pub(crate) fn remember(&mut self, path: &Path, id: &str, name: &str) {
        if self.names.len() >= MAX_NAMES
            && let Some(k) = self.names.keys().next().cloned()
        {
            self.names.remove(&k);
        }
        self.names.insert(id.to_owned(), name.to_owned());
        // A convenience: failing to save it is not an error.
        let _ = save_json(path, self);
    }
}

fn save_json<T: Serialize>(path: &Path, v: &T) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = tempfile::NamedTempFile::new_in(dir)?;
    serde_json::to_writer_pretty(tmp.as_file(), v)?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn display_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl App {
    fn target(&self) -> Result<ServiceTarget> {
        match &self.target {
            Some(t) => Ok(t.clone()),
            None => Ok(service_target()?),
        }
    }

    /// Sign-in providers of the service personal accounts use.
    pub async fn providers(&self) -> Result<Providers> {
        let t = self.target()?;
        let providers = personal::providers(&t)
            .await?
            .into_iter()
            .map(|p| Provider {
                name: p.name,
                issuer: p.issuer,
            })
            .collect();
        Ok(Providers {
            service_url: t.service_url,
            dev: t.dev,
            providers,
        })
    }

    async fn sign_up_with(
        &self,
        issuer: Option<String>,
        keys: KeyChoice,
        login: LoginMethod,
        replace: bool,
    ) -> Result<AccountInfo> {
        let (_, info) = personal::sign_up(
            &self.paths,
            self.secrets.clone(),
            SignUpOptions {
                target: self.target()?,
                issuer,
                keys,
                default_output_dir: None,
                replace,
            },
            login,
        )
        .await?;
        self.reload();
        Ok(info)
    }

    /// Continue with Google: a new account, or this device for an
    /// account that has no keys elsewhere. `reset` replaces the account's
    /// keys (files sent to the old ones can't be opened any more).
    pub async fn sign_up(
        &self,
        issuer: Option<String>,
        reset: bool,
        login: LoginMethod,
        replace: bool,
    ) -> Result<AccountInfo> {
        let keys = if reset {
            KeyChoice::Reset
        } else {
            KeyChoice::New
        };
        self.sign_up_with(issuer, keys, login, replace).await
    }

    /// Sign in on a new device with a backup and its recovery password.
    pub async fn restore(
        &self,
        backup: &Path,
        password: &str,
        issuer: Option<String>,
        login: LoginMethod,
        replace: bool,
    ) -> Result<AccountInfo> {
        let keys = personal::read_backup(backup, password)?;
        self.sign_up_with(issuer, KeyChoice::Restore(Box::new(keys)), login, replace)
            .await
    }

    /// Email a six-digit code for `purpose` (`sign_up`, `sign_in`,
    /// `reset_password`).
    pub async fn request_email_code(&self, email: &str, purpose_name: &str) -> Result<CodeSent> {
        let r =
            personal::request_email_code(&self.target()?, email, purpose(purpose_name)?).await?;
        Ok(CodeSent {
            challenge: hex::encode(r.challenge),
            expires_at: r.expires_at,
        })
    }

    async fn email_with(
        &self,
        form: EmailForm,
        keys: KeyChoice,
        replace: bool,
    ) -> Result<AccountInfo> {
        let (_, info) = personal::sign_up_email(
            &self.paths,
            self.secrets.clone(),
            SignUpOptions {
                target: self.target()?,
                issuer: None,
                keys,
                default_output_dir: None,
                replace,
            },
            form.credentials()?,
        )
        .await?;
        self.reload();
        Ok(info)
    }

    /// Create an email account, or sign in with one on this device.
    /// `reset` replaces the account's keys.
    pub async fn email_sign_up(
        &self,
        form: EmailForm,
        reset: bool,
        replace: bool,
    ) -> Result<AccountInfo> {
        let keys = if reset {
            KeyChoice::Reset
        } else {
            KeyChoice::New
        };
        self.email_with(form, keys, replace).await
    }

    /// Sign in with an email account on a new device, using a backup.
    pub async fn email_restore(
        &self,
        backup: &Path,
        recovery_password: &str,
        form: EmailForm,
        replace: bool,
    ) -> Result<AccountInfo> {
        let keys = personal::read_backup(backup, recovery_password)?;
        self.email_with(form, KeyChoice::Restore(Box::new(keys)), replace)
            .await
    }

    /// Forgot password: set a new one with an emailed code.
    pub async fn reset_password(
        &self,
        email: &str,
        challenge: &str,
        code: &str,
        new_password: &str,
    ) -> Result<()> {
        let mut c = [0u8; 16];
        hex::decode_to_slice(challenge.trim(), &mut c).map_err(|_| {
            AppError::from(svx_client::ClientError::Invalid(
                "ask for a new code".into(),
            ))
        })?;
        personal::reset_password(&self.target()?, email, c, code, new_password).await?;
        Ok(())
    }

    pub async fn change_password(&self, current: &str, new: &str) -> Result<()> {
        Ok(self.client()?.change_password(current, new).await?)
    }

    /// The strength meter: the same check the service enforces.
    pub fn password_strength(&self, password: &str, inputs: &[String]) -> PasswordStrength {
        let inputs: Vec<&str> = inputs.iter().map(String::as_str).collect();
        password_strength(password, &inputs)
    }

    pub fn save_backup(&self, path: &Path, password: &str) -> Result<()> {
        self.client()?.save_backup(path, password)?;
        self.produced.lock().unwrap().insert(path.to_path_buf());
        Ok(())
    }

    pub async fn account(&self) -> Result<AccountInfo> {
        Ok(self.client()?.account().await?)
    }

    /// The account's name; both parts absent when it still needs one.
    pub async fn account_name(&self) -> Result<AccountName> {
        Ok(self.client()?.account_name().await?)
    }

    pub async fn set_account_name(&self, first: &str, last: &str) -> Result<AccountName> {
        Ok(self.client()?.set_account_name(first, last).await?)
    }

    pub async fn lookup(&self, email: &str) -> Result<Contact> {
        Ok(self.client()?.lookup(email).await?)
    }

    pub async fn send_personal(&self, req: PersonalSendRequest) -> Result<SendResult> {
        let c = self.client()?;
        let name = display_name(&req.input);
        let r = c
            .send(SendOptions {
                input: req.input,
                output: None,
                overwrite: false,
                to: req.to,
                rules: FileRules {
                    require_approval: req.require_approval,
                    one_time: req.one_time,
                    expires_at: None,
                    view_only: req.view_only,
                    allow_share_requests: req.allow_share_requests && req.view_only,
                },
                expires_at: req.expires_at,
                name: None,
            })
            .await?;
        self.produced.lock().unwrap().insert(r.path.clone());
        self.names
            .lock()
            .unwrap()
            .remember(&self.names_path(), &r.artifact_id, &name);
        Ok(r)
    }

    /// Requests waiting for my approval.
    pub async fn requests(&self) -> Result<Vec<RequestView>> {
        let list = self.client()?.requests().await?;
        let names = self.names.lock().unwrap();
        Ok(list
            .into_iter()
            .map(|r| RequestView {
                file_name: names.get(&hex::encode(r.artifact_id)),
                request: r,
            })
            .collect())
    }

    pub async fn approve(&self, request_id: &str) -> Result<ApprovalRequest> {
        Ok(self.client()?.approve(request_id).await?)
    }

    pub async fn decline(&self, request_id: &str) -> Result<ApprovalRequest> {
        Ok(self.client()?.decline(request_id).await?)
    }

    pub async fn history(&self) -> Result<HistoryView> {
        let h = self.client()?.history().await?;
        let names = self.names.lock().unwrap();
        Ok(HistoryView {
            sent: h
                .sent
                .into_iter()
                .map(|f| SentView {
                    file_name: names.get(&hex::encode(f.artifact_id)),
                    file: f,
                })
                .collect(),
            received: h
                .received
                .into_iter()
                .map(|f| ReceivedView {
                    file_name: names.get(&hex::encode(f.artifact_id)),
                    file: f,
                })
                .collect(),
        })
    }

    /// One of my sent files.
    pub async fn file(&self, artifact_id: &str) -> Result<SentView> {
        let id = hex_id(artifact_id)?;
        let f = self.client()?.file_status(&id).await?;
        Ok(SentView {
            file_name: self.names.lock().unwrap().get(&id),
            file: f,
        })
    }

    pub async fn update_file(&self, artifact_id: &str, u: UpdateFileRequest) -> Result<SentView> {
        let id = hex_id(artifact_id)?;
        let f = self.client()?.update_file(&id, &u).await?;
        Ok(SentView {
            file_name: self.names.lock().unwrap().get(&id),
            file: f,
        })
    }

    /// Stop waiting for a sender's approval.
    pub fn cancel_open(&self) {
        if let Some(c) = self.cancel.lock().unwrap().as_ref() {
            c.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub(crate) fn new_cancel(&self) -> Arc<AtomicBool> {
        let c = Arc::new(AtomicBool::new(false));
        *self.cancel.lock().unwrap() = Some(c.clone());
        c
    }

    pub(crate) fn remember_received(&self, artifact_id: &str, name: &str) {
        self.names
            .lock()
            .unwrap()
            .remember(&self.names_path(), artifact_id, name);
    }

    pub(crate) fn names_path(&self) -> PathBuf {
        self.paths.config.with_file_name("history.json")
    }

    /// Forget the account on this computer (keys and configuration).
    pub fn sign_out(&self) -> Result<()> {
        self.client()?.sign_out()?;
        self.reload();
        Ok(())
    }
}

/// An artifact ID as 32 hex characters (never a path from the UI).
fn hex_id(s: &str) -> Result<String> {
    let s = s.trim().to_ascii_lowercase();
    if s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s)
    } else {
        Err(AppError::other("invalid file ID"))
    }
}
