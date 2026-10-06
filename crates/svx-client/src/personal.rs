//! Personal accounts: sign up with Google or an email address, keys in the keychain
//! with one password-protected backup, send to email addresses, open with
//! the sender's live approval, and manage sent files afterwards.
//!
//! After sign-up, every request to the service is signed with the device's
//! SVX-2 key, so opening a file never needs a browser.

use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use svx_core::crypto::{
    BackupParams, KemSecretKey, KeyKind, SigningKey, Suite, open_with_password, os_rng,
    seal_with_password,
};
use svx_core::format::{EnvelopeRole, Identifier};
use svx_core::{Manifest, PackRequest, unwrap_envelope};
use svx_protocol::email_account::{
    ChangePasswordRequest, CodePurpose, EMAIL_ISSUER, EMAIL_PROVIDER_NAME, EmailAccountRequest,
    EmailCodeRequest, EmailCodeResponse, KeyMode, PasswordResetRequest, password_strength,
    valid_name,
};
use svx_protocol::personal::{
    Account, AccountName, ApprovalRequest, FileRules, FileStatus, History, OpenedReceipt,
    PersonalIdp, PersonalReleaseResponse, RegisterFileRequest, ReleaseMode, SetNameRequest,
    ShareStatus, SignUpRequest, UpdateFileRequest, signup_nonce,
};
use svx_protocol::{KeyKindWire, KeyStatus, ManagedClient, Method, OrgRecord, ReleaseSession};
use zeroize::Zeroizing;

use crate::account::{LOGIN_TIMEOUT, LoginMethod};
use crate::client::Client;
use crate::config::{AccountConfig, ClientConfig, Paths, default_open_dir};
use crate::defaults::ServiceTarget;
use crate::error::{ClientError, Result};
use crate::keystore::{self, KeyRef, SecretStore};
use crate::login::{Authenticator, BrowserLogin, DevLogin};
use crate::open::{OpenOutcome, Output, Step, write_output};
use crate::presence::Need;
use crate::registry::{Registry, active_kem_key};

/// How often to ask again while waiting for the sender's approval.
pub const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// Shortest recovery password accepted for a backup.
pub const MIN_PASSWORD_LEN: usize = 10;
/// At most this many recipients per file.
pub const MAX_RECIPIENTS: usize = svx_core::format::limits::MAX_RECIPIENTS;

/// A released personal file: verified, with both halves of its key.
pub(crate) struct Released {
    pub verified: svx_core::VerifiedArtifact,
    pub svc_share: svx_core::crypto::Share,
    pub recipient_share: svx_core::crypto::Share,
    pub session: ReleaseSession,
    /// The sender, as shown in the app.
    pub sender: String,
}

/// A reader that keeps `T` (a temporary file) alive while it is read.
struct Keep<R, T>(R, T);

impl<R: Read, T> Read for Keep<R, T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

/// The two private keys of a device.
pub struct DeviceKeys {
    pub signing: SigningKey,
    pub kem: KemSecretKey,
    /// From a backup: the account and email it was made for.
    pub account: Option<String>,
    pub email: Option<String>,
}

impl DeviceKeys {
    pub fn generate() -> DeviceKeys {
        let mut rng = os_rng();
        DeviceKeys {
            signing: SigningKey::generate_max(&mut rng),
            kem: KemSecretKey::generate_max(&mut rng),
            account: None,
            email: None,
        }
    }
}

/// Which keys a sign-up registers.
pub enum KeyChoice {
    /// New keys (a new account, or the first device).
    New,
    /// Keys from a backup (a new device for an existing account).
    Restore(Box<DeviceKeys>),
    /// New keys replacing the account's old ones. Files sent to the old
    /// keys can no longer be opened.
    Reset,
}

pub struct SignUpOptions {
    pub target: ServiceTarget,
    /// The provider's issuer (from [`providers`]); `None` = the first one.
    pub issuer: Option<String>,
    pub keys: KeyChoice,
    pub default_output_dir: Option<PathBuf>,
    /// Replace an existing configuration.
    pub replace: bool,
}

/// The signed-in account, safe to show.
#[derive(Clone, Debug, Serialize)]
pub struct AccountInfo {
    pub account: String,
    pub email: String,
    pub provider: String,
    pub issuer: String,
    pub created_at: Option<i64>,
    pub signing_key_id: String,
    pub kem_key_id: String,
    /// The account's public encryption key (hex), to share if asked.
    pub kem_public: String,
}

/// A person found in the directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Contact {
    pub account: String,
    pub email: String,
}

pub struct SendOptions {
    /// A file, or a folder (zipped, and extracted again on open).
    pub input: PathBuf,
    /// Default: `input` with the extension `.svx`.
    pub output: Option<PathBuf>,
    pub overwrite: bool,
    /// Recipients' email addresses.
    pub to: Vec<String>,
    pub rules: FileRules,
    /// Signed into the file; the service-side expiry can only be earlier.
    pub expires_at: Option<i64>,
    /// File name recorded in the encrypted manifest (default: input's name).
    pub name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SendResult {
    pub path: PathBuf,
    pub artifact_id: String,
    pub recipients: Vec<Contact>,
    pub rules: FileRules,
    pub expires_at: Option<i64>,
    pub protection: String,
}

/// The sign-in providers the service offers, checked with the pinned key.
pub async fn providers(target: &ServiceTarget) -> Result<Vec<PersonalIdp>> {
    let http = ManagedClient::new(target.dev)?;
    let key =
        crate::setup::registry_key(&http, &target.service_url, &target.registry_key, target.dev)
            .await?;
    let mut idps = http
        .service_record(&target.service_url, &key)
        .await?
        .personal_idps;
    for p in &mut idps {
        // Not secret, but nothing for a UI to show.
        p.client_secret = None;
    }
    Ok(idps)
}

fn authenticator(
    http: &ManagedClient,
    idp: &PersonalIdp,
    dev: bool,
    login: LoginMethod,
) -> Result<Box<dyn Authenticator>> {
    Ok(match login {
        LoginMethod::Dev(user) => {
            if !dev {
                return Err(ClientError::Config(
                    "dev sign-in is only available with a development service".into(),
                ));
            }
            Box::new(DevLogin {
                client: http.clone(),
                issuer: idp.issuer.clone(),
                client_id: idp.client_id.clone(),
                user,
            })
        }
        LoginMethod::Browser(opener) => Box::new(BrowserLogin {
            client: http.clone(),
            issuer: idp.issuer.clone(),
            client_id: idp.client_id.clone(),
            client_secret: idp.client_secret.clone(),
            opener,
            timeout: LOGIN_TIMEOUT,
        }),
    })
}

/// Sign up (or sign in on a new device) with Google or an email address, register the
/// device keys, keep them in the keychain and save the configuration.
pub async fn sign_up(
    paths: &Paths,
    secrets: Arc<dyn SecretStore>,
    opts: SignUpOptions,
    login: LoginMethod,
) -> Result<(Client, AccountInfo)> {
    if paths.config.exists() && !opts.replace {
        return Err(ClientError::Config(format!(
            "{} exists; sign out first",
            paths.config.display()
        )));
    }
    let t = &opts.target;
    let http = ManagedClient::new(t.dev)?;
    let registry =
        crate::setup::registry_key(&http, &t.service_url, &t.registry_key, t.dev).await?;
    let service = http.service_record(&t.service_url, &registry).await?;
    let idp = match &opts.issuer {
        Some(i) => service.personal_idps.iter().find(|p| &p.issuer == i),
        None => service.personal_idps.first(),
    }
    .cloned()
    .ok_or_else(|| ClientError::Config("the service doesn't offer this sign-in provider".into()))?;

    let (keys, reset) = match opts.keys {
        KeyChoice::New => (DeviceKeys::generate(), false),
        KeyChoice::Restore(k) => (*k, false),
        KeyChoice::Reset => (DeviceKeys::generate(), true),
    };
    let signing_public = keys.signing.verifying_key().to_vec();
    let kem_public = keys.kem.public_key().to_vec();
    let auth = authenticator(&http, &idp, t.dev, login)?;
    let id_token = auth
        .id_token(&signup_nonce(&signing_public, &kem_public))
        .await?;
    let account: Account = http
        .post_json(
            &t.service_url,
            "/v1/accounts",
            &SignUpRequest {
                issuer: idp.issuer.clone(),
                id_token,
                signing_public,
                kem_public,
                reset,
            },
            None,
        )
        .await?;
    check_backup_owner(&keys, &account)?;
    save_account(
        paths,
        secrets,
        t,
        &registry,
        &idp.issuer,
        &idp.client_id,
        idp.client_secret.clone(),
        &keys,
        &account,
        &idp.name,
        opts.default_output_dir,
    )
}

/// The common end of every sign-up: check a restored backup belongs to
/// this account, keep the keys in the keychain and write the config.
#[allow(clippy::too_many_arguments)]
fn save_account(
    paths: &Paths,
    secrets: Arc<dyn SecretStore>,
    t: &ServiceTarget,
    registry: &svx_core::crypto::VerifyingKey,
    issuer: &str,
    client_id: &str,
    client_secret: Option<String>,
    keys: &DeviceKeys,
    account: &Account,
    provider: &str,
    default_output_dir: Option<PathBuf>,
) -> Result<(Client, AccountInfo)> {
    let (signing_ref, _) =
        keystore::store_signing(secrets.as_ref(), &account.account, &keys.signing)?;
    let kem_key = keystore::store_kem(secrets.as_ref(), &account.account, &keys.kem)?;
    let cfg = ClientConfig {
        service_url: t.service_url.clone(),
        registry_key: hex::encode(registry.fingerprint()),
        registry_public: hex::encode(registry.to_vec()),
        org_id: account.account.clone(),
        idp_issuer: issuer.to_owned(),
        idp_client_id: client_id.to_owned(),
        group_claim: "groups".into(),
        dev: t.dev,
        default_output_dir,
        idp_client_secret: client_secret,
        account: Some(AccountConfig {
            email: account.email.clone(),
            signing_key: signing_ref.to_string(),
            kem_key,
        }),
    };
    cfg.save(&paths.config)?;
    let client = Client::with_config(paths.clone(), cfg)?.with_secret_store(secrets);
    let info = client.account_info_from(account, provider)?;
    Ok((client, info))
}

fn check_backup_owner(keys: &DeviceKeys, account: &Account) -> Result<()> {
    if let Some(a) = &keys.account
        && a != &account.account
    {
        return Err(ClientError::Invalid(format!(
            "this backup belongs to {}, not to {}",
            keys.email.as_deref().unwrap_or(a),
            account.email
        )));
    }
    Ok(())
}

// ----- Email accounts -----

/// Ask the service to email a six-digit code to `email`. For signing in
/// or a password reset, nothing is sent unless the address has an email
/// account (the answer looks the same either way).
pub async fn request_email_code(
    target: &ServiceTarget,
    email: &str,
    purpose: CodePurpose,
) -> Result<EmailCodeResponse> {
    let http = ManagedClient::new(target.dev)?;
    Ok(http
        .post_json(
            &target.service_url,
            "/v1/auth/email/code",
            &EmailCodeRequest {
                email: email.trim().to_owned(),
                purpose,
            },
            None,
        )
        .await?)
}

/// What the person typed for an email account.
pub struct EmailCredentials {
    pub email: String,
    pub password: Zeroizing<String>,
    /// For a new account (both required); `None` to sign in.
    pub names: Option<(String, String)>,
    /// From [`request_email_code`].
    pub challenge: [u8; 16],
    pub code: String,
}

/// Create an email account (`creds.names` set) or sign in on this device
/// with one, register the device keys, keep them in the keychain and save
/// the configuration. The password is checked here first with the same
/// rules the service enforces.
pub async fn sign_up_email(
    paths: &Paths,
    secrets: Arc<dyn SecretStore>,
    opts: SignUpOptions,
    creds: EmailCredentials,
) -> Result<(Client, AccountInfo)> {
    if paths.config.exists() && !opts.replace {
        return Err(ClientError::Config(format!(
            "{} exists; sign out first",
            paths.config.display()
        )));
    }
    if let Some((first, last)) = &creds.names {
        if !valid_name(first) || !valid_name(last) {
            return Err(ClientError::Invalid(
                "enter your first and last name (without @, < or >)".into(),
            ));
        }
        let s = password_strength(&creds.password, &[&creds.email, first, last]);
        if !s.ok {
            return Err(ClientError::Invalid(format!(
                "choose a stronger password: {}",
                s.feedback.join(" ")
            )));
        }
    }
    let t = &opts.target;
    let http = ManagedClient::new(t.dev)?;
    let registry =
        crate::setup::registry_key(&http, &t.service_url, &t.registry_key, t.dev).await?;
    let (keys, reset) = match opts.keys {
        KeyChoice::New => (DeviceKeys::generate(), false),
        KeyChoice::Restore(k) => (*k, false),
        KeyChoice::Reset => (DeviceKeys::generate(), true),
    };
    let account: Account = http
        .post_json(
            &t.service_url,
            "/v1/accounts/email",
            &EmailAccountRequest {
                challenge: creds.challenge,
                code: creds.code.trim().to_owned(),
                email: creds.email.trim().to_owned(),
                password: creds.password.to_string(),
                first_name: creds.names.as_ref().map(|n| n.0.trim().to_owned()),
                last_name: creds.names.as_ref().map(|n| n.1.trim().to_owned()),
                signing_public: keys.signing.verifying_key().to_vec(),
                kem_public: keys.kem.public_key().to_vec(),
                keys: if reset { KeyMode::Reset } else { KeyMode::Keep },
            },
            None,
        )
        .await?;
    check_backup_owner(&keys, &account)?;
    save_account(
        paths,
        secrets,
        t,
        &registry,
        EMAIL_ISSUER,
        "svx",
        None,
        &keys,
        &account,
        EMAIL_PROVIDER_NAME,
        opts.default_output_dir,
    )
}

/// Forgot password: set a new one with an emailed code
/// ([`CodePurpose::ResetPassword`]). Device keys are not affected.
pub async fn reset_password(
    target: &ServiceTarget,
    email: &str,
    challenge: [u8; 16],
    code: &str,
    new_password: &str,
) -> Result<()> {
    let s = password_strength(new_password, &[email]);
    if !s.ok {
        return Err(ClientError::Invalid(format!(
            "choose a stronger password: {}",
            s.feedback.join(" ")
        )));
    }
    let http = ManagedClient::new(target.dev)?;
    let _: serde_json::Value = http
        .post_json(
            &target.service_url,
            "/v1/auth/email/reset",
            &PasswordResetRequest {
                challenge,
                code: code.trim().to_owned(),
                email: email.trim().to_owned(),
                new_password: new_password.to_owned(),
            },
            None,
        )
        .await?;
    Ok(())
}

// ----- Backups -----

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupBody {
    v: u32,
    account: String,
    email: String,
    /// `kind ‖ secret`, hex.
    signing: String,
    kem: String,
}

fn check_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(ClientError::Config(format!(
            "use a recovery password of at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

/// Read a backup made with [`Client::save_backup`].
pub fn read_backup(path: &Path, password: &str) -> Result<DeviceKeys> {
    let blob = std::fs::read(path)?;
    let pt = open_with_password(password, &blob).map_err(|_| {
        ClientError::Invalid("wrong recovery password, or not an SVX backup".into())
    })?;
    let b: BackupBody = serde_json::from_slice(&pt)
        .map_err(|_| ClientError::Invalid("this backup is damaged".into()))?;
    let bad = || ClientError::Invalid("this backup is damaged".into());
    let signing = Zeroizing::new(hex::decode(&b.signing).map_err(|_| bad())?);
    let kem = Zeroizing::new(hex::decode(&b.kem).map_err(|_| bad())?);
    let (&sk, s) = signing.split_first().ok_or_else(bad)?;
    let (&kk, k) = kem.split_first().ok_or_else(bad)?;
    let signing = SigningKey::from_secret_bytes(KeyKind::from_byte(sk).ok_or_else(bad)?, s)
        .map_err(|_| bad())?;
    let kem = KemSecretKey::from_kind_bytes(
        KeyKind::from_byte(kk).ok_or_else(bad)?,
        k.try_into().map_err(|_| bad())?,
    )
    .map_err(|_| bad())?;
    if signing.kind() != KeyKind::MaxSigning || kem.kind() != KeyKind::MaxKem {
        return Err(bad());
    }
    Ok(DeviceKeys {
        signing,
        kem,
        account: Some(b.account),
        email: Some(b.email),
    })
}

/// Write `bytes` to a new owner-only file (never replaces one).
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            ClientError::OutputExists(path.to_path_buf())
        } else {
            ClientError::Io(e)
        }
    })?;
    std::io::Write::write_all(&mut f, bytes)?;
    f.sync_all()?;
    Ok(())
}

// ----- The account's operations -----

struct Device {
    account: String,
    signing: SigningKey,
    kem: KemSecretKey,
}

fn header_and_trailer(path: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut r = svx_core::format::Reader::new(BufReader::new(File::open(path)?))
        .map_err(|e| ClientError::Rejected(e.to_string()))?;
    let header_region = r.header_region().to_vec();
    let mut buf = Vec::new();
    while r
        .next_chunk(&mut buf)
        .map_err(|e| ClientError::Rejected(e.to_string()))?
        .is_some()
    {}
    let (trailer, _) = r
        .finish()
        .map_err(|e| ClientError::Rejected(e.to_string()))?;
    let trailer = trailer
        .encode()
        .map_err(|e| ClientError::Rejected(e.to_string()))?;
    Ok((header_region, trailer))
}

fn normalize_emails(to: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for e in to {
        let e = e.trim().to_owned();
        if e.is_empty() {
            continue;
        }
        if !e.contains('@') || e.len() > 254 {
            return Err(ClientError::Config(format!(
                "{e:?} is not an email address"
            )));
        }
        if !out.iter().any(|o| o.eq_ignore_ascii_case(&e)) {
            out.push(e);
        }
    }
    if out.is_empty() {
        return Err(ClientError::Config("add at least one recipient".into()));
    }
    if out.len() > MAX_RECIPIENTS {
        return Err(ClientError::Config(format!(
            "at most {MAX_RECIPIENTS} recipients per file"
        )));
    }
    Ok(out)
}

impl Client {
    fn account_config(&self) -> Result<&AccountConfig> {
        self.cfg.account.as_ref().ok_or_else(|| {
            ClientError::Config("this is a company setup, not a personal account".into())
        })
    }

    fn device(&self) -> Result<Device> {
        let a = self.account_config()?;
        let (_, signing) =
            keystore::load_signing(self.secrets.as_ref(), &KeyRef::parse(&a.signing_key)?)?;
        let kem = keystore::load_kem(self.secrets.as_ref(), &self.cfg.org_id, &a.kem_key)?;
        Ok(Device {
            account: self.cfg.org_id.clone(),
            signing,
            kem,
        })
    }

    async fn call<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let d = self.device()?;
        Ok(self
            .http
            .signed(
                method,
                &self.cfg.service_url,
                path,
                body,
                &d.account,
                &d.signing,
            )
            .await?)
    }

    fn account_info_from(&self, a: &Account, provider: &str) -> Result<AccountInfo> {
        let d = self.device()?;
        Ok(AccountInfo {
            account: a.account.clone(),
            email: a.email.clone(),
            provider: provider.to_owned(),
            issuer: a.issuer.clone(),
            created_at: Some(a.created_at),
            signing_key_id: hex::encode(d.signing.verifying_key().key_id()),
            kem_key_id: hex::encode(d.kem.public_key().key_id()),
            kem_public: hex::encode(d.kem.public_key().to_vec()),
        })
    }

    /// The signed-in account (checks the device keys with the service).
    pub async fn account(&self) -> Result<AccountInfo> {
        let a: Account = self.call::<(), _>(Method::GET, "/v1/me", None).await?;
        let provider = provider_name(&a.issuer);
        self.account_info_from(&a, &provider)
    }

    /// The account's name. Google accounts start without one; the app asks
    /// for it before anything else.
    pub async fn account_name(&self) -> Result<AccountName> {
        self.call::<(), _>(Method::GET, "/v1/me/name", None).await
    }

    /// Give an account without a name its name (once; it's shown next to
    /// the email address to the people this account sends files to).
    pub async fn set_account_name(&self, first: &str, last: &str) -> Result<AccountName> {
        let (first, last) = (first.trim(), last.trim());
        if !valid_name(first) || !valid_name(last) {
            return Err(ClientError::Invalid(
                "names are 1 to 64 characters, without @, < or >".into(),
            ));
        }
        self.call(
            Method::PUT,
            "/v1/me/name",
            Some(&SetNameRequest {
                first_name: first.to_owned(),
                last_name: last.to_owned(),
            }),
        )
        .await
    }

    /// Change an email account's password.
    pub async fn change_password(&self, current: &str, new: &str) -> Result<()> {
        let s = password_strength(new, &[&self.account_config()?.email]);
        if !s.ok {
            return Err(ClientError::Invalid(format!(
                "choose a stronger password: {}",
                s.feedback.join(" ")
            )));
        }
        self.present(Need::Always, "change your password").await?;
        let _: serde_json::Value = self
            .call(
                Method::POST,
                "/v1/me/password",
                Some(&ChangePasswordRequest {
                    current_password: current.to_owned(),
                    new_password: new.to_owned(),
                }),
            )
            .await?;
        Ok(())
    }

    /// Save the account's private keys to `path` (a new file), encrypted
    /// with `password`.
    pub fn save_backup(&self, path: &Path, password: &str) -> Result<()> {
        check_password(password)?;
        self.present_blocking(Need::Always, "save a backup of your keys")?;
        let a = self.account_config()?;
        let d = self.device()?;
        let mut signing = Zeroizing::new(vec![d.signing.kind().byte()]);
        signing.extend_from_slice(&d.signing.to_secret_bytes());
        let mut kem = Zeroizing::new(vec![d.kem.kind().byte()]);
        kem.extend_from_slice(d.kem.to_bytes().as_ref());
        let body = BackupBody {
            v: 1,
            account: d.account,
            email: a.email.clone(),
            signing: hex::encode(&*signing),
            kem: hex::encode(&*kem),
        };
        let pt = Zeroizing::new(
            serde_json::to_vec(&body).map_err(|e| ClientError::Other(e.to_string()))?,
        );
        drop(Zeroizing::new(body.signing));
        drop(Zeroizing::new(body.kem));
        let blob = seal_with_password(password, &pt, BackupParams::STRONG, &mut os_rng())
            .map_err(|e| ClientError::Other(e.to_string()))?;
        write_private(path, &blob)
    }

    /// Find someone by email in the signed directory.
    pub async fn lookup(&self, email: &str) -> Result<Contact> {
        let rec = self.lookup_record(email).await?;
        Ok(Contact {
            account: rec.org_id,
            email: rec.account_email.unwrap_or_default(),
        })
    }

    async fn lookup_record(&self, email: &str) -> Result<OrgRecord> {
        let d = self.device()?;
        self.http
            .lookup_email(
                &self.cfg.service_url,
                email,
                &d.account,
                &d.signing,
                &self.cfg.registry_key()?,
            )
            .await
            .map_err(|e| match ClientError::from(e) {
                ClientError::Denied(svx_protocol::DenyReason::InvalidRequest) => {
                    ClientError::Invalid(format!(
                        "{} doesn't have an SVX account yet",
                        email.trim()
                    ))
                }
                other => other,
            })
    }

    /// Encrypt a file for people by email and register it with its rules.
    pub async fn send(&self, o: SendOptions) -> Result<SendResult> {
        self.present(Need::Session, "send a file").await?;
        let d = self.device()?;
        let emails = normalize_emails(&o.to)?;
        if o.expires_at.is_some_and(|t| t <= crate::now()) {
            return Err(ClientError::Config("expiry is in the past".into()));
        }
        let registry = Registry::new(&self.cfg, &self.http)?;
        // My key must be active, or recipients would refuse the file.
        let me = registry.org(&d.account).await?;
        let my_id = d.signing.verifying_key().key_id();
        if !me.keys.iter().any(|k| {
            k.kind == KeyKindWire::Max && k.status == KeyStatus::Active && k.key_id == my_id
        }) {
            return Err(ClientError::Config(
                "this device's key is no longer active for your account (keys were reset on \
                 another device): restore your backup or reset your keys"
                    .into(),
            ));
        }
        let mut recipients = Vec::new();
        for e in &emails {
            let rec = self.lookup_record(e).await?;
            let key = active_kem_key(&rec)?;
            let id = Identifier::new(&rec.org_id)
                .map_err(|_| ClientError::Other("invalid account ID".into()))?;
            recipients.push((
                Contact {
                    account: rec.org_id.clone(),
                    email: rec.account_email.clone().unwrap_or_default(),
                },
                id,
                key,
            ));
        }
        let service = registry.service().await?;
        let service_key = service
            .kem_public_key()
            .map_err(|_| ClientError::Other("invalid service key".into()))?;
        let service_id = Identifier::new(&service.service_id)
            .map_err(|_| ClientError::Other("invalid service id".into()))?;

        // A view-only file holds a small container (see `viewfile`); an
        // Office file is converted here, from the sender's own file.
        let (manifest, source, output): (Manifest, Box<dyn Read + Send>, PathBuf) =
            if o.rules.view_only {
                let input = o.input.clone();
                let parts = tokio::task::spawn_blocking(move || crate::viewfile::prepare(&input))
                    .await
                    .map_err(|e| ClientError::Other(e.to_string()))??;
                let payload = crate::viewfile::build(&parts)?;
                let name = match o.name {
                    Some(n) => n,
                    None => o
                        .input
                        .file_name()
                        .and_then(|n| n.to_str())
                        .ok_or_else(|| ClientError::Config("input has no usable file name".into()))?
                        .to_owned(),
                };
                let mut manifest = Manifest::single_file(&name, payload.len() as u64);
                manifest.files[0].content_type = Some(crate::viewfile::VIEW_CONTENT_TYPE.into());
                let output = o.output.unwrap_or_else(|| o.input.with_extension("svx"));
                (manifest, Box::new(Cursor::new(payload)), output)
            } else {
                let input = crate::pack::prepare_input(&o.input, o.name)?;
                let output = o.output.unwrap_or_else(|| input.default_output.clone());
                let file = File::open(&input.path)?;
                let mut manifest = Manifest::single_file(&input.name, file.metadata()?.len());
                manifest.files[0].content_type = input.content_type.clone();
                // `input` may own a temporary zip of a folder: keep it open with the file.
                (
                    manifest,
                    Box::new(Keep(BufReader::new(file), input)),
                    output,
                )
            };
        let dir = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let tmp = tempfile::NamedTempFile::new_in(&dir)?;
        let summary = svx_core::pack(
            &PackRequest {
                suite: Suite::CURRENT,
                sender_org: Identifier::new(&d.account)
                    .map_err(|_| ClientError::Other("invalid account ID".into()))?,
                signing_key: &d.signing,
                recipient_org: recipients[0].1.clone(),
                recipient_key: &recipients[0].2,
                more_recipients: recipients[1..]
                    .iter()
                    .map(|(_, id, k)| (id.clone(), k))
                    .collect(),
                service_id,
                service_key: &service_key,
                policy_ref: Identifier::new("personal").expect("valid identifier"),
                created_at: crate::now(),
                expires_at: o.expires_at,
                chunk_size: None,
                manifest,
                view_only: o.rules.view_only,
            },
            source,
            BufWriter::new(tmp.as_file()),
            &mut os_rng(),
        )
        .map_err(|e| ClientError::Other(e.to_string()))?;
        tmp.as_file().sync_all()?;
        // Register before the file appears: an unregistered personal file
        // can't be opened by anyone.
        let (header_region, trailer) = header_and_trailer(tmp.path())?;
        let _: FileStatus = self
            .call(
                Method::POST,
                "/v1/me/files",
                Some(&RegisterFileRequest {
                    header_region,
                    trailer,
                    rules: o.rules,
                }),
            )
            .await?;
        if o.overwrite {
            tmp.persist(&output).map_err(|e| ClientError::Io(e.error))?;
        } else {
            tmp.persist_noclobber(&output).map_err(|e| {
                if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                    ClientError::OutputExists(output.clone())
                } else {
                    ClientError::Io(e.error)
                }
            })?;
        }
        Ok(SendResult {
            path: output,
            artifact_id: hex::encode(summary.artifact_id),
            recipients: recipients.into_iter().map(|(c, _, _)| c).collect(),
            rules: o.rules,
            expires_at: o.expires_at,
            protection: summary.suite.description().into(),
        })
    }

    /// Open a file sent to this account. Every open checks with the service;
    /// if the sender must approve, this waits (polling) until they do,
    /// decline, or `cancel` is set.
    ///
    /// A view-only file is saved only once the sender has allowed it (the
    /// service refuses otherwise); then the sender's original is written.
    pub async fn open_personal(
        &self,
        path: &Path,
        output: Option<Output>,
        progress: &mut (dyn FnMut(Step) + Send),
        cancel: &AtomicBool,
    ) -> Result<OpenOutcome> {
        self.present(Need::Session, "open a file").await?;
        let output = match output {
            Some(o) => o,
            None => Output::Dir {
                dir: match &self.cfg.default_output_dir {
                    Some(dir) => dir.clone(),
                    None => default_open_dir()?,
                },
                overwrite: false,
            },
        };
        let r = self
            .release_personal(path, ReleaseMode::Save, progress, cancel)
            .await?;

        // Decrypt locally, then confirm (makes a one-time open final).
        progress(Step::Decrypting);
        let h = &r.verified.header;
        let outcome = if h.view_only {
            crate::view::save(
                path,
                &r,
                output,
                h.sender_org.to_string(),
                hex::encode(h.artifact_id),
            )?
        } else {
            write_output(path, &r.verified, &r.svc_share, &r.recipient_share, output)?
        };
        self.opened(&r).await;
        Ok(outcome)
    }

    /// Show a view-only file: decrypted only into memory, never written to
    /// disk. Every view asks the service again. Refused on Linux, where the
    /// viewer can't be kept out of screenshots.
    pub async fn view_personal(
        &self,
        path: &Path,
        progress: &mut (dyn FnMut(Step) + Send),
        cancel: &AtomicBool,
    ) -> Result<crate::view::ViewSession> {
        if cfg!(target_os = "linux") {
            return Err(ClientError::ViewUnsupported);
        }
        self.present(Need::Session, "view a file").await?;
        let viewer = self.account_config()?.email.clone();
        let r = self
            .release_personal(path, ReleaseMode::View, progress, cancel)
            .await?;
        progress(Step::Decrypting);
        let (manifest, parts) = crate::view::decrypt(path, &r)?;
        let session = crate::view::ViewSession::new(&r, &manifest, parts, viewer, crate::now());
        self.opened(&r).await;
        Ok(session)
    }

    /// Steps shared by saving and viewing: verify against the sender's
    /// registered keys, check it's for me and from our service, unwrap my
    /// half, then ask the service (waiting while the sender decides).
    async fn release_personal(
        &self,
        path: &Path,
        mode: ReleaseMode,
        progress: &mut (dyn FnMut(Step) + Send),
        cancel: &AtomicBool,
    ) -> Result<Released> {
        let d = self.device()?;
        let registry = Registry::new(&self.cfg, &self.http)?;

        // 1. Verify locally against the sender's registered keys.
        progress(Step::Verifying);
        let (_, header) = svx_core::inspect(BufReader::new(File::open(path)?))
            .map_err(|e| ClientError::Rejected(e.to_string()))?;
        let sender = match registry.org(header.sender_org.as_str()).await {
            Ok(r) => r,
            Err(ClientError::Unavailable(e)) => return Err(ClientError::Unavailable(e)),
            Err(_) => {
                return Err(ClientError::Rejected(format!(
                    "sender {} is not a verified account",
                    header.sender_org
                )));
            }
        };
        let mut trust = svx_core::TrustStore::new();
        sender
            .add_signing_keys_to(&mut trust)
            .map_err(|e| ClientError::Other(e.to_string()))?;
        let verified = svx_core::verify(BufReader::new(File::open(path)?), &trust)
            .map_err(|e| ClientError::Rejected(e.to_string()))?;
        let h = &verified.header;
        let sender_name = crate::info::sender_label(&sender);
        progress(Step::SignatureValid {
            sender: sender_name.clone(),
        });
        // Viewing is for view-only files; asking would count as an open.
        if mode == ReleaseMode::View && !h.view_only {
            return Err(ClientError::Invalid(
                "this file isn't view-only: open it normally".into(),
            ));
        }

        // 2. For me, from our service, not expired.
        if !h.all_recipients().iter().any(|r| r.as_str() == d.account) {
            return Err(ClientError::NotRecipient {
                recipient: h.recipient_org.to_string(),
                mine: self.account_config()?.email.clone(),
            });
        }
        if verified.is_expired(crate::now()) {
            return Err(ClientError::Expired);
        }
        progress(Step::Connecting);
        let service = registry.service().await?;
        if h.service_id.as_str() != service.service_id {
            return Err(ClientError::Rejected(format!(
                "this file is managed by {}, not {}",
                h.service_id, service.service_id
            )));
        }
        // My half first: if it isn't sealed to this device's key, asking the
        // sender would be pointless.
        let recipient_share =
            unwrap_envelope(h, EnvelopeRole::RecipientOrg, &d.kem).map_err(|_| {
                ClientError::Rejected(
                    "this file was sent to keys this device doesn't have (restore your backup)"
                        .into(),
                )
            })?;

        // 3. Ask the service; repeat while the sender decides. Saving a
        // view-only file is refused unless the sender allowed sharing.
        progress(Step::CheckingAuthorization);
        let session = ReleaseSession::new();
        let request = session.personal_request(
            &verified.header_region,
            &{
                verified
                    .trailer
                    .encode()
                    .map_err(|e| ClientError::Rejected(e.to_string()))?
            },
            mode,
        );
        let mut announced = false;
        let share = loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(ClientError::Cancelled);
            }
            let resp: PersonalReleaseResponse = self
                .call(Method::POST, "/v1/personal/release", Some(&request))
                .await?;
            match resp {
                PersonalReleaseResponse::Released { share, .. } => break share,
                PersonalReleaseResponse::Pending {
                    sender_email,
                    expires_at,
                    ..
                } => {
                    if !announced {
                        progress(Step::AwaitingApproval {
                            sender: sender_email.unwrap_or_else(|| sender_name.clone()),
                        });
                        announced = true;
                    }
                    if crate::now() >= expires_at {
                        return Err(ClientError::Other(
                            "the sender didn't answer in time; try again".into(),
                        ));
                    }
                    wait(POLL_INTERVAL, cancel).await?;
                }
            }
        };
        let svc_share = session.open_service_share(&h.artifact_id, &share)?;
        progress(Step::AccessApproved);
        Ok(Released {
            verified,
            svc_share,
            recipient_share,
            session,
            sender: sender_name,
        })
    }

    /// Tell the service the file was decrypted (makes a one-time open final).
    /// Best effort: without it the open becomes final after a few minutes.
    async fn opened(&self, r: &Released) {
        let receipt = OpenedReceipt {
            artifact_id: r.verified.header.artifact_id,
            txn: *r.session.txn(),
        };
        let _ = self
            .call::<_, serde_json::Value>(Method::POST, "/v1/personal/opened", Some(&receipt))
            .await;
    }

    /// Requests waiting for this account's approval.
    pub async fn requests(&self) -> Result<Vec<ApprovalRequest>> {
        self.call::<(), _>(Method::GET, "/v1/me/requests", None)
            .await
    }

    pub async fn approve(&self, request_id: &str) -> Result<ApprovalRequest> {
        self.present(Need::Always, "approve a request about your file")
            .await?;
        self.decide(request_id, "approve").await
    }

    pub async fn decline(&self, request_id: &str) -> Result<ApprovalRequest> {
        self.decide(request_id, "decline").await
    }

    async fn decide(&self, request_id: &str, what: &str) -> Result<ApprovalRequest> {
        let id = parse_hex_id(request_id)?;
        self.call::<(), _>(
            Method::POST,
            &format!("/v1/me/requests/{}/{what}", hex::encode(id)),
            None,
        )
        .await
    }

    /// Whether this account may save a view-only file it received (by
    /// artifact ID or file).
    pub async fn share_status(&self, target: &str) -> Result<ShareStatus> {
        let id = crate::info::artifact_id_of(target)?;
        self.call::<(), _>(
            Method::GET,
            &format!("/v1/personal/share/{}", hex::encode(id)),
            None,
        )
        .await
    }

    /// Ask the sender to allow saving a view-only file as a normal file.
    /// The sender decides in the app; poll with [`Client::share_status`].
    pub async fn request_share(&self, target: &str) -> Result<ShareStatus> {
        self.present(Need::Session, "ask to keep a file").await?;
        let id = crate::info::artifact_id_of(target)?;
        self.call::<(), _>(
            Method::POST,
            &format!("/v1/personal/share/{}", hex::encode(id)),
            None,
        )
        .await
    }

    /// A sent file's rules and recipients (by artifact ID or file).
    pub async fn file_status(&self, target: &str) -> Result<FileStatus> {
        let id = crate::info::artifact_id_of(target)?;
        self.call::<(), _>(
            Method::GET,
            &format!("/v1/me/files/{}", hex::encode(id)),
            None,
        )
        .await
    }

    /// Change a sent file's rules, or revoke it (for everyone or some).
    pub async fn update_file(&self, target: &str, u: &UpdateFileRequest) -> Result<FileStatus> {
        self.present(Need::Session, "change who can open your file")
            .await?;
        let id = crate::info::artifact_id_of(target)?;
        self.call(
            Method::PATCH,
            &format!("/v1/me/files/{}", hex::encode(id)),
            Some(u),
        )
        .await
    }

    /// Files sent and received, newest first.
    pub async fn history(&self) -> Result<History> {
        self.call::<(), _>(Method::GET, "/v1/me/history", None)
            .await
    }

    /// Forget this account on this computer: delete its keys from the
    /// keychain and its configuration. Make a backup first.
    pub fn sign_out(&self) -> Result<()> {
        self.present_blocking(Need::Always, "remove your keys from this computer")?;
        let a = self.account_config()?;
        keystore::delete(self.secrets.as_ref(), &KeyRef::parse(&a.signing_key)?)?;
        keystore::delete_kem(self.secrets.as_ref(), &self.cfg.org_id, &a.kem_key)?;
        match std::fs::remove_file(&self.paths.config) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

fn parse_hex_id(s: &str) -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    hex::decode_to_slice(s.trim(), &mut id)
        .map_err(|_| ClientError::Config("IDs are 32 hex characters".into()))?;
    Ok(id)
}

fn provider_name(issuer: &str) -> String {
    match issuer {
        "https://accounts.google.com" => "Google".into(),
        EMAIL_ISSUER => EMAIL_PROVIDER_NAME.into(),
        other => other.into(),
    }
}

async fn wait(d: Duration, cancel: &AtomicBool) -> Result<()> {
    let step = Duration::from_millis(200);
    let mut left = d;
    while !left.is_zero() {
        if cancel.load(Ordering::Relaxed) {
            return Err(ClientError::Cancelled);
        }
        let s = step.min(left);
        tokio::time::sleep(s).await;
        left -= s;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_cleaned_and_bounded() {
        let v = normalize_emails(&[
            " bob@example.test ".into(),
            "Bob@Example.test".into(),
            "".into(),
            "carol@example.test".into(),
        ])
        .unwrap();
        assert_eq!(v, ["bob@example.test", "carol@example.test"]);
        assert!(normalize_emails(&["bob".into()]).is_err());
        assert!(normalize_emails(&[]).is_err());
        let many: Vec<String> = (0..16).map(|i| format!("p{i}@example.test")).collect();
        assert!(normalize_emails(&many).is_err());
    }

    #[test]
    fn weak_passwords_are_refused() {
        assert!(check_password("short").is_err());
        check_password("a long recovery phrase").unwrap();
    }
}
