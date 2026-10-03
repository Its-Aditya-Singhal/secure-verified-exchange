//! Personal accounts: sign up with Google or Apple, keys in the keychain
//! with one password-protected backup, send to email addresses, open with
//! the sender's live approval, and manage sent files afterwards.
//!
//! After sign-up, every request to the service is signed with the device's
//! hybrid key, so opening a file never needs a browser.

use std::fs::File;
use std::io::{BufReader, BufWriter};
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
use svx_protocol::personal::{
    Account, ApprovalRequest, FileRules, FileStatus, History, OpenedReceipt, PersonalIdp,
    PersonalReleaseResponse, RegisterFileRequest, SignUpRequest, UpdateFileRequest, signup_nonce,
};
use svx_protocol::{KeyKindWire, KeyStatus, ManagedClient, Method, OrgRecord, ReleaseSession};
use zeroize::Zeroizing;

use crate::account::{LOGIN_TIMEOUT, LoginMethod};
use crate::client::Client;
use crate::config::{AccountConfig, ClientConfig, Paths, default_open_dir};
use crate::defaults::ServiceTarget;
use crate::error::{ClientError, Result};
use crate::keystore::{self, KeyRef, SecretStore};
use crate::login::{Authenticator, BrowserLogin, DevLogin, RelayLogin};
use crate::open::{OpenOutcome, Output, Step, write_output};
use crate::registry::{Registry, active_hybrid_kem_key};

/// How often to ask again while waiting for the sender's approval.
pub const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// Shortest recovery password accepted for a backup.
pub const MIN_PASSWORD_LEN: usize = 10;
/// At most this many recipients per file.
pub const MAX_RECIPIENTS: usize = svx_core::format::limits::MAX_RECIPIENTS;

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
            signing: SigningKey::generate_hybrid(&mut rng),
            kem: KemSecretKey::generate_hybrid(&mut rng),
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
    service_url: &str,
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
        // Apple and other relayed providers: the service receives the
        // provider's callback.
        LoginMethod::Browser(opener) if idp.relay => Box::new(RelayLogin {
            client: http.clone(),
            service_url: service_url.to_owned(),
            issuer: idp.issuer.clone(),
            opener,
            timeout: LOGIN_TIMEOUT,
        }),
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

/// Sign up (or sign in on a new device) with Google or Apple, register the
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
    let auth = authenticator(&http, &t.service_url, &idp, t.dev, login)?;
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
    if let Some(a) = &keys.account
        && a != &account.account
    {
        return Err(ClientError::Invalid(format!(
            "this backup belongs to {}, not to {}",
            keys.email.as_deref().unwrap_or(a),
            account.email
        )));
    }

    let (signing_ref, _) =
        keystore::store_signing(secrets.as_ref(), &account.account, &keys.signing)?;
    let kem_key = keystore::store_kem(secrets.as_ref(), &account.account, &keys.kem)?;
    let cfg = ClientConfig {
        service_url: t.service_url.clone(),
        registry_key: hex::encode(registry.fingerprint()),
        registry_public: hex::encode(registry.to_vec()),
        org_id: account.account.clone(),
        idp_issuer: idp.issuer.clone(),
        idp_client_id: idp.client_id.clone(),
        group_claim: "groups".into(),
        dev: t.dev,
        default_output_dir: opts.default_output_dir,
        idp_client_secret: idp.client_secret.clone(),
        account: Some(AccountConfig {
            email: account.email.clone(),
            signing_key: signing_ref.to_string(),
            kem_key,
        }),
    };
    cfg.save(&paths.config)?;
    let client = Client::with_config(paths.clone(), cfg)?.with_secret_store(secrets);
    let info = client.account_info_from(&account, &idp.name)?;
    Ok((client, info))
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
    if signing.kind() != KeyKind::HybridSigning || kem.kind() != KeyKind::XWingKem {
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

    /// Save the account's private keys to `path` (a new file), encrypted
    /// with `password`.
    pub fn save_backup(&self, path: &Path, password: &str) -> Result<()> {
        check_password(password)?;
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
            k.kind == KeyKindWire::Ed25519Mldsa65
                && k.status == KeyStatus::Active
                && k.key_id == my_id
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
            let key = active_hybrid_kem_key(&rec)?;
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

        let input = crate::pack::prepare_input(&o.input, o.name)?;
        let output = o.output.unwrap_or_else(|| input.default_output.clone());
        let file = File::open(&input.path)?;
        let mut manifest = Manifest::single_file(&input.name, file.metadata()?.len());
        manifest.files[0].content_type = input.content_type.clone();
        let dir = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let tmp = tempfile::NamedTempFile::new_in(&dir)?;
        let summary = svx_core::pack(
            &PackRequest {
                suite: Suite::Svx1H,
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
            },
            BufReader::new(file),
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
    pub async fn open_personal(
        &self,
        path: &Path,
        output: Option<Output>,
        progress: &mut (dyn FnMut(Step) + Send),
        cancel: &AtomicBool,
    ) -> Result<OpenOutcome> {
        let d = self.device()?;
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
        let sender_name = sender
            .account_email
            .clone()
            .unwrap_or_else(|| sender.display_name.clone());
        progress(Step::SignatureValid {
            sender: sender_name.clone(),
        });

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

        // 3. Ask the service; repeat while the sender decides.
        progress(Step::CheckingAuthorization);
        let session = ReleaseSession::new();
        let request = session.personal_request(&verified.header_region, &{
            verified
                .trailer
                .encode()
                .map_err(|e| ClientError::Rejected(e.to_string()))?
        });
        let mut announced = false;
        let share = loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(ClientError::Cancelled);
            }
            let resp: PersonalReleaseResponse = self
                .call(Method::POST, "/v1/personal/release", Some(&request))
                .await?;
            match resp {
                PersonalReleaseResponse::Released { share } => break share,
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

        // 4. Decrypt locally, then confirm (makes a one-time open final).
        progress(Step::Decrypting);
        let outcome = write_output(path, &verified, &svc_share, &recipient_share, output)?;
        let receipt = OpenedReceipt {
            artifact_id: h.artifact_id,
            txn: *session.txn(),
        };
        // Best effort: without it the open becomes final after a few minutes.
        let _ = self
            .call::<_, serde_json::Value>(Method::POST, "/v1/personal/opened", Some(&receipt))
            .await;
        Ok(outcome)
    }

    /// Requests waiting for this account's approval.
    pub async fn requests(&self) -> Result<Vec<ApprovalRequest>> {
        self.call::<(), _>(Method::GET, "/v1/me/requests", None)
            .await
    }

    pub async fn approve(&self, request_id: &str) -> Result<ApprovalRequest> {
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
        "https://appleid.apple.com" => "Apple".into(),
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
