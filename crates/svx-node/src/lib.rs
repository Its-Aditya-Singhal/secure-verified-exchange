//! Native core of the `@svx/sdk` Node.js package.
//!
//! A deliberately thin layer over [`svx_client`]: every operation is the
//! same code the `svx` CLI runs. Results cross the boundary as JSON
//! strings; errors are thrown as `Error`s whose message is
//! `SVX_ERROR:{json}` (kind, message, exitCode, denyReason), which the
//! TypeScript layer turns into typed error classes. All I/O runs on the
//! napi tokio runtime and returns Promises.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::{Buffer, FnArgs};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use serde::Serialize;
use svx_client::account::LoginMethod;
use svx_client::login::{print_url, system_browser};
use svx_client::{ClientError, Output, PackOptions, Step, info, keys};
use svx_protocol::Policy;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorJson<'a> {
    kind: &'a str,
    message: String,
    exit_code: u8,
    deny_reason: Option<&'a str>,
}

fn err(e: ClientError) -> napi::Error {
    let j = ErrorJson {
        kind: e.kind().as_str(),
        message: e.to_string(),
        exit_code: e.exit_code(),
        deny_reason: e.deny_reason(),
    };
    napi::Error::from_reason(format!(
        "SVX_ERROR:{}",
        serde_json::to_string(&j).unwrap_or_default()
    ))
}

fn to_json<T: Serialize>(v: &T) -> napi::Result<String> {
    serde_json::to_string(v).map_err(|e| err(ClientError::Other(e.to_string())))
}

fn login_method(dev_user: Option<String>, browser: bool) -> LoginMethod {
    match dev_user {
        Some(u) => LoginMethod::Dev(u),
        None => LoginMethod::Browser(if browser {
            system_browser()
        } else {
            print_url()
        }),
    }
}

/// `onStep(name, detail)` progress callback, called without blocking.
type StepArgs = FnArgs<(String, Option<String>)>;
type StepFn = ThreadsafeFunction<StepArgs, (), StepArgs, napi::Status, false>;

fn progress_fn(cb: Option<Arc<StepFn>>) -> impl FnMut(Step) + Send {
    move |s: Step| {
        if let Some(cb) = &cb {
            let detail = match &s {
                Step::SignatureValid { sender } => Some(sender.clone()),
                _ => None,
            };
            cb.call(
                (s.name().to_owned(), detail).into(),
                ThreadsafeFunctionCallMode::NonBlocking,
            );
        }
    }
}

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("buffer poisoned"))?
            .extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct OpenJson<'a> {
    path: Option<&'a Path>,
    sender_org: &'a str,
    artifact_id: &'a str,
    manifest: &'a svx_core::Manifest,
}

impl<'a> From<&'a svx_client::OpenOutcome> for OpenJson<'a> {
    fn from(o: &'a svx_client::OpenOutcome) -> Self {
        OpenJson {
            path: o.path.as_deref(),
            sender_org: &o.sender_org,
            artifact_id: &o.artifact_id,
            manifest: &o.manifest,
        }
    }
}

/// Parse the artifact header without verifying anything (JSON).
#[napi]
pub fn inspect(path: String) -> napi::Result<String> {
    to_json(&info::inspect(Path::new(&path)).map_err(err)?)
}

/// Verify offline against `*.sign.pub` files (JSON).
#[napi]
pub fn verify(path: String, trust: Vec<String>) -> napi::Result<String> {
    let trust: Vec<PathBuf> = trust.into_iter().map(PathBuf::from).collect();
    let t = info::trust_from_files(&trust).map_err(err)?;
    to_json(&info::verify_with(Path::new(&path), &t).map_err(err)?)
}

/// Generate `<prefix>.sign.key/.pub`; returns the key ID.
#[napi]
pub fn generate_signing_key(prefix: String, owner: String) -> napi::Result<String> {
    keys::generate_signing(Path::new(&prefix), &owner).map_err(err)
}

/// Generate `<prefix>.kem.key/.pub`; returns the key ID.
#[napi]
pub fn generate_kem_key(prefix: String, owner: String) -> napi::Result<String> {
    keys::generate_kem(Path::new(&prefix), &owner).map_err(err)
}

#[napi(object)]
pub struct OpenBytesResult {
    pub json: String,
    pub data: Buffer,
}

#[napi(object)]
pub struct NativePackOptions {
    pub input: String,
    pub output: Option<String>,
    pub recipient: String,
    pub policy: String,
    pub signing_key: String,
    pub expires_at: Option<i64>,
    pub classification: Option<String>,
    pub description: Option<String>,
    pub name: Option<String>,
    pub overwrite: Option<bool>,
    pub register: Option<bool>,
}

#[napi]
pub struct NativeClient {
    inner: Arc<svx_client::Client>,
}

#[napi]
impl NativeClient {
    #[napi(constructor)]
    pub fn new(config: Option<String>) -> napi::Result<Self> {
        let inner = svx_client::Client::load(config.as_deref().map(Path::new)).map_err(err)?;
        Ok(NativeClient {
            inner: Arc::new(inner),
        })
    }

    #[napi]
    pub fn config_json(&self) -> napi::Result<String> {
        to_json(&self.inner.cfg)
    }

    #[napi]
    pub fn config_path(&self) -> String {
        self.inner.paths.config.display().to_string()
    }

    #[napi]
    pub async fn status(&self, path: String) -> napi::Result<String> {
        let c = self.inner.clone();
        to_json(&c.status(Path::new(&path)).await.map_err(err)?)
    }

    #[napi]
    pub async fn open(
        &self,
        path: String,
        output_dir: Option<String>,
        overwrite: bool,
        dev_user: Option<String>,
        browser: bool,
        #[napi(ts_arg_type = "((name: string, detail: string | null) => void) | undefined | null")]
        on_step: Option<StepFn>,
    ) -> napi::Result<String> {
        let c = self.inner.clone();
        let output = output_dir.map(|dir| Output::Dir {
            dir: PathBuf::from(dir),
            overwrite,
        });
        let mut progress = progress_fn(on_step.map(Arc::new));
        let o = c
            .open(
                Path::new(&path),
                output,
                login_method(dev_user, browser),
                &mut progress,
            )
            .await
            .map_err(err)?;
        to_json(&OpenJson::from(&o))
    }

    #[napi]
    pub async fn open_bytes(
        &self,
        path: String,
        dev_user: Option<String>,
        browser: bool,
        #[napi(ts_arg_type = "((name: string, detail: string | null) => void) | undefined | null")]
        on_step: Option<StepFn>,
    ) -> napi::Result<OpenBytesResult> {
        let c = self.inner.clone();
        let buf = SharedBuf::default();
        let mut progress = progress_fn(on_step.map(Arc::new));
        let o = c
            .open(
                Path::new(&path),
                Some(Output::Writer(Box::new(buf.clone()))),
                login_method(dev_user, browser),
                &mut progress,
            )
            .await
            .map_err(err)?;
        let data = std::mem::take(
            &mut *buf
                .0
                .lock()
                .map_err(|_| err(ClientError::Other("buffer poisoned".into())))?,
        );
        Ok(OpenBytesResult {
            json: to_json(&OpenJson::from(&o))?,
            data: data.into(),
        })
    }

    #[napi]
    pub async fn pack(&self, o: NativePackOptions) -> napi::Result<String> {
        let c = self.inner.clone();
        let r = c
            .pack(PackOptions {
                input: o.input.into(),
                output: o.output.map(PathBuf::from),
                overwrite: o.overwrite.unwrap_or(false),
                signing_key: o.signing_key.into(),
                recipient: o.recipient,
                policy: o.policy,
                expires_at: o.expires_at,
                classification: o.classification,
                description: o.description,
                name: o.name,
                register: o.register.unwrap_or(false),
            })
            .await
            .map_err(err)?;
        to_json(&r)
    }

    #[napi]
    pub async fn login(&self, dev_user: Option<String>, browser: bool) -> napi::Result<String> {
        let c = self.inner.clone();
        to_json(
            &c.login(login_method(dev_user, browser))
                .await
                .map_err(err)?,
        )
    }

    #[napi]
    pub fn logout(&self) -> napi::Result<bool> {
        self.inner.logout().map_err(err)
    }

    #[napi]
    pub async fn whoami(&self) -> napi::Result<String> {
        let c = self.inner.clone();
        to_json(&c.whoami().await.map_err(err)?)
    }

    #[napi]
    pub async fn revoke(&self, target: String) -> napi::Result<String> {
        let c = self.inner.clone();
        c.revoke(&target).await.map_err(err)
    }

    #[napi]
    pub async fn policies(&self) -> napi::Result<String> {
        let c = self.inner.clone();
        to_json(&c.policies().await.map_err(err)?)
    }

    #[napi]
    pub async fn set_policy(&self, name: String, policy_json: String) -> napi::Result<String> {
        let c = self.inner.clone();
        let p: Policy = serde_json::from_str(&policy_json)
            .map_err(|e| err(ClientError::Config(format!("invalid policy: {e}"))))?;
        to_json(&c.set_policy(&name, &p).await.map_err(err)?)
    }

    #[napi]
    pub async fn audit(&self, limit: u32) -> napi::Result<String> {
        let c = self.inner.clone();
        to_json(&c.audit(limit).await.map_err(err)?)
    }

    #[napi]
    pub async fn org_record(&self, org: String) -> napi::Result<String> {
        let c = self.inner.clone();
        to_json(&c.org_record(&org).await.map_err(err)?)
    }
}

#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
