//! Native core of the `svx` Python package (`svx._native`).
//!
//! A deliberately thin layer over [`svx_client`]: every operation is the
//! same code the `svx` CLI runs. Structured results cross the boundary as
//! JSON and errors as `NativeError(kind, message, exit_code, deny_reason)`;
//! the pure-Python package turns those into dataclasses and an exception
//! hierarchy. The GIL is released for all I/O.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde::Serialize;
use svx_client::account::LoginMethod;
use svx_client::login::{print_url, system_browser};
use svx_client::{ClientError, Output, PackOptions, Step, info, keys};
use svx_protocol::Policy;

pyo3::create_exception!(_native, NativeError, PyException);

fn err(e: ClientError) -> PyErr {
    NativeError::new_err((
        e.kind().as_str(),
        e.to_string(),
        e.exit_code(),
        e.deny_reason(),
    ))
}

fn to_json<T: Serialize>(v: &T) -> PyResult<String> {
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

/// Collects plaintext for `open_bytes`; discarded on error.
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

/// Progress callback: `on_step(name, detail)`; exceptions it raises are
/// reported as unraisable and never interrupt the open.
fn progress_fn(cb: Option<Py<PyAny>>) -> impl FnMut(Step) + Send {
    move |s: Step| {
        if let Some(cb) = &cb {
            let detail = match &s {
                Step::SignatureValid { sender } => Some(sender.clone()),
                _ => None,
            };
            Python::attach(|py| {
                if let Err(e) = cb.call1(py, (s.name(), detail)) {
                    e.write_unraisable(py, None);
                }
            });
        }
    }
}

/// Parse the artifact header without verifying anything (JSON).
#[pyfunction]
fn inspect(py: Python<'_>, path: PathBuf) -> PyResult<String> {
    let i = py.detach(|| info::inspect(&path)).map_err(err)?;
    to_json(&i)
}

/// Verify signature and integrity offline against `*.sign.pub` files (JSON).
#[pyfunction]
fn verify(py: Python<'_>, path: PathBuf, trust: Vec<PathBuf>) -> PyResult<String> {
    let v = py
        .detach(|| {
            let t = info::trust_from_files(&trust)?;
            info::verify_with(&path, &t)
        })
        .map_err(err)?;
    to_json(&v)
}

/// Generate `<prefix>.sign.key/.pub`; returns the key ID.
#[pyfunction]
fn generate_signing_key(prefix: PathBuf, owner: &str) -> PyResult<String> {
    keys::generate_signing(&prefix, owner).map_err(err)
}

/// Generate `<prefix>.kem.key/.pub`; returns the key ID.
#[pyfunction]
fn generate_kem_key(prefix: PathBuf, owner: &str) -> PyResult<String> {
    keys::generate_kem(&prefix, owner).map_err(err)
}

#[pyclass(module = "svx._native", frozen)]
struct NativeClient {
    inner: svx_client::Client,
    rt: tokio::runtime::Runtime,
}

impl NativeClient {
    fn block<T: Send>(
        &self,
        py: Python<'_>,
        f: impl std::future::Future<Output = svx_client::Result<T>> + Send,
    ) -> PyResult<T> {
        py.detach(|| self.rt.block_on(f)).map_err(err)
    }
}

#[pymethods]
impl NativeClient {
    #[new]
    #[pyo3(signature = (config=None))]
    fn new(config: Option<PathBuf>) -> PyResult<Self> {
        let inner = svx_client::Client::load(config.as_deref()).map_err(err)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| err(e.into()))?;
        Ok(NativeClient { inner, rt })
    }

    fn config_json(&self) -> PyResult<String> {
        to_json(&self.inner.cfg)
    }

    fn config_path(&self) -> PathBuf {
        self.inner.paths.config.clone()
    }

    fn status(&self, py: Python<'_>, path: PathBuf) -> PyResult<String> {
        let s = self.block(py, self.inner.status(&path))?;
        to_json(&s)
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (path, output_dir, overwrite, dev_user, browser, on_step))]
    fn open(
        &self,
        py: Python<'_>,
        path: PathBuf,
        output_dir: Option<PathBuf>,
        overwrite: bool,
        dev_user: Option<String>,
        browser: bool,
        on_step: Option<Py<PyAny>>,
    ) -> PyResult<String> {
        let output = output_dir.map(|dir| Output::Dir { dir, overwrite });
        let mut progress = progress_fn(on_step);
        let o = self.block(
            py,
            self.inner.open(
                &path,
                output,
                login_method(dev_user, browser),
                &mut progress,
            ),
        )?;
        to_json(&OpenJson::from(&o))
    }

    /// Decrypt into memory. Returns `(result_json, plaintext)`.
    #[pyo3(signature = (path, dev_user, browser, on_step))]
    fn open_bytes<'py>(
        &self,
        py: Python<'py>,
        path: PathBuf,
        dev_user: Option<String>,
        browser: bool,
        on_step: Option<Py<PyAny>>,
    ) -> PyResult<(String, Bound<'py, PyBytes>)> {
        let buf = SharedBuf::default();
        let mut progress = progress_fn(on_step);
        let o = self.block(
            py,
            self.inner.open(
                &path,
                Some(Output::Writer(Box::new(buf.clone()))),
                login_method(dev_user, browser),
                &mut progress,
            ),
        )?;
        let data = std::mem::take(
            &mut *buf
                .0
                .lock()
                .map_err(|_| err(ClientError::Other("buffer poisoned".into())))?,
        );
        Ok((to_json(&OpenJson::from(&o))?, PyBytes::new(py, &data)))
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (input, output, recipient, policy, signing_key, expires_at, classification, description, name, overwrite, register))]
    fn pack(
        &self,
        py: Python<'_>,
        input: PathBuf,
        output: Option<PathBuf>,
        recipient: String,
        policy: String,
        signing_key: PathBuf,
        expires_at: Option<i64>,
        classification: Option<String>,
        description: Option<String>,
        name: Option<String>,
        overwrite: bool,
        register: bool,
    ) -> PyResult<String> {
        let r = self.block(
            py,
            self.inner.pack(PackOptions {
                input,
                output,
                overwrite,
                signing_key: signing_key.into(),
                recipient,
                policy,
                expires_at,
                classification,
                description,
                name,
                register,
            }),
        )?;
        to_json(&r)
    }

    #[pyo3(signature = (dev_user, browser))]
    fn login(&self, py: Python<'_>, dev_user: Option<String>, browser: bool) -> PyResult<String> {
        let w = self.block(py, self.inner.login(login_method(dev_user, browser)))?;
        to_json(&w)
    }

    fn logout(&self) -> PyResult<bool> {
        self.inner.logout().map_err(err)
    }

    fn whoami(&self, py: Python<'_>) -> PyResult<String> {
        let w = self.block(py, self.inner.whoami())?;
        to_json(&w)
    }

    fn revoke(&self, py: Python<'_>, target: String) -> PyResult<String> {
        self.block(py, self.inner.revoke(&target))
    }

    fn policies(&self, py: Python<'_>) -> PyResult<String> {
        let p = self.block(py, self.inner.policies())?;
        to_json(&p)
    }

    fn set_policy(&self, py: Python<'_>, name: String, policy_json: &str) -> PyResult<String> {
        let p: Policy = serde_json::from_str(policy_json)
            .map_err(|e| err(ClientError::Config(format!("invalid policy: {e}"))))?;
        let p = self.block(py, self.inner.set_policy(&name, &p))?;
        to_json(&p)
    }

    fn audit(&self, py: Python<'_>, limit: u32) -> PyResult<String> {
        let a = self.block(py, self.inner.audit(limit))?;
        to_json(&a)
    }

    fn org_record(&self, py: Python<'_>, org: String) -> PyResult<String> {
        let r = self.block(py, self.inner.org_record(&org))?;
        to_json(&r)
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

#[pymodule]
#[pyo3(name = "_native")]
fn svx_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("NativeError", m.py().get_type::<NativeError>())?;
    m.add_class::<NativeClient>()?;
    m.add_function(wrap_pyfunction!(inspect, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(generate_signing_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_kem_key, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
