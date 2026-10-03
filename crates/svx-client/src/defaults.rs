//! The service a personal account signs up with, so nobody types a URL or
//! a fingerprint.
//!
//! Release builds bake in the official service at build time
//! (`SVX_OFFICIAL_SERVICE_URL`, `SVX_OFFICIAL_REGISTRY_FINGERPRINT`). For
//! development, `SVX_SERVICE_URL` and `SVX_REGISTRY_FINGERPRINT` at run time
//! take precedence (`svx-demo serve` prints them), with `SVX_DEV=1` for a
//! plain-http loopback stack.

use serde::Serialize;

use crate::error::{ClientError, Result};

/// A managed service and its pinned registry key fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceTarget {
    pub service_url: String,
    /// Registry key fingerprint (64 hex).
    pub registry_key: String,
    /// Plain-http loopback service and dev sign-in allowed.
    pub dev: bool,
}

const OFFICIAL_URL: Option<&str> = option_env!("SVX_OFFICIAL_SERVICE_URL");
const OFFICIAL_FINGERPRINT: Option<&str> = option_env!("SVX_OFFICIAL_REGISTRY_FINGERPRINT");

/// The service to sign up with: the run-time override, else the official
/// one this build was made for.
pub fn service_target() -> Result<ServiceTarget> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    if let (Some(url), Some(fp)) = (env("SVX_SERVICE_URL"), env("SVX_REGISTRY_FINGERPRINT")) {
        return Ok(ServiceTarget {
            service_url: url.trim().to_owned(),
            registry_key: fp.trim().to_owned(),
            dev: env("SVX_DEV").is_some_and(|v| v == "1"),
        });
    }
    match (OFFICIAL_URL, OFFICIAL_FINGERPRINT) {
        (Some(url), Some(fp)) => Ok(ServiceTarget {
            service_url: url.into(),
            registry_key: fp.into(),
            dev: false,
        }),
        _ => Err(ClientError::Config(
            "this build doesn't include a service: set SVX_SERVICE_URL and \
             SVX_REGISTRY_FINGERPRINT (svx-demo serve prints them), or use company setup"
                .into(),
        )),
    }
}
