//! Domain-control verification via DNS TXT records.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hickory_resolver::proto::rr::RData;

#[async_trait]
pub trait DnsVerifier: Send + Sync {
    /// All TXT strings at `name`. An empty list means "no record".
    async fn txt(&self, name: &str) -> anyhow::Result<Vec<String>>;
}

/// System resolver (hickory, using the host's resolv.conf).
pub struct SystemDns(hickory_resolver::TokioResolver);

impl SystemDns {
    pub fn new() -> anyhow::Result<Self> {
        Ok(SystemDns(
            hickory_resolver::TokioResolver::builder_tokio()?.build()?,
        ))
    }
}

#[async_trait]
impl DnsVerifier for SystemDns {
    async fn txt(&self, name: &str) -> anyhow::Result<Vec<String>> {
        let lookup = match self.0.txt_lookup(name).await {
            Ok(l) => l,
            Err(e) if e.is_no_records_found() => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|part| String::from_utf8_lossy(part).into_owned())
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect())
    }
}

/// In-memory records for tests and local demos.
#[derive(Clone, Default)]
pub struct StaticDns(Arc<Mutex<HashMap<String, Vec<String>>>>);

impl StaticDns {
    pub fn set(&self, name: &str, value: &str) {
        self.0
            .lock()
            .expect("lock")
            .entry(name.to_owned())
            .or_default()
            .push(value.to_owned());
    }
}

#[async_trait]
impl DnsVerifier for StaticDns {
    async fn txt(&self, name: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .0
            .lock()
            .expect("lock")
            .get(name)
            .cloned()
            .unwrap_or_default())
    }
}
