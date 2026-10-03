//! Administration and onboarding commands. Each is a thin wrapper over
//! `svx-client`, which holds the rules (key order, agent check, keychain).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use svx_client::account::{LoginMethod, WhoAmI};
use svx_client::admin::AuditQuery;
use svx_client::keyadmin::{ExportedKemKey, NewSigningKey};
use svx_client::keystore::KeyRef;
use svx_client::onboard::{self, OnboardRequest, PendingOrg};
use svx_client::setup::SetupPreview;
use svx_protocol::admin::{AuditEntry, AuditPage, OrgOverview, UpdateOrgRequest};
use svx_protocol::{KeyEntry, KeyStatus, Policy};

use crate::{App, AppError, Prefs, Result, prefs_path};

/// What the admin screen shows.
#[derive(Clone, Debug, Serialize)]
pub struct AdminOverview {
    pub org: OrgOverview,
    pub agent: Option<AgentStatus>,
    /// Key ID of the signing key this computer uses, if it loads.
    pub this_computer_key: Option<String>,
    /// Why this computer's signing key can't be used, if it can't.
    pub signing_key_problem: Option<String>,
    pub pending_encryption_key: Option<ExportedKemKey>,
}

/// The organization's key agent as seen from here.
#[derive(Clone, Debug, Serialize)]
pub struct AgentStatus {
    pub url: String,
    pub reachable: bool,
    pub error: Option<String>,
    /// Hex IDs of the keys the agent holds.
    pub key_ids: Vec<String>,
}

/// Fields an administrator can change (empty strings mean "unchanged").
#[derive(Clone, Debug, Default, Deserialize)]
pub struct OrgSettingsForm {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub key_agent_url: Option<String>,
    #[serde(default)]
    pub remove_key_agent: bool,
}

/// Most audit records written to one CSV export.
const MAX_EXPORT: usize = 10_000;

impl App {
    fn update_prefs(&self, f: impl FnOnce(&mut Prefs)) {
        let mut p = self.prefs.lock().unwrap();
        f(&mut p);
        // Preferences are a convenience: failing to save them is not an error.
        let _ = p.save(&prefs_path(&self.paths));
    }

    // ----- Onboarding a new organization -----

    /// Register a new organization; the returned DNS record must be created
    /// before [`App::onboard_complete`].
    pub async fn onboard_register(&self, req: OnboardRequest) -> Result<PendingOrg> {
        let pending = onboard::register(req).await?;
        let keep = pending.clone();
        self.update_prefs(|p| p.pending_org = Some(keep));
        Ok(pending)
    }

    /// Verify the DNS record and sign in; the person becomes the first
    /// administrator and the configuration is saved.
    pub async fn onboard_complete(
        &self,
        login: LoginMethod,
        replace: bool,
    ) -> Result<(SetupPreview, WhoAmI)> {
        let pending = self
            .prefs
            .lock()
            .unwrap()
            .pending_org
            .clone()
            .ok_or_else(|| AppError::other("no organization registration in progress"))?;
        let r = onboard::complete(&self.paths, &pending, login, replace).await?;
        self.update_prefs(|p| p.pending_org = None);
        self.reload();
        Ok(r)
    }

    pub fn onboard_cancel(&self) {
        self.update_prefs(|p| p.pending_org = None);
    }

    // ----- Overview and settings -----

    pub async fn admin_overview(&self) -> Result<AdminOverview> {
        let c = self.client()?;
        let org = c.org_overview().await?;
        let agent = match &org.key_agent_url {
            Some(url) => Some(match c.agent_keys(url).await {
                Ok(k) => AgentStatus {
                    url: url.clone(),
                    reachable: k.org_id == org.org_id,
                    error: (k.org_id != org.org_id)
                        .then(|| format!("this key agent serves {}", k.org_id)),
                    key_ids: k.keys.iter().map(|k| hex::encode(k.key_id)).collect(),
                },
                Err(e) => AgentStatus {
                    url: url.clone(),
                    reachable: false,
                    error: Some(e.to_string()),
                    key_ids: vec![],
                },
            }),
            None => None,
        };
        let prefs = self.prefs.lock().unwrap().clone();
        let (this_computer_key, signing_key_problem) = match prefs.signing_key.as_deref() {
            None => (None, None),
            Some(s) => match KeyRef::parse(s)
                .and_then(|r| svx_client::keyadmin::check_signing_key(c.secrets.as_ref(), &r))
            {
                Ok(id) => (Some(id), None),
                Err(e) => (None, Some(e.to_string())),
            },
        };
        Ok(AdminOverview {
            org,
            agent,
            this_computer_key,
            signing_key_problem,
            pending_encryption_key: prefs.pending_encryption_key,
        })
    }

    pub async fn update_org(&self, f: OrgSettingsForm) -> Result<()> {
        let trim = |s: Option<String>| s.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
        Ok(self
            .client()?
            .update_org(&UpdateOrgRequest {
                display_name: trim(f.display_name),
                key_agent_url: trim(f.key_agent_url),
                remove_key_agent: f.remove_key_agent,
            })
            .await?)
    }

    pub async fn add_admin(&self, subject: &str) -> Result<()> {
        Ok(self.client()?.add_admin(subject).await?)
    }

    pub async fn remove_admin(&self, subject: &str) -> Result<()> {
        Ok(self.client()?.remove_admin(subject).await?)
    }

    // ----- Policies -----

    pub async fn set_policy(&self, name: &str, policy: Policy) -> Result<Policy> {
        Ok(self.client()?.set_policy(name.trim(), &policy).await?)
    }

    pub async fn delete_policy(&self, name: &str) -> Result<()> {
        Ok(self.client()?.delete_policy(name).await?)
    }

    // ----- Audit -----

    pub async fn audit_page(
        &self,
        limit: u32,
        before_seq: Option<i64>,
        event: Option<String>,
    ) -> Result<AuditPage> {
        Ok(self
            .client()?
            .audit_page(&AuditQuery {
                limit: limit.clamp(1, 1000),
                before_seq,
                event,
            })
            .await?)
    }

    /// Write the audit trail (newest first, up to 10,000 records) as CSV to
    /// `path`, a location the user chose. Returns the number of records.
    pub async fn export_audit_csv(&self, path: &Path, event: Option<String>) -> Result<usize> {
        let c = self.client()?;
        let mut all: Vec<AuditEntry> = Vec::new();
        let mut before = None;
        let mut chain_valid = true;
        while all.len() < MAX_EXPORT {
            let page = c
                .audit_page(&AuditQuery {
                    limit: 1000,
                    before_seq: before,
                    event: event.clone(),
                })
                .await?;
            chain_valid &= page.chain_valid;
            let Some(last) = page.entries.last() else {
                break;
            };
            before = Some(last.seq);
            let n = page.entries.len();
            all.extend(page.entries);
            if n < 1000 {
                break;
            }
        }
        all.truncate(MAX_EXPORT);
        let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
        writeln!(
            out,
            "seq,time_utc,event,subject,artifact_id,txn,reason,hash,chain_valid"
        )?;
        for e in &all {
            let row = [
                e.seq.to_string(),
                time_utc(e.at),
                e.event.clone(),
                e.subject.clone().unwrap_or_default(),
                e.artifact_id.clone().unwrap_or_default(),
                e.txn.clone().unwrap_or_default(),
                e.reason.clone().unwrap_or_default(),
                e.hash.clone(),
                chain_valid.to_string(),
            ];
            let cells: Vec<String> = row.iter().map(|c| csv_cell(c)).collect();
            writeln!(out, "{}", cells.join(","))?;
        }
        out.flush()?;
        self.produced.lock().unwrap().insert(path.to_path_buf());
        Ok(all.len())
    }

    // ----- Keys -----

    /// Create this computer's signing key in the keychain, register it, and
    /// use it for sending from now on.
    pub async fn create_signing_key(&self) -> Result<NewSigningKey> {
        let k = self.client()?.create_signing_key().await?;
        let r = k.key_ref.clone();
        self.update_prefs(|p| p.signing_key = Some(r));
        Ok(k)
    }

    /// Move a signing key file into the keychain and use it from now on.
    pub fn import_signing_key(&self, path: &Path) -> Result<NewSigningKey> {
        let k = self.client()?.import_signing_key(path)?;
        let r = k.key_ref.clone();
        self.update_prefs(|p| p.signing_key = Some(r));
        Ok(k)
    }

    /// Register another sender's `*.sign.pub`.
    pub async fn register_signing_public(&self, path: &Path) -> Result<KeyEntry> {
        Ok(self.client()?.register_signing_public(path).await?)
    }

    /// Write a new encryption key for the key agent into `dir`.
    pub fn export_encryption_key(&self, dir: &Path) -> Result<ExportedKemKey> {
        let k = self.client()?.export_encryption_key(dir)?;
        self.produced.lock().unwrap().insert(k.secret_file.clone());
        let keep = k.clone();
        self.update_prefs(|p| p.pending_encryption_key = Some(keep));
        Ok(k)
    }

    /// Activate the exported encryption key (only once the agent holds it).
    pub async fn activate_encryption_key(&self) -> Result<KeyEntry> {
        let pending = self
            .prefs
            .lock()
            .unwrap()
            .pending_encryption_key
            .clone()
            .ok_or_else(|| AppError::other("no new encryption key to activate"))?;
        let e = self
            .client()?
            .activate_encryption_key(&pending.public_file)
            .await?;
        self.update_prefs(|p| p.pending_encryption_key = None);
        Ok(e)
    }

    pub fn discard_pending_encryption_key(&self) {
        self.update_prefs(|p| p.pending_encryption_key = None);
    }

    /// Retire or revoke a key.
    pub async fn set_key_status(&self, key_id: &str, status: KeyStatus) -> Result<KeyEntry> {
        Ok(self.client()?.set_key_status(key_id, status).await?)
    }

    /// A path for files written by the app (the CSV export picker uses it).
    pub fn default_export_dir(&self) -> PathBuf {
        self.paths
            .config
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }
}

fn time_utc(t: i64) -> String {
    // RFC 3339 without pulling in a date library: seconds since the epoch
    // are converted by civil-from-days (Howard Hinnant's algorithm).
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// One CSV cell: quoted, with formula-like values neutralized so a
/// spreadsheet never runs them.
fn csv_cell(v: &str) -> String {
    let v = if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{v}")
    } else {
        v.to_owned()
    };
    format!("\"{}\"", v.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_and_cells() {
        assert_eq!(time_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(time_utc(1_791_000_000), "2026-10-03T04:00:00Z");
        assert_eq!(time_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("=HYPERLINK(1)"), "\"'=HYPERLINK(1)\"");
    }
}
