//! Authorization policy documents.
//!
//! A policy is defined by the **recipient** organization and referenced by
//! name from the artifact's signed `policy_ref`. Evaluation is default-deny:
//! a user is allowed only if they match `allow_users` or `allow_groups`, and
//! every other configured constraint holds.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Subjects (`sub` claims) explicitly allowed.
    #[serde(default)]
    pub allow_users: Vec<String>,
    /// Groups (from the org's configured group claim) allowed.
    #[serde(default)]
    pub allow_groups: Vec<String>,
    /// If non-empty, the token's `acr` must be one of these values
    /// (e.g. a phishing-resistant MFA level).
    #[serde(default)]
    pub require_acr: Vec<String>,
    /// Maximum artifact age, measured from its signed `created_at`. Can only
    /// shorten the sender's signed expiry, never extend it.
    #[serde(default)]
    pub max_age_secs: Option<i64>,
    /// Access window (Unix seconds).
    #[serde(default)]
    pub not_before: Option<i64>,
    #[serde(default)]
    pub not_after: Option<i64>,
}

/// Upper bounds to keep policy documents small.
pub const MAX_POLICY_ENTRIES: usize = 1024;

impl Policy {
    pub fn validate(&self) -> Result<(), String> {
        if self.allow_users.is_empty() && self.allow_groups.is_empty() {
            return Err("policy must allow at least one user or group".into());
        }
        if self.allow_users.len() + self.allow_groups.len() + self.require_acr.len()
            > MAX_POLICY_ENTRIES
        {
            return Err("policy too large".into());
        }
        if self.max_age_secs.is_some_and(|a| a <= 0) {
            return Err("max_age_secs must be positive".into());
        }
        if let (Some(a), Some(b)) = (self.not_before, self.not_after) {
            if a >= b {
                return Err("not_before must be before not_after".into());
            }
        }
        Ok(())
    }
}
