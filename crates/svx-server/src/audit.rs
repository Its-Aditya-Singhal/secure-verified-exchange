//! Append-only, per-organization hash-chained audit log.
//!
//! ```text
//! hash_n = SHA-256("SVX-1 audit\0" ‖ hash_{n-1} ‖ JSON[org, seq, at, event, subject, artifact, txn, reason])
//! ```
//!
//! Records never contain payloads, keys, shares, tokens or file names.
//! Subjects of *other* organizations are stored as pseudonyms.

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use svx_protocol::admin::AuditEntry;

/// Event names (see `docs/architecture.md` §8).
pub mod event {
    pub const ORG_REGISTERED: &str = "org_registered";
    pub const ORG_VERIFIED: &str = "org_verified";
    pub const ADMIN_ADDED: &str = "admin_added";
    pub const ADMIN_AUTH_FAILURE: &str = "admin_authentication_failure";
    pub const KEY_CHANGED: &str = "key_changed";
    pub const POLICY_CHANGED: &str = "policy_changed";
    pub const ARTIFACT_REGISTERED: &str = "artifact_registered";
    pub const ARTIFACT_SHARED: &str = "artifact_shared";
    pub const ARTIFACT_REVOKED: &str = "artifact_revoked";
    pub const AUTHN_FAILURE: &str = "authentication_failure";
    pub const AUTHZ_FAILURE: &str = "authorization_failure";
    pub const SIGNATURE_FAILURE: &str = "signature_failure";
    pub const ARTIFACT_EXPIRED: &str = "artifact_expired";
    pub const REVOKED_ACCESS: &str = "revoked_artifact_access";
    pub const REPLAY: &str = "replay_detected";
    pub const KEY_RELEASE_FAILURE: &str = "key_release_failure";
    pub const DECRYPTION_AUTHORIZED: &str = "decryption_authorized";
    pub const SUSPICIOUS: &str = "suspicious_repeated_attempts";
}

/// One event to append.
#[derive(Clone, Debug, Default)]
pub struct Record<'a> {
    pub event: &'a str,
    pub subject: Option<String>,
    pub artifact_id: Option<String>,
    pub txn: Option<String>,
    pub reason: Option<String>,
}

/// A stable pseudonym for a user of another organization.
pub fn pseudonym(issuer: &str, sub: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"SVX-1 audit subject\0");
    h.update(issuer.as_bytes());
    h.update([0]);
    h.update(sub.as_bytes());
    format!("anon:{}", hex::encode(&h.finalize()[..12]))
}

#[allow(clippy::too_many_arguments)]
fn chain_hash(
    prev: &[u8],
    org: &str,
    seq: i64,
    at: i64,
    event: &str,
    subject: Option<&str>,
    artifact: Option<&str>,
    txn: Option<&str>,
    reason: Option<&str>,
) -> Vec<u8> {
    let body = serde_json::to_vec(&(org, seq, at, event, subject, artifact, txn, reason))
        .expect("serializes");
    let mut h = Sha256::new();
    h.update(b"SVX-1 audit\0");
    h.update(prev);
    h.update(&body);
    h.finalize().to_vec()
}

/// Append a record to `org`'s log. Serialized per org with an advisory lock.
pub async fn append(db: &PgPool, org: &str, rec: Record<'_>) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(org)
        .execute(&mut *tx)
        .await?;
    let last =
        sqlx::query("SELECT seq, hash FROM audit WHERE org_id = $1 ORDER BY seq DESC LIMIT 1")
            .bind(org)
            .fetch_optional(&mut *tx)
            .await?;
    let (seq, prev): (i64, Vec<u8>) = match last {
        Some(r) => (r.get::<i64, _>("seq") + 1, r.get("hash")),
        None => (1, vec![0u8; 32]),
    };
    let at = svx_protocol::unix_now();
    let hash = chain_hash(
        &prev,
        org,
        seq,
        at,
        rec.event,
        rec.subject.as_deref(),
        rec.artifact_id.as_deref(),
        rec.txn.as_deref(),
        rec.reason.as_deref(),
    );
    sqlx::query(
        "INSERT INTO audit (org_id, seq, at, event, subject, artifact_id, txn, reason, prev_hash, hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(org)
    .bind(seq)
    .bind(at)
    .bind(rec.event)
    .bind(&rec.subject)
    .bind(&rec.artifact_id)
    .bind(&rec.txn)
    .bind(&rec.reason)
    .bind(&prev)
    .bind(&hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Best-effort append: audit failures are logged but do not change the
/// outcome of an already-denied request. (Successful releases use
/// [`append`] directly and fail closed if auditing fails.)
pub async fn note(db: &PgPool, org: &str, rec: Record<'_>) {
    if let Err(e) = append(db, org, rec).await {
        tracing::error!(error = %e, org, "audit append failed");
    }
}

/// The latest `limit` records for `org`, oldest first, with chain check.
pub async fn list(
    db: &PgPool,
    org: &str,
    limit: i64,
) -> Result<(Vec<AuditEntry>, bool), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT seq, at, event, subject, artifact_id, txn, reason, prev_hash, hash FROM audit \
         WHERE org_id = $1 ORDER BY seq DESC LIMIT $2",
    )
    .bind(org)
    .bind(limit)
    .fetch_all(db)
    .await?;
    let mut valid = true;
    let mut out = Vec::with_capacity(rows.len());
    let mut expected_prev: Option<Vec<u8>> = None;
    for r in rows.iter().rev() {
        let seq: i64 = r.get("seq");
        let prev: Vec<u8> = r.get("prev_hash");
        let hash: Vec<u8> = r.get("hash");
        let subject: Option<String> = r.get("subject");
        let artifact: Option<String> = r.get("artifact_id");
        let txn: Option<String> = r.get("txn");
        let reason: Option<String> = r.get("reason");
        let event: String = r.get("event");
        let at: i64 = r.get("at");
        let recomputed = chain_hash(
            &prev,
            org,
            seq,
            at,
            &event,
            subject.as_deref(),
            artifact.as_deref(),
            txn.as_deref(),
            reason.as_deref(),
        );
        if recomputed != hash
            || expected_prev.as_ref().is_some_and(|p| *p != prev)
            || (seq == 1 && prev != [0u8; 32])
        {
            valid = false;
        }
        expected_prev = Some(hash.clone());
        out.push(AuditEntry {
            seq,
            at,
            event,
            subject,
            artifact_id: artifact,
            txn,
            reason,
            hash: hex::encode(&hash),
        });
    }
    Ok((out, valid))
}

/// Count `events` for `(org, subject)` since `since`.
pub async fn count_recent(
    db: &PgPool,
    org: &str,
    subject: &str,
    events: &[&str],
    since: i64,
) -> Result<i64, sqlx::Error> {
    let events: Vec<String> = events.iter().map(|s| s.to_string()).collect();
    sqlx::query_scalar(
        "SELECT count(*) FROM audit WHERE org_id = $1 AND subject = $2 AND at >= $3 AND event = ANY($4)",
    )
    .bind(org)
    .bind(subject)
    .bind(since)
    .bind(&events)
    .fetch_one(db)
    .await
}
