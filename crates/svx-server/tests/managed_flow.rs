//! Managed Mode end to end: the scenarios from the product specification
//! (§13, §29, §35) against the real service, key agent and IdPs.

mod common;

use std::io::Cursor;

use common::*;
use svx_core::crypto::{KemSecretKey, SigningKey, os_rng};
use svx_protocol::admin::AuditPage;
use svx_protocol::{
    AgentReleaseRequest, AgentReleaseResponse, DenyReason, Grant, KeyKindWire, KeyStatus, Policy,
    ProtocolError, ReleaseSession, SignedGrant,
};

macro_rules! world {
    () => {
        match World::new().await {
            Some(w) => w,
            None => return,
        }
    };
}

fn denied(r: Result<Vec<u8>, ProtocolError>) -> DenyReason {
    match r {
        Err(ProtocolError::Denied(d)) => d,
        Err(e) => panic!("expected a denial, got error {e}"),
        Ok(_) => panic!("expected a denial, got plaintext"),
    }
}

async fn audit(w: &World, org: &str, admin: &str) -> AuditPage {
    let t = w.token(org, admin, "audit").await;
    w.client
        .get_json_auth(
            &w.service_url,
            &format!("/v1/admin/orgs/{org}/audit?limit=1000"),
            &t,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn alice_authorized_decrypts_and_is_audited() {
    let w = world!();
    let file = w.pack();
    let pt = w.open_as(&file, EXAMPLE, "alice").await.unwrap();
    assert_eq!(pt, SECRET);

    let ex = audit(&w, EXAMPLE, "example-admin").await;
    assert!(ex.chain_valid);
    let e = ex
        .entries
        .iter()
        .find(|e| e.event == "decryption_authorized")
        .expect("recipient audit");
    assert_eq!(e.subject.as_deref(), Some("alice"));

    // The sender sees the access, pseudonymously.
    let ac = audit(&w, ACME, "acme-admin").await;
    assert!(ac.chain_valid);
    let e = ac
        .entries
        .iter()
        .find(|e| e.event == "decryption_authorized")
        .expect("sender audit");
    assert!(e.subject.as_deref().unwrap().starts_with("anon:"));

    // No secrets in audit records.
    let dump =
        serde_json::to_string(&ex.entries).unwrap() + &serde_json::to_string(&ac.entries).unwrap();
    assert!(!dump.contains("FICTIONAL"));
    assert!(!dump.contains("eyJ"), "a JWT leaked into the audit log");
    assert!(!dump.contains("evidence.txt"));
}

#[tokio::test]
async fn bob_authenticated_but_not_authorized() {
    let w = world!();
    let file = w.pack();
    assert_eq!(
        denied(w.open_as(&file, EXAMPLE, "bob").await),
        DenyReason::NotAuthorized
    );
    let ex = audit(&w, EXAMPLE, "example-admin").await;
    assert!(
        ex.entries
            .iter()
            .any(|e| e.event == "authorization_failure" && e.subject.as_deref() == Some("bob"))
    );
}

#[tokio::test]
async fn eve_with_wrong_idp_or_no_token_is_denied() {
    let w = world!();
    let file = w.pack();
    // Carol is in an "incident-response" group, but at Acme's IdP.
    assert_eq!(
        denied(w.open_as(&file, ACME, "carol").await),
        DenyReason::NotAuthorized
    );

    let v = svx_core::verify(Cursor::new(&file), &w.trust().await).unwrap();
    let session = ReleaseSession::new();
    for bogus in ["", "not.a.token", "eyJhbGciOiJub25lIn0.e30."] {
        let r = w
            .client
            .release_from_service(&w.service_url, &session, v.head(), bogus)
            .await;
        assert!(
            matches!(r, Err(ProtocolError::Denied(DenyReason::NotAuthorized))),
            "{bogus:?}"
        );
    }
}

#[tokio::test]
async fn token_bound_to_another_key_is_rejected() {
    let w = world!();
    let file = w.pack();
    let v = svx_core::verify(Cursor::new(&file), &w.trust().await).unwrap();
    let s1 = ReleaseSession::new();
    let s2 = ReleaseSession::new();
    // Alice's token is bound to s1; presenting it with s2's key fails.
    let token = w.token(EXAMPLE, "alice", &s1.nonce()).await;
    let r = w
        .client
        .release_from_service(&w.service_url, &s2, v.head(), &token)
        .await;
    assert!(matches!(
        r,
        Err(ProtocolError::Denied(DenyReason::NotAuthorized))
    ));
}

#[tokio::test]
async fn expired_artifacts_are_denied() {
    let w = world!();
    // Signed expiry in the past.
    let old = w.pack_with(&w.acme_sign, now() - 100, Some(now() - 10), POLICY);
    assert_eq!(
        denied(w.open_as(&old, EXAMPLE, "alice").await),
        DenyReason::ExpiredOrRevoked
    );

    // No signed expiry, but the recipient policy limits age to 50 s.
    let admin = w.token(EXAMPLE, "example-admin", "a").await;
    w.put_policy(
        &admin,
        "short-lived",
        &Policy {
            allow_groups: vec!["incident-response".into()],
            max_age_secs: Some(50),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let aged = w.pack_with(&w.acme_sign, now() - 100, None, "short-lived");
    assert_eq!(
        denied(w.open_as(&aged, EXAMPLE, "alice").await),
        DenyReason::ExpiredOrRevoked
    );
    let fresh = w.pack_with(&w.acme_sign, now() - 1, None, "short-lived");
    assert_eq!(w.open_as(&fresh, EXAMPLE, "alice").await.unwrap(), SECRET);
}

#[tokio::test]
async fn revoked_artifact_is_denied_after_revocation() {
    let w = world!();
    let file = w.pack();
    assert_eq!(w.open_as(&file, EXAMPLE, "alice").await.unwrap(), SECRET);
    let aid = hex::encode(svx_core::inspect(Cursor::new(&file)).unwrap().1.artifact_id);

    // A non-admin cannot revoke.
    let carol = w.token(ACME, "carol", "x").await;
    let r: Result<serde_json::Value, _> = w
        .client
        .post_json(
            &w.service_url,
            &format!("/v1/admin/orgs/{ACME}/artifacts/{aid}/revoke"),
            &(),
            Some(&carol),
        )
        .await;
    assert!(r.is_err());

    let admin = w.token(ACME, "acme-admin", "x").await;
    let _: serde_json::Value = w
        .client
        .post_json(
            &w.service_url,
            &format!("/v1/admin/orgs/{ACME}/artifacts/{aid}/revoke"),
            &(),
            Some(&admin),
        )
        .await
        .unwrap();
    assert_eq!(
        denied(w.open_as(&file, EXAMPLE, "alice").await),
        DenyReason::ExpiredOrRevoked
    );
    // Other artifacts are unaffected.
    assert_eq!(
        w.open_as(&w.pack(), EXAMPLE, "alice").await.unwrap(),
        SECRET
    );
}

#[tokio::test]
async fn tampered_and_untrusted_artifacts_are_rejected() {
    let w = world!();
    let file = w.pack();
    let v = svx_core::verify(Cursor::new(&file), &w.trust().await).unwrap();

    // A tampered header (the client would already reject this locally; the
    // service must too).
    let mut head = v.head().clone();
    let n = head.header_region.len();
    head.header_region[n - 1] ^= 1;
    let s = ReleaseSession::new();
    let t = w.token(EXAMPLE, "alice", &s.nonce()).await;
    let r = w
        .client
        .release_from_service(&w.service_url, &s, &head, &t)
        .await;
    assert!(matches!(
        r,
        Err(ProtocolError::Denied(DenyReason::InvalidArtifact))
    ));

    // Mallory signs as "acme-security" with an unregistered key.
    let mallory = SigningKey::generate(&mut os_rng());
    let forged = w.pack_with(&mallory, now(), Some(now() + 600), POLICY);
    let mut trust = svx_core::TrustStore::new();
    trust.add(
        svx_core::format::Identifier::new(ACME).unwrap(),
        mallory.verifying_key(),
    );
    let fv = svx_core::verify(Cursor::new(&forged), &trust).unwrap();
    let s = ReleaseSession::new();
    let t = w.token(EXAMPLE, "alice", &s.nonce()).await;
    let r = w
        .client
        .release_from_service(&w.service_url, &s, fv.head(), &t)
        .await;
    assert!(matches!(
        r,
        Err(ProtocolError::Denied(DenyReason::InvalidArtifact))
    ));
}

#[tokio::test]
async fn revoked_sender_key_is_rejected() {
    let w = world!();
    let file = w.pack();
    let v = svx_core::verify(Cursor::new(&file), &w.trust().await).unwrap();
    let admin = w.token(ACME, "acme-admin", "x").await;
    w.put_key(
        ACME,
        &admin,
        KeyKindWire::Ed25519,
        w.acme_sign.verifying_key().to_bytes(),
        KeyStatus::Revoked,
    )
    .await
    .unwrap();
    // Revocation is terminal.
    assert!(
        w.put_key(
            ACME,
            &admin,
            KeyKindWire::Ed25519,
            w.acme_sign.verifying_key().to_bytes(),
            KeyStatus::Active
        )
        .await
        .is_err()
    );
    let s = ReleaseSession::new();
    let t = w.token(EXAMPLE, "alice", &s.nonce()).await;
    let r = w
        .client
        .release_from_service(&w.service_url, &s, v.head(), &t)
        .await;
    assert!(matches!(
        r,
        Err(ProtocolError::Denied(DenyReason::InvalidArtifact))
    ));
    // And it disappears from the recipient's registry-derived trust.
    assert!(w.trust().await.is_empty());
}

#[tokio::test]
async fn replayed_transactions_are_rejected_by_service_and_agent() {
    let w = world!();
    let file = w.pack();
    let v = svx_core::verify(Cursor::new(&file), &w.trust().await).unwrap();
    let s = ReleaseSession::new();
    let t = w.token(EXAMPLE, "alice", &s.nonce()).await;
    let (_, grant) = w
        .client
        .release_from_service(&w.service_url, &s, v.head(), &t)
        .await
        .unwrap();
    // Service: same txn again.
    let r = w
        .client
        .release_from_service(&w.service_url, &s, v.head(), &t)
        .await;
    assert!(matches!(
        r,
        Err(ProtocolError::Denied(DenyReason::NotAuthorized))
    ));
    // Agent: first use succeeds, second fails.
    w.client
        .release_from_agent(&w.agent_url, &s, v.head(), &t, grant.clone())
        .await
        .unwrap();
    let r = w
        .client
        .release_from_agent(&w.agent_url, &s, v.head(), &t, grant)
        .await;
    assert!(matches!(
        r,
        Err(ProtocolError::Denied(DenyReason::NotAuthorized))
    ));
}

#[tokio::test]
async fn grant_for_another_client_key_is_rejected_by_agent() {
    let w = world!();
    let file = w.pack();
    let v = svx_core::verify(Cursor::new(&file), &w.trust().await).unwrap();
    let s1 = ReleaseSession::new();
    let t1 = w.token(EXAMPLE, "alice", &s1.nonce()).await;
    let (_, grant) = w
        .client
        .release_from_service(&w.service_url, &s1, v.head(), &t1)
        .await
        .unwrap();
    // Present s1's grant with a different session (different key and txn).
    let s2 = ReleaseSession::new();
    let t2 = w.token(EXAMPLE, "alice", &s2.nonce()).await;
    let r = w
        .client
        .release_from_agent(&w.agent_url, &s2, v.head(), &t2, grant)
        .await;
    assert!(matches!(
        r,
        Err(ProtocolError::Denied(DenyReason::NotAuthorized))
    ));
}

/// A fully compromised managed service (it holds the grant key) still
/// cannot obtain the recipient-org share: it can mint a grant for its own
/// ephemeral key, but Alice's ID token is bound to *her* key via the nonce,
/// and it cannot mint Example Corp ID tokens.
#[tokio::test]
async fn compromised_service_cannot_get_org_share() {
    let w = world!();
    let file = w.pack();
    let v = svx_core::verify(Cursor::new(&file), &w.trust().await).unwrap();
    let alice = ReleaseSession::new();
    let alice_token = w.token(EXAMPLE, "alice", &alice.nonce()).await;

    let attacker_key = KemSecretKey::generate(&mut os_rng());
    let h = &v.header;
    let grant = SignedGrant::sign(
        &Grant {
            v: 1,
            service_id: SERVICE_ID.into(),
            artifact_id: h.artifact_id,
            header_hash: *v.header_hash().as_bytes(),
            recipient_org: EXAMPLE.into(),
            issuer: w.example_idp.issuer().into(),
            sub: "alice".into(),
            client_key_id: attacker_key.public_key().key_id(),
            txn: *alice.txn(),
            iat: now(),
            exp: now() + 60,
        },
        &w.service_grant,
    );
    let req = AgentReleaseRequest {
        header_region: v.header_region.clone(),
        id_token: alice_token,
        client_key: attacker_key.public_key().to_bytes(),
        txn: *alice.txn(),
        grant,
    };
    let r: Result<AgentReleaseResponse, _> = w
        .client
        .post_json(&w.agent_url, "/v1/agent/release", &req, None)
        .await;
    assert!(matches!(
        r,
        Err(ProtocolError::Denied(DenyReason::NotAuthorized))
    ));

    // A grant signed by anyone other than the pinned service key is refused.
    let rogue = SigningKey::generate(&mut os_rng());
    let s = ReleaseSession::new();
    let t = w.token(EXAMPLE, "alice", &s.nonce()).await;
    let (_, real) = w
        .client
        .release_from_service(&w.service_url, &s, v.head(), &t)
        .await
        .unwrap();
    let mut g: Grant = serde_json::from_slice(&real.payload).unwrap();
    g.exp = now() + 3600;
    let forged = SignedGrant::sign(&g, &rogue);
    let r = w
        .client
        .release_from_agent(&w.agent_url, &s, v.head(), &t, forged)
        .await;
    assert!(matches!(
        r,
        Err(ProtocolError::Denied(DenyReason::NotAuthorized))
    ));
}

#[tokio::test]
async fn admin_endpoints_require_that_orgs_admin() {
    let w = world!();
    let policy = Policy {
        allow_users: vec!["bob".into()],
        ..Default::default()
    };
    // Bob is a user but not an admin of Example Corp.
    let bob = w.token(EXAMPLE, "bob", "x").await;
    assert!(w.put_policy(&bob, POLICY, &policy).await.is_err());
    // Acme's admin is not Example Corp's admin.
    let acme_admin = w.token(ACME, "acme-admin", "x").await;
    assert!(w.put_policy(&acme_admin, POLICY, &policy).await.is_err());
    // No token at all.
    let r: Result<AuditPage, _> = w
        .client
        .get_json(&w.service_url, &format!("/v1/admin/orgs/{EXAMPLE}/audit"))
        .await;
    assert!(r.is_err());
    // Policy unchanged: Bob still denied, Alice still allowed.
    let file = w.pack();
    assert_eq!(
        denied(w.open_as(&file, EXAMPLE, "bob").await),
        DenyReason::NotAuthorized
    );
    assert_eq!(w.open_as(&file, EXAMPLE, "alice").await.unwrap(), SECRET);
}

#[tokio::test]
async fn org_verification_requires_dns_and_idp() {
    let w = world!();
    use svx_protocol::admin::{RegisterOrgRequest, RegisterOrgResponse, VerifyOrgRequest};
    let reg = RegisterOrgRequest {
        org_id: "squatter".into(),
        display_name: "Squatter".into(),
        domain: "example-corp.example".into(), // already verified by Example Corp
        idp_issuer: w.acme_idp.issuer().into(),
        idp_client_id: w.acme_idp.client_id().into(),
        group_claim: None,
        key_agent_url: None,
    };
    let resp: RegisterOrgResponse = w
        .client
        .post_json(&w.service_url, "/v1/orgs", &reg, None)
        .await
        .unwrap();
    let token = w.token(ACME, "carol", "v").await;
    // No DNS record: refused.
    let r: Result<serde_json::Value, _> = w
        .client
        .post_json(
            &w.service_url,
            "/v1/orgs/squatter/verify",
            &VerifyOrgRequest {
                id_token: token.clone(),
            },
            None,
        )
        .await;
    assert!(r.is_err());
    // Even with the TXT record, the domain already belongs to a verified org.
    w.dns.set(&resp.txt_name, &resp.txt_value);
    let r: Result<serde_json::Value, _> = w
        .client
        .post_json(
            &w.service_url,
            "/v1/orgs/squatter/verify",
            &VerifyOrgRequest { id_token: token },
            None,
        )
        .await;
    assert!(r.is_err());
    // Re-registering a verified org is refused.
    let mut again = reg.clone();
    again.org_id = EXAMPLE.into();
    let r: Result<RegisterOrgResponse, _> = w
        .client
        .post_json(&w.service_url, "/v1/orgs", &again, None)
        .await;
    assert!(r.is_err());
    // Unverified orgs have no registry record.
    let r = w
        .client
        .org_record(&w.service_url, "squatter", &w.registry_key())
        .await;
    assert!(r.is_err());
}

#[tokio::test]
async fn registry_records_are_signed_and_scoped() {
    let w = world!();
    let rec = w
        .client
        .org_record(&w.service_url, EXAMPLE, &w.registry_key())
        .await
        .unwrap();
    assert_eq!(rec.org_id, EXAMPLE);
    assert_eq!(rec.key_agent_url.as_deref(), Some(w.agent_url.as_str()));
    assert_eq!(
        rec.active_kem_key().unwrap().public_key,
        w.example_kem.public_key().to_bytes()
    );
    // Verifying with the wrong registry key fails.
    let wrong = SigningKey::generate(&mut os_rng()).verifying_key();
    assert!(
        w.client
            .org_record(&w.service_url, EXAMPLE, &wrong)
            .await
            .is_err()
    );
}
