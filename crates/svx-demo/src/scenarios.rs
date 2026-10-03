//! The scripted scenarios. Every step goes through `svx_client` — the same
//! code the `svx` CLI and the SDKs use — except where the point of the
//! scenario is an attacker bypassing the client.

use std::io::Cursor;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use svx_client::account::{self, LoginMethod};
use svx_client::pack::{ManagedPack, register};
use svx_client::{ClientConfig, ClientError, OpenOutcome, Output, Step, admin, info};
use svx_core::format::Identifier;
use svx_mock_idp::{Config, MockIdp, User};
use svx_protocol::{DenyReason, ProtocolError, ReleaseSession};
use svx_testkit::{ACME, EXAMPLE, POLICY, World, now};

use crate::ui::Ui;

/// Fictional incident report shared by Acme Security with Example Corp.
const REPORT: &str = "\
FICTIONAL DEMO DATA — Acme Security incident report IR-2026-0412
Customer: Example Corp
Summary: credential-phishing campaign targeting Example Corp finance staff.
Indicator: login-examplecorp.invalid (lookalike domain)
Indicator: 203.0.113.47 (documentation range; stand-in for attacker infra)
Recommended action: block indicators, reset affected credentials, notify staff.
";
/// A line that must never appear in the ciphertext.
const MARKER: &str = "credential-phishing campaign";

async fn open_as(
    w: &World,
    cfg: &ClientConfig,
    user: &str,
    file: &Path,
    out: &Path,
) -> (svx_client::Result<OpenOutcome>, Vec<Step>) {
    let mut steps = Vec::new();
    let auth = match account::authenticator(cfg, &w.client, LoginMethod::Dev(user.into())) {
        Ok(a) => a,
        Err(e) => return (Err(e), steps),
    };
    let mut progress = |s: Step| steps.push(s);
    let r = svx_client::open(
        cfg,
        &w.client,
        auth.as_ref(),
        file,
        Output::Dir {
            dir: out.to_path_buf(),
            overwrite: false,
        },
        &mut progress,
    )
    .await;
    (r, steps)
}

fn describe(r: &svx_client::Result<OpenOutcome>) -> String {
    match r {
        Ok(o) => format!(
            "opened {}",
            o.path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        Err(e) => format!("{} ({})", e.kind().as_str(), e),
    }
}

fn narrate_steps(ui: &Ui, steps: &[Step]) {
    for s in steps {
        ui.sys(match s {
            Step::Verifying => "Verifying artifact...".to_owned(),
            Step::SignatureValid { sender } => format!("Signature valid (sender: {sender})"),
            Step::Connecting => "Connecting to SVX service...".to_owned(),
            Step::Authenticating => "Authenticating with the organization's IdP...".to_owned(),
            Step::CheckingAuthorization => "Checking authorization...".to_owned(),
            Step::AccessApproved => "Access approved".to_owned(),
            Step::Decrypting => "Decrypting locally...".to_owned(),
        });
    }
}

fn dir_is_empty(p: &Path) -> bool {
    match std::fs::read_dir(p) {
        Ok(mut d) => d.next().is_none(),
        Err(_) => true,
    }
}

async fn admin_login(w: &World, cfg: &ClientConfig, user: &str, session: &Path) -> Result<String> {
    let auth = account::authenticator(cfg, &w.client, LoginMethod::Dev(user.into()))?;
    account::login(cfg, auth.as_ref(), session).await?;
    Ok(account::bearer(session)?)
}

pub async fn run_all(w: &World, dir: &Path, ui: &Ui) -> Result<()> {
    let acme = w.client_config(ACME);
    let example = w.client_config(EXAMPLE);
    let mut eve_cfg = w.client_config(EXAMPLE);
    eve_cfg.org_id = "eve-labs".into();

    ui.say(format!("Managed service:  {}", w.service_url));
    ui.say(format!("Example Corp key agent: {}", w.agent_url));
    ui.say(format!("Acme IdP:         {}", w.acme_idp.issuer()));
    ui.say(format!("Example Corp IdP: {}", w.example_idp.issuer()));
    ui.say(format!(
        "Example Corp policy '{POLICY}': only the incident-response group may open"
    ));

    // 1. Carol packs and registers the report.
    ui.scenario("1", "Carol (Acme) sends an incident report to Example Corp");
    let carol_dir = dir.join("carol");
    std::fs::create_dir_all(&carol_dir)?;
    let input = carol_dir.join("incident-report.txt");
    std::fs::write(&input, REPORT)?;
    let artifact = carol_dir.join("incident-report.svx");
    let carol_bearer = admin_login(w, &acme, "carol", &carol_dir.join("session.json"))
        .await
        .context("Carol signing in to Acme's IdP")?;
    ui.say("Carol signs in to Acme's IdP and packs the report for example-corp.");
    ui.say("Recipient and service keys come from the signed registry, not from files.");
    let packed = svx_client::pack::pack(
        &acme,
        &w.client,
        ManagedPack {
            input: &input,
            output: artifact.clone(),
            overwrite: false,
            signing_key: &w.acme_sign,
            sender_org: Identifier::new(ACME)?,
            recipient_org: Identifier::new(EXAMPLE)?,
            policy: Identifier::new(POLICY)?,
            expires_at: Some(now() + 7 * 86_400),
            classification: Some("TLP:AMBER".into()),
            description: Some("Phishing campaign indicators".into()),
            name: "incident-report.txt".into(),
            content_type: None,
            chunk_size: None,
        },
    )
    .await
    .context("packing the report")?;
    register(&acme, &w.client, &artifact, &carol_bearer)
        .await
        .context("registering the artifact")?;
    let artifact_id = packed.summary.artifact_id;
    ui.sys(format!("Created {}", artifact.display()));
    ui.sys(format!("Artifact ID {}", hex::encode(artifact_id)));
    ui.check(
        "1",
        "Carol packs and registers the report",
        "a signed, encrypted .svx",
        artifact.exists(),
        format!("{} bytes", std::fs::metadata(&artifact)?.len()),
    );

    // 2. Eve intercepts.
    let eve_dir = dir.join("eve");
    std::fs::create_dir_all(&eve_dir)?;
    let eve_copy = eve_dir.join("intercepted.svx");
    std::fs::copy(&artifact, &eve_copy)?;

    ui.scenario("2a", "Eve intercepts the file in transit and looks inside");
    let i = info::inspect(&eve_copy)?;
    ui.sys(format!(
        "UNVERIFIED header: sender {} → recipient {}, policy {}",
        i.sender_org, i.recipient_org, i.policy_ref
    ));
    let bytes = std::fs::read(&eve_copy)?;
    let leaked = bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes());
    ui.say("Eve sees routing metadata only; the content and file names are encrypted.");
    ui.check(
        "2a",
        "Eve inspects the intercepted file",
        "metadata only, no plaintext",
        !leaked,
        if leaked {
            "plaintext found in file!"
        } else {
            "no plaintext in the bytes"
        },
    );

    ui.scenario("2b", "Eve opens it with her own organization's SVX client");
    let (r, steps) = open_as(w, &eve_cfg, "eve", &eve_copy, &eve_dir.join("out")).await;
    narrate_steps(ui, &steps);
    let ok = matches!(r, Err(ClientError::NotRecipient { .. }))
        && !steps.contains(&Step::Authenticating);
    ui.check(
        "2b",
        "Eve opens it as eve-labs",
        "refused locally, before any login",
        ok,
        describe(&r),
    );

    ui.scenario(
        "2c",
        "Eve forges an Example Corp ID token for Alice and calls the API directly",
    );
    let eve_idp = MockIdp::spawn(
        Config {
            client_id: example.idp_client_id.clone(),
            users: vec![User {
                sub: "alice".into(),
                email: Some("alice@fictional.example".into()),
                groups: vec!["incident-response".into()],
                acr: Some("phr".into()),
            }],
            token_ttl_secs: 300,
        },
        "127.0.0.1:0".parse()?,
    )
    .await?;
    let trust = info::registry_trust(&example, &w.client, &eve_copy).await?;
    let verified = svx_core::verify(Cursor::new(&bytes), &trust)?;
    let session = ReleaseSession::new();
    let fake_alice = eve_idp
        .user("alice")
        .cloned()
        .ok_or_else(|| anyhow!("user"))?;
    let mut claims = eve_idp.claims_for(&fake_alice, &session.nonce());
    // Claim to be Example Corp's IdP; signed with Eve's own key.
    claims["iss"] = serde_json::Value::String(example.idp_issuer.clone());
    let forged = eve_idp.mint(&claims);
    ui.say("The token names Example Corp's issuer, user alice and the right group,");
    ui.say("but it is signed with Eve's key, not Example Corp's.");
    let r = w
        .client
        .release(
            &w.service_url,
            &w.agent_url,
            &session,
            verified.head(),
            &forged,
        )
        .await;
    let observed = match &r {
        Ok(_) => "KEY SHARES RELEASED".to_owned(),
        Err(e) => format!("refused ({e})"),
    };
    ui.sys(&observed);
    ui.check(
        "2c",
        "Eve presents a forged token",
        "service refuses, no share released",
        matches!(r, Err(ProtocolError::Denied(_))),
        observed,
    );

    ui.scenario("2d", "Eve tries to sign in to Example Corp's IdP");
    let (r, steps) = open_as(w, &example, "eve", &eve_copy, &eve_dir.join("out")).await;
    narrate_steps(ui, &steps);
    ui.check(
        "2d",
        "Eve signs in to Example Corp's IdP",
        "login fails, nothing released",
        matches!(r, Err(ClientError::Login(_))) && dir_is_empty(&eve_dir.join("out")),
        describe(&r),
    );

    // 3. Alice.
    ui.scenario(
        "3",
        "Alice (Example Corp, incident-response) opens the report",
    );
    let alice_out = dir.join("alice");
    let (r, steps) = open_as(w, &example, "alice", &artifact, &alice_out).await;
    narrate_steps(ui, &steps);
    let mut ok = false;
    let mut observed = describe(&r);
    if let Ok(o) = &r {
        let p = o.path.clone().unwrap_or_default();
        let content = std::fs::read_to_string(&p).unwrap_or_default();
        ok = content == REPORT && private(&p);
        observed = format!(
            "{} ({}, content {})",
            observed,
            if private(&p) {
                "owner-only"
            } else {
                "NOT owner-only"
            },
            if content == REPORT {
                "matches"
            } else {
                "DIFFERS"
            }
        );
        if let Some(c) = &o.manifest.classification {
            ui.sys(format!("Classification: {c}"));
        }
    }
    ui.check(
        "3",
        "Alice opens the report",
        "approved, plaintext matches",
        ok,
        observed,
    );

    // 4. Bob.
    ui.scenario("4", "Bob (Example Corp, staff only) opens the report");
    let bob_out = dir.join("bob");
    let (r, steps) = open_as(w, &example, "bob", &artifact, &bob_out).await;
    narrate_steps(ui, &steps);
    ui.check(
        "4",
        "Bob opens the report",
        "denied: not authorized, nothing written",
        matches!(r, Err(ClientError::Denied(DenyReason::NotAuthorized))) && dir_is_empty(&bob_out),
        describe(&r),
    );

    // 5. Tampered.
    ui.scenario("5", "Someone flips one byte of the file in transit");
    let tampered = dir.join("tampered.svx");
    let mut t = std::fs::read(&artifact)?;
    let mid = t.len() / 2;
    t[mid] ^= 0x01;
    std::fs::write(&tampered, &t)?;
    let (r, steps) = open_as(w, &example, "alice", &tampered, &dir.join("alice-tampered")).await;
    narrate_steps(ui, &steps);
    ui.check(
        "5",
        "Alice opens a tampered copy",
        "rejected locally, never reaches login",
        matches!(r, Err(ClientError::Rejected(_))) && !steps.contains(&Step::Authenticating),
        describe(&r),
    );

    // 6. Expired.
    ui.scenario("6a", "Alice opens an artifact that expired yesterday");
    let expired = dir.join("expired.svx");
    std::fs::write(
        &expired,
        w.pack_with(
            &w.acme_sign,
            now() - 2 * 86_400,
            Some(now() - 86_400),
            POLICY,
        ),
    )?;
    let (r, steps) = open_as(w, &example, "alice", &expired, &dir.join("alice-expired")).await;
    narrate_steps(ui, &steps);
    ui.check(
        "6a",
        "Alice opens an expired artifact",
        "refused locally",
        matches!(r, Err(ClientError::Expired)) && !steps.contains(&Step::Authenticating),
        describe(&r),
    );

    ui.scenario(
        "6b",
        "A modified client skips the local expiry check and asks for keys anyway",
    );
    let exp_bytes = std::fs::read(&expired)?;
    let v = svx_core::verify(Cursor::new(&exp_bytes), &trust)?;
    let session = ReleaseSession::new();
    let token = w.token(EXAMPLE, "alice", &session.nonce()).await;
    let r = w
        .client
        .release(&w.service_url, &w.agent_url, &session, v.head(), &token)
        .await;
    let observed = match &r {
        Ok(_) => "KEY SHARES RELEASED".to_owned(),
        Err(e) => format!("refused ({e})"),
    };
    ui.sys(&observed);
    ui.check(
        "6b",
        "Direct key request for an expired artifact",
        "service refuses: expired",
        matches!(r, Err(ProtocolError::Denied(DenyReason::ExpiredOrRevoked))),
        observed,
    );

    // 7. Revoked.
    ui.scenario(
        "7",
        "Example Corp's admin revokes the report; Alice tries again",
    );
    let admin_dir = dir.join("example-admin");
    std::fs::create_dir_all(&admin_dir)?;
    let admin_bearer = admin_login(
        w,
        &example,
        "example-admin",
        &admin_dir.join("session.json"),
    )
    .await?;
    admin::revoke(&example, &w.client, &admin_bearer, &artifact_id).await?;
    ui.sys(format!("Revoked {}", hex::encode(artifact_id)));
    let (r, steps) = open_as(w, &example, "alice", &artifact, &dir.join("alice-again")).await;
    narrate_steps(ui, &steps);
    ui.say("Note: revocation stops future access; it cannot recall Alice's earlier copy.");
    ui.check(
        "7",
        "Alice opens the revoked report",
        "denied: revoked",
        matches!(r, Err(ClientError::Denied(DenyReason::ExpiredOrRevoked))),
        describe(&r),
    );

    // 8. Audit.
    ui.scenario("8", "Example Corp's admin reviews the audit trail");
    let page = admin::audit(&example, &w.client, &admin_bearer, 100).await?;
    let mut entries = page.entries.clone();
    entries.sort_by_key(|e| e.seq);
    for e in &entries {
        ui.sys(format!(
            "#{:<3} {:<26} {:<16} {}",
            e.seq,
            e.event,
            e.subject.as_deref().unwrap_or("-"),
            e.reason.as_deref().unwrap_or("")
        ));
    }
    let has = |ev: &str| entries.iter().any(|e| e.event == ev);
    let wanted = [
        "decryption_authorized",
        "authorization_failure",
        "artifact_revoked",
        "revoked_artifact_access",
    ];
    let missing: Vec<_> = wanted.iter().filter(|e| !has(e)).collect();
    ui.sys(format!(
        "Hash chain: {}",
        if page.chain_valid { "valid" } else { "BROKEN" }
    ));
    ui.check(
        "8",
        "Audit trail records every decision",
        "approvals, denials, revocation; chain valid",
        page.chain_valid && missing.is_empty(),
        if missing.is_empty() {
            format!("{} events, chain valid={}", entries.len(), page.chain_valid)
        } else {
            format!("missing events {missing:?}")
        },
    );

    // 9. A folder.
    ui.scenario(
        "9",
        "Carol sends a folder of evidence; Alice opens it as a folder",
    );
    let evidence = carol_dir.join("ir-2026-0412-evidence");
    std::fs::create_dir_all(evidence.join("indicators"))?;
    std::fs::write(evidence.join("report.txt"), REPORT)?;
    std::fs::write(
        evidence.join("indicators/domains.txt"),
        "login-examplecorp.invalid\n",
    )?;
    let input = svx_client::pack::prepare_input(&evidence, None)?;
    ui.say("The folder is zipped and marked as a folder inside the encrypted manifest.");
    let folder_artifact = carol_dir.join("ir-2026-0412-evidence.svx");
    svx_client::pack::pack(
        &acme,
        &w.client,
        ManagedPack {
            input: &input.path,
            output: folder_artifact.clone(),
            overwrite: false,
            signing_key: &w.acme_sign,
            sender_org: Identifier::new(ACME)?,
            recipient_org: Identifier::new(EXAMPLE)?,
            policy: Identifier::new(POLICY)?,
            expires_at: Some(now() + 7 * 86_400),
            classification: Some("TLP:AMBER".into()),
            description: None,
            name: input.name.clone(),
            content_type: input.content_type.clone(),
            chunk_size: None,
        },
    )
    .await
    .context("packing the folder")?;
    ui.sys(format!("Created {}", folder_artifact.display()));
    let folder_out = dir.join("alice-folder");
    let (r, steps) = open_as(w, &example, "alice", &folder_artifact, &folder_out).await;
    narrate_steps(ui, &steps);
    let (ok, observed) = match &r {
        Ok(o) => {
            let p = o.path.clone().unwrap_or_default();
            let same = std::fs::read_to_string(p.join("report.txt")).unwrap_or_default() == REPORT
                && p.join("indicators/domains.txt").is_file();
            let only_folder = std::fs::read_dir(&folder_out).map_or(0, |d| d.count()) == 1;
            (
                o.is_folder() && same && only_folder && private(&p),
                format!(
                    "{} (folder {}, {})",
                    describe(&r),
                    if same { "matches" } else { "DIFFERS" },
                    if private(&p) {
                        "owner-only"
                    } else {
                        "NOT owner-only"
                    }
                ),
            )
        }
        Err(_) => (false, describe(&r)),
    };
    ui.check(
        "9",
        "Alice opens a folder",
        "approved, extracted folder matches",
        ok,
        observed,
    );
    Ok(())
}

#[cfg(unix)]
fn private(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o077 == 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn private(p: &Path) -> bool {
    p.exists()
}
