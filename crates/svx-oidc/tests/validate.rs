use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use svx_mock_idp::{Config, MockIdp, User};
use svx_oidc::{IssuerConfig, OidcError, Validator};
use svx_protocol::ManagedClient;
use svx_protocol::oidc_login::dev_auto_login;

fn users() -> Vec<User> {
    vec![User {
        sub: "alice".into(),
        email: Some("alice@example-corp.example".into()),
        groups: vec!["incident-response".into(), "staff".into()],
        acr: Some("phr".into()),
    }]
}

async fn idp(client_id: &str) -> MockIdp {
    MockIdp::spawn(
        Config {
            client_id: client_id.into(),
            users: users(),
            token_ttl_secs: 300,
        },
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .unwrap()
}

fn cfg(idp: &MockIdp) -> IssuerConfig {
    IssuerConfig {
        issuer: idp.issuer().into(),
        client_id: idp.client_id().into(),
        group_claim: "groups".into(),
    }
}

fn now() -> i64 {
    svx_protocol::unix_now()
}

fn edit(mut v: Value, f: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Value {
    f(v.as_object_mut().unwrap());
    v
}

#[tokio::test]
async fn pkce_flow_and_validation() {
    let a = idp("svx-example-corp").await;
    let client = ManagedClient::new(true).unwrap();
    let token = dev_auto_login(&client, a.issuer(), a.client_id(), "alice", "n-123")
        .await
        .unwrap();
    let v = Validator::new(true).unwrap();
    let id = v.validate(&cfg(&a), &token, Some("n-123")).await.unwrap();
    assert_eq!(id.sub, "alice");
    assert_eq!(id.groups, vec!["incident-response", "staff"]);
    assert_eq!(id.acr.as_deref(), Some("phr"));
    assert_eq!(
        v.validate(&cfg(&a), &token, Some("other")).await,
        Err(OidcError::Nonce)
    );
    assert_eq!(
        Validator::unverified_issuer(&token).as_deref(),
        Some(a.issuer())
    );

    // Unknown user is refused at the IdP.
    assert!(
        dev_auto_login(&client, a.issuer(), a.client_id(), "mallory", "n")
            .await
            .is_err()
    );
    // Wrong client_id is refused at the IdP.
    assert!(
        dev_auto_login(&client, a.issuer(), "other-client", "alice", "n")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_bad_claims() {
    let a = idp("svx-example-corp").await;
    let v = Validator::new(true).unwrap();
    let c = cfg(&a);
    let base = a.claims_for(a.user("alice").unwrap(), "n");

    let cases: Vec<(&str, Value)> = vec![
        (
            "wrong issuer",
            edit(base.clone(), |m| {
                m.insert("iss".into(), json!("https://evil.example"));
            }),
        ),
        (
            "wrong audience",
            edit(base.clone(), |m| {
                m.insert("aud".into(), json!("someone-else"));
            }),
        ),
        (
            "expired",
            edit(base.clone(), |m| {
                m.insert("exp".into(), json!(now() - 3600));
            }),
        ),
        (
            "not yet valid",
            edit(base.clone(), |m| {
                m.insert("nbf".into(), json!(now() + 3600));
            }),
        ),
        (
            "missing sub",
            edit(base.clone(), |m| {
                m.remove("sub");
            }),
        ),
        (
            "empty sub",
            edit(base.clone(), |m| {
                m.insert("sub".into(), json!(""));
            }),
        ),
        (
            "missing iat",
            edit(base.clone(), |m| {
                m.remove("iat");
            }),
        ),
    ];
    for (name, claims) in cases {
        let t = a.mint(&claims);
        assert!(
            v.validate(&c, &t, Some("n")).await.is_err(),
            "{name} accepted"
        );
    }

    let stale = edit(base.clone(), |m| {
        m.insert("iat".into(), json!(now() - 3600));
    });
    assert_eq!(
        v.validate(&c, &a.mint(&stale), Some("n")).await,
        Err(OidcError::Stale)
    );
    let no_nonce = edit(base.clone(), |m| {
        m.remove("nonce");
    });
    assert_eq!(
        v.validate(&c, &a.mint(&no_nonce), Some("n")).await,
        Err(OidcError::Nonce)
    );
    // Without a bound nonce (admin calls) the same token is fine.
    v.validate(&c, &a.mint(&no_nonce), None).await.unwrap();
}

#[tokio::test]
async fn rejects_forged_and_unsigned_tokens() {
    let a = idp("svx-example-corp").await;
    let b = idp("svx-example-corp").await; // a different key
    let v = Validator::new(true).unwrap();
    let c = cfg(&a);
    let claims = a.claims_for(a.user("alice").unwrap(), "n");

    // IdP B signs a token claiming to be from A.
    let forged = b.mint(&claims);
    assert!(v.validate(&c, &forged, Some("n")).await.is_err());

    // alg=none
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let none = format!("{}.{}.", URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#), body);
    assert!(v.validate(&c, &none, Some("n")).await.is_err());

    // HS256 "signed" with a guessable secret (key confusion attempt).
    let hs = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        body,
        URL_SAFE_NO_PAD.encode([0u8; 32])
    );
    assert_eq!(
        v.validate(&c, &hs, Some("n")).await,
        Err(OidcError::AlgorithmNotAllowed)
    );

    // Tampered payload with A's original signature.
    let good = a.mint(&claims);
    let parts: Vec<&str> = good.split('.').collect();
    let evil = edit(claims.clone(), |m| {
        m.insert("groups".into(), json!(["admins"]));
    });
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&evil).unwrap()),
        parts[2]
    );
    assert!(v.validate(&c, &tampered, Some("n")).await.is_err());

    // Garbage and oversized input.
    assert_eq!(
        v.validate(&c, "not-a-jwt", None).await,
        Err(OidcError::Malformed)
    );
    assert_eq!(
        v.validate(&c, &"a".repeat(20_000), None).await,
        Err(OidcError::Malformed)
    );
}

#[tokio::test]
async fn issuer_must_be_reachable_and_secure() {
    let v = Validator::new(false).unwrap();
    let c = IssuerConfig {
        issuer: "http://127.0.0.1:9".into(),
        client_id: "x".into(),
        group_claim: "groups".into(),
    };
    let a = idp("x").await;
    let t = a.mint(&a.claims_for(a.user("alice").unwrap(), "n"));
    // Plain-http issuer refused when dev mode is off.
    assert!(matches!(
        v.validate(&c, &t, None).await,
        Err(OidcError::Unavailable(_))
    ));
}
