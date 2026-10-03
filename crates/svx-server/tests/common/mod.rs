//! End-to-end harness: real Postgres, two dev IdPs, the managed service and
//! Example Corp's key agent, all over real HTTP on loopback.
//!
//! Set `SVX_TEST_DATABASE_URL` to a Postgres URL with CREATE DATABASE rights
//! (e.g. `postgres://svx@127.0.0.1:55432/postgres`). Without it these tests
//! are skipped, unless `SVX_REQUIRE_DB` is set, in which case they fail.

#![allow(dead_code)]

use std::io::Cursor;
use std::sync::Arc;

use svx_core::crypto::{
    KemPublicKey, KemSecretKey, SigningKey, VerifyingKey, os_rng, random_bytes,
};
use svx_core::format::Identifier;
use svx_core::{Manifest, PackRequest, TrustStore};
use svx_keyagent::AgentState;
use svx_mock_idp::{Config, MockIdp, User};
use svx_oidc::{IssuerConfig, Validator};
use svx_protocol::admin::{
    PutKeyRequest, RegisterOrgRequest, RegisterOrgResponse, VerifyOrgRequest,
};
use svx_protocol::oidc_login::dev_auto_login;
use svx_protocol::{
    KeyKindWire, KeyStatus, ManagedClient, Policy, ProtocolError, ReleaseSession, ServiceInfo,
};
use svx_server::AppState;
use svx_server::dns::StaticDns;
use svx_server::keys::LocalKeys;

pub const SECRET: &[u8] = b"FICTIONAL: Example Corp incident 3921 evidence. Not a real secret.";
pub const ACME: &str = "acme-security";
pub const EXAMPLE: &str = "example-corp";
pub const SERVICE_ID: &str = "svx.example";
pub const POLICY: &str = "incident-response";

pub struct World {
    pub client: ManagedClient,
    pub service_url: String,
    pub agent_url: String,
    pub acme_idp: MockIdp,
    pub example_idp: MockIdp,
    pub dns: StaticDns,
    pub db: sqlx::PgPool,
    pub acme_sign: SigningKey,
    pub example_kem: KemSecretKey,
    pub service_grant: SigningKey,
    pub info: ServiceInfo,
}

fn user(sub: &str, groups: &[&str], acr: Option<&str>) -> User {
    User {
        sub: sub.into(),
        email: Some(format!("{sub}@fictional.example")),
        groups: groups.iter().map(|g| g.to_string()).collect(),
        acr: acr.map(str::to_owned),
    }
}

pub fn now() -> i64 {
    svx_protocol::unix_now()
}

async fn fresh_db(admin_url: &str, name: &str) -> sqlx::PgPool {
    let admin = sqlx::PgPool::connect(admin_url)
        .await
        .expect("connect admin db");
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .expect("create database");
    let mut url = url::Url::parse(admin_url).expect("db url");
    url.set_path(&format!("/{name}"));
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(url.as_str())
        .await
        .expect("connect test db")
}

async fn serve(router: axum::Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(l, router).await;
    });
    url
}

impl World {
    /// `None` when no test database is configured (and `SVX_REQUIRE_DB` is unset).
    pub async fn new() -> Option<World> {
        let Ok(admin_url) = std::env::var("SVX_TEST_DATABASE_URL") else {
            if std::env::var_os("SVX_REQUIRE_DB").is_some() {
                panic!("SVX_TEST_DATABASE_URL must be set when SVX_REQUIRE_DB is set");
            }
            eprintln!("skipping: SVX_TEST_DATABASE_URL not set");
            return None;
        };
        let tag = hex::encode(random_bytes::<6>());

        let acme_idp = MockIdp::spawn(
            Config {
                client_id: "svx-acme".into(),
                users: vec![
                    user("acme-admin", &["admins"], None),
                    user("carol", &["incident-response"], None),
                ],
                token_ttl_secs: 300,
            },
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let example_idp = MockIdp::spawn(
            Config {
                client_id: "svx-example".into(),
                users: vec![
                    user("example-admin", &["admins"], None),
                    user("alice", &["incident-response", "staff"], Some("phr")),
                    user("bob", &["staff"], Some("phr")),
                ],
                token_ttl_secs: 300,
            },
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();

        // Managed service.
        let mut rng = os_rng();
        let service_kem = KemSecretKey::generate(&mut rng);
        let service_grant = SigningKey::generate(&mut rng);
        let registry = SigningKey::generate(&mut rng);
        let grant_copy = SigningKey::from_bytes(&service_grant.to_bytes());
        let db = fresh_db(&admin_url, &format!("svx_t_{tag}_svc")).await;
        let dns = StaticDns::default();
        let state = AppState {
            db: db.clone(),
            service_id: Identifier::new(SERVICE_ID).unwrap(),
            keys: Arc::new(LocalKeys::new(service_kem, service_grant, registry)),
            oidc: Arc::new(Validator::new(true).unwrap()),
            dns: Arc::new(dns.clone()),
            dev: true,
        };
        let service_url = serve(svx_server::app(state).await.unwrap()).await;

        // Example Corp's key agent.
        let example_kem = KemSecretKey::generate(&mut rng);
        let agent_db = fresh_db(&admin_url, &format!("svx_t_{tag}_agent")).await;
        let agent = AgentState {
            db: agent_db,
            org_id: Identifier::new(EXAMPLE).unwrap(),
            idp: IssuerConfig {
                issuer: example_idp.issuer().into(),
                client_id: "svx-example".into(),
                group_claim: "groups".into(),
            },
            service_id: Identifier::new(SERVICE_ID).unwrap(),
            service_grant_key: grant_copy.verifying_key(),
            kem_keys: Arc::new(vec![
                KemSecretKey::from_bytes(&example_kem.to_bytes()).unwrap(),
            ]),
            oidc: Arc::new(Validator::new(true).unwrap()),
        };
        let agent_url = serve(svx_keyagent::app(agent).await.unwrap()).await;

        let client = ManagedClient::new(true).unwrap();
        let info = client.service_info(&service_url).await.unwrap();
        let w = World {
            client,
            service_url,
            agent_url,
            acme_idp,
            example_idp,
            dns,
            db,
            acme_sign: SigningKey::generate(&mut rng),
            example_kem,
            service_grant: grant_copy,
            info,
        };

        // Onboard both organizations through the public API.
        w.onboard(ACME, "acme.example", true).await;
        w.onboard(EXAMPLE, "example-corp.example", false).await;
        let acme_admin = w.token(ACME, "acme-admin", "admin").await;
        let example_admin = w.token(EXAMPLE, "example-admin", "admin").await;
        w.put_key(
            ACME,
            &acme_admin,
            KeyKindWire::Ed25519,
            w.acme_sign.verifying_key().to_bytes(),
            KeyStatus::Active,
        )
        .await
        .unwrap();
        w.put_key(
            EXAMPLE,
            &example_admin,
            KeyKindWire::X25519,
            w.example_kem.public_key().to_bytes(),
            KeyStatus::Active,
        )
        .await
        .unwrap();
        w.put_policy(
            &example_admin,
            POLICY,
            &Policy {
                allow_groups: vec!["incident-response".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        Some(w)
    }

    pub fn idp(&self, org: &str) -> &MockIdp {
        if org == ACME {
            &self.acme_idp
        } else {
            &self.example_idp
        }
    }

    pub async fn token(&self, org: &str, sub: &str, nonce: &str) -> String {
        let idp = self.idp(org);
        dev_auto_login(&self.client, idp.issuer(), idp.client_id(), sub, nonce)
            .await
            .unwrap()
    }

    async fn onboard(&self, org: &str, domain: &str, sender_only: bool) {
        let idp = self.idp(org);
        let resp: RegisterOrgResponse = self
            .client
            .post_json(
                &self.service_url,
                "/v1/orgs",
                &RegisterOrgRequest {
                    org_id: org.into(),
                    display_name: org.into(),
                    domain: domain.into(),
                    idp_issuer: idp.issuer().into(),
                    idp_client_id: idp.client_id().into(),
                    group_claim: None,
                    key_agent_url: (!sender_only).then(|| self.agent_url.clone()),
                },
                None,
            )
            .await
            .unwrap();
        self.dns.set(&resp.txt_name, &resp.txt_value);
        let admin = if org == ACME {
            "acme-admin"
        } else {
            "example-admin"
        };
        let id_token = self.token(org, admin, "verify").await;
        let _: serde_json::Value = self
            .client
            .post_json(
                &self.service_url,
                &format!("/v1/orgs/{org}/verify"),
                &VerifyOrgRequest { id_token },
                None,
            )
            .await
            .unwrap();
    }

    pub async fn put_key(
        &self,
        org: &str,
        bearer: &str,
        kind: KeyKindWire,
        public_key: [u8; 32],
        status: KeyStatus,
    ) -> Result<serde_json::Value, ProtocolError> {
        self.client
            .put_json(
                &self.service_url,
                &format!("/v1/admin/orgs/{org}/keys"),
                &PutKeyRequest {
                    kind,
                    public_key,
                    status,
                },
                bearer,
            )
            .await
    }

    pub async fn put_policy(
        &self,
        bearer: &str,
        name: &str,
        p: &Policy,
    ) -> Result<Policy, ProtocolError> {
        self.client
            .put_json(
                &self.service_url,
                &format!("/v1/admin/orgs/{EXAMPLE}/policies/{name}"),
                p,
                bearer,
            )
            .await
    }

    pub fn service_kem(&self) -> KemPublicKey {
        KemPublicKey::from_bytes(&self.info.kem_public).unwrap()
    }

    pub fn registry_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.info.registry_public).unwrap()
    }

    /// Acme packs SECRET for Example Corp.
    pub fn pack_with(
        &self,
        signer: &SigningKey,
        created_at: i64,
        expires_at: Option<i64>,
        policy: &str,
    ) -> Vec<u8> {
        let svc = self.service_kem();
        let req = PackRequest {
            sender_org: Identifier::new(ACME).unwrap(),
            signing_key: signer,
            recipient_org: Identifier::new(EXAMPLE).unwrap(),
            recipient_key: self.example_kem.public_key(),
            service_id: Identifier::new(SERVICE_ID).unwrap(),
            service_key: &svc,
            policy_ref: Identifier::new(policy).unwrap(),
            created_at,
            expires_at,
            chunk_size: Some(64),
            manifest: Manifest::single_file("evidence.txt", SECRET.len() as u64),
        };
        let mut out = Vec::new();
        svx_core::pack(&req, SECRET, &mut out, &mut os_rng()).unwrap();
        out
    }

    pub fn pack(&self) -> Vec<u8> {
        self.pack_with(&self.acme_sign, now() - 10, Some(now() + 3600), POLICY)
    }

    /// The recipient's trust store, built from the signed registry record.
    pub async fn trust(&self) -> TrustStore {
        let rec = self
            .client
            .org_record(&self.service_url, ACME, &self.registry_key())
            .await
            .unwrap();
        let mut t = TrustStore::new();
        rec.add_signing_keys_to(&mut t).unwrap();
        t
    }

    /// Full recipient flow as `user` of `user_org`'s IdP.
    pub async fn open_as(
        &self,
        file: &[u8],
        user_org: &str,
        user: &str,
    ) -> Result<Vec<u8>, ProtocolError> {
        let v = svx_core::verify(Cursor::new(file), &self.trust().await).unwrap();
        let session = ReleaseSession::new();
        let token = self.token(user_org, user, &session.nonce()).await;
        let (s, r) = self
            .client
            .release(
                &self.service_url,
                &self.agent_url,
                &session,
                v.head(),
                &token,
            )
            .await?;
        let mut out = Vec::new();
        v.decrypt(Cursor::new(file), &s, &r, &mut out).unwrap();
        Ok(out)
    }
}
