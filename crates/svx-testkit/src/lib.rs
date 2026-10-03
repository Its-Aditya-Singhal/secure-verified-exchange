//! End-to-end harness: real Postgres, two dev IdPs, the managed service and
//! Example Corp's key agent, all over real HTTP on loopback.
//!
//! Set `SVX_TEST_DATABASE_URL` to a Postgres URL with CREATE DATABASE rights
//! (e.g. `postgres://svx@127.0.0.1:55432/postgres`). Without it these tests
//! are skipped, unless `SVX_REQUIRE_DB` is set, in which case they fail.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use svx_client::ClientConfig;

use svx_core::crypto::{
    KemPublicKey, KemSecretKey, KeyKind, SigningKey, Suite, VerifyingKey, os_rng, random_bytes,
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
    /// Acme's active post-quantum hybrid signing key (Ed25519 + ML-DSA-65).
    pub acme_sign: SigningKey,
    /// Acme's retired classical Ed25519 key (verifies older files).
    pub acme_sign_classical: SigningKey,
    /// Example Corp's active X-Wing key (held by its key agent).
    pub example_kem: KemSecretKey,
    /// Example Corp's retired X25519 key (still opens older files).
    pub example_kem_classical: KemSecretKey,
    /// The service's X25519 key for older files (not published).
    pub service_kem_classical: KemPublicKey,
    pub service_grant: SigningKey,
    pub info: ServiceInfo,
    agent_db: sqlx::PgPool,
    admin_url: String,
    db_names: Vec<String>,
}

pub fn copy_kem(k: &KemSecretKey) -> KemSecretKey {
    KemSecretKey::from_kind_bytes(k.kind(), &k.to_bytes()).unwrap()
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

/// Check that `admin_url` is reachable and allows creating databases.
pub async fn check_database(admin_url: &str) -> Result<(), sqlx::Error> {
    let pool = sqlx::PgPool::connect(admin_url).await?;
    let can: (bool,) =
        sqlx::query_as("SELECT rolcreatedb OR rolsuper FROM pg_roles WHERE rolname = current_user")
            .fetch_one(&pool)
            .await?;
    pool.close().await;
    if !can.0 {
        return Err(sqlx::Error::Protocol(
            "the database role lacks CREATE DATABASE rights".into(),
        ));
    }
    Ok(())
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
        Some(World::connect(&admin_url, "t").await)
    }

    /// Start a fresh world with two new databases created through
    /// `admin_url` (which needs CREATE DATABASE rights). Database names are
    /// `svx_<prefix>_<random>_{svc,agent}`; see [`World::cleanup`].
    pub async fn connect(admin_url: &str, prefix: &str) -> World {
        assert!(
            !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_lowercase()),
            "database prefix must be lowercase letters"
        );
        let tag = hex::encode(random_bytes::<6>());
        let svc_db = format!("svx_{prefix}_{tag}_svc");
        let agent_db_name = format!("svx_{prefix}_{tag}_agent");

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
        // Post-quantum hybrid keys for new files, classical ones for older
        // files (suite SVX-1), as after a real migration.
        let service_kem = KemSecretKey::generate_hybrid(&mut rng);
        let service_kem_classical = KemSecretKey::generate(&mut rng);
        let service_kem_classical_pub = service_kem_classical.public_key().clone();
        let service_grant = SigningKey::generate(&mut rng);
        let registry = SigningKey::generate(&mut rng);
        let grant_copy = SigningKey::from_bytes(&service_grant.to_bytes());
        let db = fresh_db(admin_url, &svc_db).await;
        let dns = StaticDns::default();
        let state = AppState {
            db: db.clone(),
            service_id: Identifier::new(SERVICE_ID).unwrap(),
            keys: Arc::new(
                LocalKeys::new(
                    vec![service_kem, service_kem_classical],
                    service_grant,
                    registry,
                )
                .unwrap(),
            ),
            oidc: Arc::new(Validator::new(true).unwrap()),
            dns: Arc::new(dns.clone()),
            dev: true,
        };
        let service_url = serve(svx_server::app(state).await.unwrap()).await;

        // Example Corp's key agent.
        let example_kem = KemSecretKey::generate_hybrid(&mut rng);
        let example_kem_classical = KemSecretKey::generate(&mut rng);
        let agent_db = fresh_db(admin_url, &agent_db_name).await;
        let agent = AgentState {
            db: agent_db.clone(),
            org_id: Identifier::new(EXAMPLE).unwrap(),
            idp: IssuerConfig {
                issuer: example_idp.issuer().into(),
                client_id: "svx-example".into(),
                group_claim: "groups".into(),
            },
            service_id: Identifier::new(SERVICE_ID).unwrap(),
            service_grant_key: grant_copy.verifying_key(),
            kem_keys: Arc::new(vec![
                copy_kem(&example_kem),
                copy_kem(&example_kem_classical),
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
            acme_sign: SigningKey::generate_hybrid(&mut rng),
            acme_sign_classical: SigningKey::generate(&mut rng),
            example_kem,
            example_kem_classical,
            service_kem_classical: service_kem_classical_pub,
            service_grant: grant_copy,
            info,
            agent_db,
            admin_url: admin_url.to_owned(),
            db_names: vec![svc_db, agent_db_name],
        };

        // Onboard both organizations through the public API.
        w.onboard(ACME, "acme.example", true).await;
        w.onboard(EXAMPLE, "example-corp.example", false).await;
        let acme_admin = w.token(ACME, "acme-admin", "admin").await;
        let example_admin = w.token(EXAMPLE, "example-admin", "admin").await;
        let keys = [
            (
                ACME,
                &acme_admin,
                w.acme_sign.verifying_key().to_vec(),
                KeyKindWire::Ed25519Mldsa65,
                KeyStatus::Active,
            ),
            (
                ACME,
                &acme_admin,
                w.acme_sign_classical.verifying_key().to_vec(),
                KeyKindWire::Ed25519,
                KeyStatus::Retired,
            ),
            (
                EXAMPLE,
                &example_admin,
                w.example_kem.public_key().to_vec(),
                KeyKindWire::XWing,
                KeyStatus::Active,
            ),
            (
                EXAMPLE,
                &example_admin,
                w.example_kem_classical.public_key().to_vec(),
                KeyKindWire::X25519,
                KeyStatus::Retired,
            ),
        ];
        for (org, admin, public_key, kind, status) in keys {
            w.put_key(org, admin, kind, public_key, status)
                .await
                .unwrap();
        }
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
        w
    }

    /// Close connections and drop this world's databases. The in-process
    /// services stop working afterwards.
    pub async fn cleanup(&self) -> Result<(), sqlx::Error> {
        self.db.close().await;
        self.agent_db.close().await;
        let admin = sqlx::PgPool::connect(&self.admin_url).await?;
        for name in &self.db_names {
            sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                .execute(&admin)
                .await?;
        }
        admin.close().await;
        Ok(())
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
        public_key: Vec<u8>,
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

    /// The service's published (X-Wing) KEM key.
    pub fn service_kem(&self) -> KemPublicKey {
        KemPublicKey::from_kind_bytes(KeyKind::XWingKem, &self.info.kem_public).unwrap()
    }

    pub fn registry_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.info.registry_public).unwrap()
    }

    /// Acme packs SECRET for Example Corp: suite SVX-1H with a hybrid
    /// `signer`, or a legacy SVX-1 file with a classical one.
    pub fn pack_with(
        &self,
        signer: &SigningKey,
        created_at: i64,
        expires_at: Option<i64>,
        policy: &str,
    ) -> Vec<u8> {
        let (suite, recipient, svc) = if signer.kind() == KeyKind::HybridSigning {
            (
                Suite::Svx1H,
                self.example_kem.public_key(),
                self.service_kem(),
            )
        } else {
            (
                Suite::Svx1,
                self.example_kem_classical.public_key(),
                self.service_kem_classical.clone(),
            )
        };
        let req = PackRequest {
            suite,
            sender_org: Identifier::new(ACME).unwrap(),
            signing_key: signer,
            recipient_org: Identifier::new(EXAMPLE).unwrap(),
            recipient_key: recipient,
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

    /// A file in the older classical suite (SVX-1), as made before the
    /// post-quantum upgrade. It must still open.
    pub fn pack_legacy(&self) -> Vec<u8> {
        self.pack_with(
            &self.acme_sign_classical,
            now() - 10,
            Some(now() + 3600),
            POLICY,
        )
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

impl World {
    /// Start another Example Corp key agent holding `kem_keys` (sharing the
    /// agent database), e.g. after a key rotation. Returns its URL.
    pub async fn spawn_agent(&self, kem_keys: Vec<KemSecretKey>) -> String {
        let agent = AgentState {
            db: self.agent_db.clone(),
            org_id: Identifier::new(EXAMPLE).unwrap(),
            idp: IssuerConfig {
                issuer: self.example_idp.issuer().into(),
                client_id: self.example_idp.client_id().into(),
                group_claim: "groups".into(),
            },
            service_id: Identifier::new(SERVICE_ID).unwrap(),
            service_grant_key: self.service_grant.verifying_key(),
            kem_keys: Arc::new(kem_keys),
            oidc: Arc::new(Validator::new(true).unwrap()),
        };
        serve(svx_keyagent::app(agent).await.unwrap()).await
    }

    /// A copy of Example Corp's current keys, for [`World::spawn_agent`].
    pub fn example_kems(&self) -> Vec<KemSecretKey> {
        vec![
            copy_kem(&self.example_kem),
            copy_kem(&self.example_kem_classical),
        ]
    }

    /// A dev IdP for a further (fictional) organization; `users` are
    /// `(sub, groups)`.
    pub async fn spawn_idp(client_id: &str, users: &[(&str, &[&str])]) -> MockIdp {
        MockIdp::spawn(
            Config {
                client_id: client_id.into(),
                users: users.iter().map(|(s, g)| user(s, g, None)).collect(),
                token_ttl_secs: 300,
            },
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap()
    }

    /// The registry public key clients must pin (hex).
    pub fn registry_key_hex(&self) -> String {
        hex::encode(self.info.registry_public)
    }

    /// Write Acme's signing key as `<dir>/acme.sign.key` (+ `.pub`).
    pub fn write_acme_sign_key(&self, dir: &Path) -> PathBuf {
        let prefix = dir.join("acme");
        svx_core::keyfile::write_signing_pair(
            &prefix,
            &Identifier::new(ACME).unwrap(),
            &self.acme_sign,
        )
        .unwrap();
        dir.join("acme.sign.key")
    }

    /// A dev client configuration for `org`.
    pub fn client_config(&self, org: &str) -> ClientConfig {
        let idp = self.idp(org);
        ClientConfig {
            service_url: self.service_url.clone(),
            registry_key: self.registry_key_hex(),
            org_id: org.into(),
            idp_issuer: idp.issuer().into(),
            idp_client_id: idp.client_id().into(),
            group_claim: "groups".into(),
            dev: true,
            default_output_dir: None,
        }
    }

    /// A fresh ID token for `org`'s administrator.
    pub async fn admin_token(&self, org: &str) -> String {
        let admin = if org == ACME {
            "acme-admin"
        } else {
            "example-admin"
        };
        self.token(org, admin, &hex::encode(random_bytes::<8>()))
            .await
    }

    /// Revoke an artifact as Example Corp's administrator.
    pub async fn revoke(&self, artifact_id: &[u8; 16]) -> Result<(), ProtocolError> {
        let bearer = self.admin_token(EXAMPLE).await;
        let _: serde_json::Value = self
            .client
            .post_json(
                &self.service_url,
                &format!(
                    "/v1/admin/orgs/{EXAMPLE}/artifacts/{}/revoke",
                    hex::encode(artifact_id)
                ),
                &(),
                Some(&bearer),
            )
            .await?;
        Ok(())
    }

    /// Write a description of this world into `dir` for external tools
    /// (SDK tests, manual CLI use): `state.json`, client configs
    /// `acme.toml` / `example.toml`, Acme's signing key, and sample
    /// artifacts `incident-report.svx` (valid) and `expired.svx`.
    pub fn write_state(&self, dir: &Path) -> std::io::Result<State> {
        std::fs::create_dir_all(dir)?;
        let other = |e: svx_client::ClientError| std::io::Error::other(e.to_string());
        let acme_cfg = dir.join("acme.toml");
        let example_cfg = dir.join("example.toml");
        self.client_config(ACME).save(&acme_cfg).map_err(other)?;
        self.client_config(EXAMPLE)
            .save(&example_cfg)
            .map_err(other)?;
        let sign_key = self.write_acme_sign_key(dir);
        let sample = dir.join("incident-report.svx");
        std::fs::write(&sample, self.pack())?;
        let expired = dir.join("expired.svx");
        std::fs::write(
            &expired,
            self.pack_with(&self.acme_sign, now() - 100, Some(now() - 10), POLICY),
        )?;
        let users = |idp: &MockIdp| {
            idp.users()
                .iter()
                .map(|u| StateUser {
                    sub: u.sub.clone(),
                    groups: u.groups.clone(),
                })
                .collect()
        };
        let state = State {
            service_url: self.service_url.clone(),
            agent_url: self.agent_url.clone(),
            registry_key: self.registry_key_hex(),
            service_id: SERVICE_ID.into(),
            policy: POLICY.into(),
            orgs: vec![
                StateOrg {
                    org_id: ACME.into(),
                    idp_issuer: self.acme_idp.issuer().into(),
                    idp_client_id: self.acme_idp.client_id().into(),
                    config: acme_cfg,
                    admin: "acme-admin".into(),
                    users: users(&self.acme_idp),
                },
                StateOrg {
                    org_id: EXAMPLE.into(),
                    idp_issuer: self.example_idp.issuer().into(),
                    idp_client_id: self.example_idp.client_id().into(),
                    config: example_cfg,
                    admin: "example-admin".into(),
                    users: users(&self.example_idp),
                },
            ],
            acme_signing_key: sign_key,
            sample_artifact: sample,
            expired_artifact: expired,
            sample_plaintext: String::from_utf8_lossy(SECRET).into_owned(),
        };
        let json = serde_json::to_vec_pretty(&state).map_err(std::io::Error::other)?;
        std::fs::write(dir.join("state.json"), json)?;
        Ok(state)
    }
}

/// What [`World::write_state`] writes to `state.json`.
#[derive(Clone, Debug, Serialize)]
pub struct State {
    pub service_url: String,
    pub agent_url: String,
    pub registry_key: String,
    pub service_id: String,
    pub policy: String,
    pub orgs: Vec<StateOrg>,
    pub acme_signing_key: PathBuf,
    pub sample_artifact: PathBuf,
    pub expired_artifact: PathBuf,
    pub sample_plaintext: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StateOrg {
    pub org_id: String,
    pub idp_issuer: String,
    pub idp_client_id: String,
    pub config: PathBuf,
    pub admin: String,
    pub users: Vec<StateUser>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StateUser {
    pub sub: String,
    pub groups: Vec<String>,
}
