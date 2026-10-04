//! Personal accounts in the test world: sign up with the "Google" dev IdP,
//! look people up by email, send and open files with device-signed
//! requests.

use std::io::Cursor;

use serde::Serialize;
use serde::de::DeserializeOwned;
use svx_core::crypto::{KemSecretKey, SigningKey, Suite, os_rng};
use svx_core::format::{EnvelopeRole, Identifier};
use svx_core::{Manifest, PackRequest, TrustStore, unwrap_envelope};
use svx_protocol::email_account::{
    CodePurpose, EmailAccountRequest, EmailCodeRequest, EmailCodeResponse, KeyMode,
};
use svx_protocol::oidc_login::dev_auto_login;
use svx_protocol::personal::{
    Account, FileRules, FileStatus, OpenedReceipt, PersonalReleaseResponse, RegisterFileRequest,
    SignUpRequest, signup_nonce,
};
use svx_protocol::{Method, OrgRecord, ProtocolError, ReleaseSession};

use crate::{SECRET, SERVICE_ID, World, now};

/// A signed-up person and their device keys.
pub struct Person {
    pub account: String,
    pub email: String,
    pub sign: SigningKey,
    pub kem: KemSecretKey,
}

impl World {
    /// An ID token from the personal IdP for `name` ("alice", …) whose
    /// nonce binds these keys.
    pub async fn personal_token(
        &self,
        name: &str,
        sign: &SigningKey,
        kem: &KemSecretKey,
    ) -> String {
        let nonce = signup_nonce(&sign.verifying_key().to_vec(), &kem.public_key().to_vec());
        dev_auto_login(
            &self.client,
            self.personal_idp.issuer(),
            self.personal_idp.client_id(),
            name,
            &nonce,
        )
        .await
        .unwrap()
    }

    /// `POST /v1/accounts` with these keys.
    pub async fn sign_up_with(
        &self,
        name: &str,
        sign: &SigningKey,
        kem: &KemSecretKey,
        reset: bool,
    ) -> Result<Account, ProtocolError> {
        let id_token = self.personal_token(name, sign, kem).await;
        self.client
            .post_json(
                &self.service_url,
                "/v1/accounts",
                &SignUpRequest {
                    issuer: self.personal_idp.issuer().into(),
                    id_token,
                    signing_public: sign.verifying_key().to_vec(),
                    kem_public: kem.public_key().to_vec(),
                    reset,
                },
                None,
            )
            .await
    }

    /// Ask for an emailed code; returns the challenge and the code from
    /// the email, if one was sent.
    pub async fn email_code(
        &self,
        email: &str,
        purpose: CodePurpose,
    ) -> Result<([u8; 16], Option<String>), ProtocolError> {
        let before = self.mail.sent().len();
        let r: EmailCodeResponse = self
            .client
            .post_json(
                &self.service_url,
                "/v1/auth/email/code",
                &EmailCodeRequest {
                    email: email.into(),
                    purpose,
                },
                None,
            )
            .await?;
        let code = self.mail.sent()[before..]
            .iter()
            .rev()
            .find(|m| m.to.eq_ignore_ascii_case(email.trim()))
            .map(|m| m.subject[..6].to_owned());
        Ok((r.challenge, code))
    }

    /// `POST /v1/accounts/email`.
    #[allow(clippy::too_many_arguments)]
    pub async fn email_account(
        &self,
        email: &str,
        password: &str,
        names: Option<(&str, &str)>,
        challenge: [u8; 16],
        code: &str,
        sign: &SigningKey,
        kem: &KemSecretKey,
        keys: KeyMode,
    ) -> Result<Account, ProtocolError> {
        self.client
            .post_json(
                &self.service_url,
                "/v1/accounts/email",
                &EmailAccountRequest {
                    challenge,
                    code: code.into(),
                    email: email.into(),
                    password: password.into(),
                    first_name: names.map(|n| n.0.into()),
                    last_name: names.map(|n| n.1.into()),
                    signing_public: sign.verifying_key().to_vec(),
                    kem_public: kem.public_key().to_vec(),
                    keys,
                },
                None,
            )
            .await
    }

    /// Create an email account with fresh keys.
    pub async fn sign_up_email(&self, email: &str, password: &str, names: (&str, &str)) -> Person {
        let mut rng = os_rng();
        let sign = SigningKey::generate_max(&mut rng);
        let kem = KemSecretKey::generate_max(&mut rng);
        let (challenge, code) = self.email_code(email, CodePurpose::SignUp).await.unwrap();
        let a = self
            .email_account(
                email,
                password,
                Some(names),
                challenge,
                &code.expect("a code was emailed"),
                &sign,
                &kem,
                KeyMode::Keep,
            )
            .await
            .unwrap();
        Person {
            account: a.account,
            email: a.email,
            sign,
            kem,
        }
    }

    /// Sign `name` up with fresh keys.
    pub async fn sign_up(&self, name: &str) -> Person {
        let mut rng = os_rng();
        let sign = SigningKey::generate_max(&mut rng);
        let kem = KemSecretKey::generate_max(&mut rng);
        let a = self.sign_up_with(name, &sign, &kem, false).await.unwrap();
        Person {
            account: a.account,
            email: a.email,
            sign,
            kem,
        }
    }

    /// A request signed with `p`'s device key.
    pub async fn call<B: Serialize, T: DeserializeOwned>(
        &self,
        p: &Person,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T, ProtocolError> {
        self.client
            .signed(method, &self.service_url, path, body, &p.account, &p.sign)
            .await
    }

    pub async fn get<T: DeserializeOwned>(
        &self,
        p: &Person,
        path: &str,
    ) -> Result<T, ProtocolError> {
        self.call::<(), T>(p, Method::GET, path, None).await
    }

    /// Look someone up by email in the signed directory.
    pub async fn lookup(&self, p: &Person, email: &str) -> Result<OrgRecord, ProtocolError> {
        self.client
            .lookup_email(
                &self.service_url,
                email,
                &p.account,
                &p.sign,
                &self.registry_key(),
            )
            .await
    }

    /// `from` packs SECRET for `to` (signed expiry `expires_at`).
    pub fn pack_personal(&self, from: &Person, to: &[&Person], expires_at: Option<i64>) -> Vec<u8> {
        let ids: Vec<Identifier> = to
            .iter()
            .map(|p| Identifier::new(&p.account).unwrap())
            .collect();
        let svc = self.service_kem();
        let req = PackRequest {
            suite: Suite::Svx2,
            sender_org: Identifier::new(&from.account).unwrap(),
            signing_key: &from.sign,
            recipient_org: ids[0].clone(),
            recipient_key: to[0].kem.public_key(),
            more_recipients: ids[1..]
                .iter()
                .cloned()
                .zip(to[1..].iter().map(|p| p.kem.public_key()))
                .collect(),
            service_id: Identifier::new(SERVICE_ID).unwrap(),
            service_key: &svc,
            policy_ref: Identifier::new("personal").unwrap(),
            created_at: now() - 10,
            expires_at,
            chunk_size: Some(64),
            manifest: Manifest::single_file("note.txt", SECRET.len() as u64),
        };
        let mut out = Vec::new();
        svx_core::pack(&req, SECRET, &mut out, &mut os_rng()).unwrap();
        out
    }

    /// Pack and register a file.
    pub async fn send(
        &self,
        from: &Person,
        to: &[&Person],
        rules: FileRules,
    ) -> Result<(Vec<u8>, FileStatus), ProtocolError> {
        let file = self.pack_personal(from, to, Some(now() + 3600));
        let status = self.register(from, &file, rules).await?;
        Ok((file, status))
    }

    pub async fn register(
        &self,
        from: &Person,
        file: &[u8],
        rules: FileRules,
    ) -> Result<FileStatus, ProtocolError> {
        let (header_region, trailer) = head_parts(file);
        self.call(
            from,
            Method::POST,
            "/v1/me/files",
            Some(&RegisterFileRequest {
                header_region,
                trailer,
                rules,
            }),
        )
        .await
    }

    /// Ask to open `file` as `p` in `session` (repeat to poll).
    pub async fn ask(
        &self,
        p: &Person,
        file: &[u8],
        session: &ReleaseSession,
    ) -> Result<PersonalReleaseResponse, ProtocolError> {
        let (header_region, trailer) = head_parts(file);
        self.call(
            p,
            Method::POST,
            "/v1/personal/release",
            Some(&session.personal_request(&header_region, &trailer)),
        )
        .await
    }

    /// Decrypt `file` as `p` after a release, and send the receipt.
    pub async fn finish_open(
        &self,
        p: &Person,
        file: &[u8],
        session: &ReleaseSession,
        resp: PersonalReleaseResponse,
    ) -> Vec<u8> {
        let PersonalReleaseResponse::Released { share } = resp else {
            panic!("not released: {resp:?}");
        };
        let sender = svx_core::inspect(Cursor::new(file)).unwrap().1.sender_org;
        let rec = self
            .client
            .org_record(&self.service_url, sender.as_str(), &self.registry_key())
            .await
            .unwrap();
        let mut trust = TrustStore::new();
        rec.add_signing_keys_to(&mut trust).unwrap();
        let v = svx_core::verify(Cursor::new(file), &trust).unwrap();
        let s = session
            .open_service_share(&v.header.artifact_id, &share)
            .unwrap();
        let r = unwrap_envelope(&v.header, EnvelopeRole::RecipientOrg, &p.kem).unwrap();
        let mut out = Vec::new();
        v.decrypt(Cursor::new(file), &s, &r, &mut out).unwrap();
        let _: serde_json::Value = self
            .call(
                p,
                Method::POST,
                "/v1/personal/opened",
                Some(&OpenedReceipt {
                    artifact_id: v.header.artifact_id,
                    txn: *session.txn(),
                }),
            )
            .await
            .unwrap();
        out
    }

    /// Ask and, if released, decrypt.
    pub async fn open_personal(&self, p: &Person, file: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let session = ReleaseSession::new();
        let resp = self.ask(p, file, &session).await?;
        if let PersonalReleaseResponse::Pending { .. } = resp {
            return Err(ProtocolError::BadResponse("pending approval".into()));
        }
        Ok(self.finish_open(p, file, &session, resp).await)
    }
}

/// The header region and encoded trailer of a file.
pub fn head_parts(file: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut r = svx_core::format::Reader::new(Cursor::new(file)).unwrap();
    let header_region = r.header_region().to_vec();
    let mut buf = Vec::new();
    while r.next_chunk(&mut buf).unwrap().is_some() {}
    let (trailer, _) = r.finish().unwrap();
    (header_region, trailer.encode().unwrap())
}
