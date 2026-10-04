# SVX Security Architecture

Status: Phases 1–4 are implemented: the format, the cryptography, the managed service, the key agent, the release protocol, the `svx` client and CLI, the demo and the Python and Node.js SDKs. The admin UI (Phase 5) is still design only.

## 1. Components

```text
            Company A (sender)                               Company B (recipient)
   +----------------------------------+            +-------------------------------------+
   | SVX client / CLI / SDK           |            | SVX client (desktop / CLI)          |
   |  - signing key (KMS/HSM in prod) |            |  - no long-term secrets             |
   +----------------+-----------------+            +----+--------------+-----------------+
                    |                                   |              |
                    | incident.svx over untrusted       | OIDC         | release requests
                    | transport (email, cloud, USB)     | (PKCE)       | (TLS 1.3)
                    +---------------------------------->|              |
                                                        v              |
                                       +-----------------------+       |
                                       | Company B IdP         |       |
                                       | (Entra / Okta / ...)  |       |
                                       +-----------------------+       |
                                                                       v
   +--------------------------------------------+     +--------------------------------------+
   | SVX Managed Service (svx.example)          |     | Company B Key Agent                  |
   |  - org registry and trust (signed records) |     |  - Company B SVX-2 KEM key in KMS    |
   |  - policy engine, expiry, revocation       |     |  - unwraps RecipientOrg share        |
   |  - service SVX-2 KEM key in KMS/HSM        |     |  - requires service grant + user     |
   |  - unwraps Service share only              |     |    token bound to client key         |
   |  - audit log                               |     |  - local audit log                   |
   +--------------------------------------------+     +--------------------------------------+
```

| Component | Holds | Never holds |
|-----------|-------|-------------|
| Sender client | Sender signing key; plaintext before packing | Recipient or service secret keys |
| `.svx` file | Ciphertext, sealed shares, public header, signature | Any usable key |
| Managed service | Service KEM key; policies; registry; audit | Recipient-org share; payload; plaintext manifest |
| Recipient key agent | Recipient-org KEM key | Service share; payload |
| Recipient client | Both shares, briefly, after authorization | Long-term secret keys |

## 2. Split-key envelope model

Every artifact has a fresh pair of 256-bit shares:

```text
share_svc  --HPKE-->  sealed to the managed service's KEM key         (envelope role 0x01)
share_org  --HPKE-->  sealed to the recipient organization's KEM key  (envelope role 0x02)

artifact keys = HKDF(salt = "SVX-1 artifact\0" || artifact_id, ikm = share_svc || share_org)
```

Neither party can decrypt alone. That gives three properties:

- **Server cannot decrypt.** A compromised or curious managed service has only `share_svc` (threat model T11).
- **Leaked org key is not enough.** Someone with the org KEM key still needs the service, which enforces policy, expiry and revocation (T12).
- **Recipient binding.** Only the named recipient org's key agent can contribute the second share (G4).

Deployments where the managed service also operates the recipient's key agent lose the "server cannot decrypt" property. The desktop app's admin screens must show this clearly.

## 3. Packing flow (implemented)

1. Validate the request. Generate `artifact_id` (16 random bytes), a STREAM `nonce_prefix` (7 random bytes), and `share_svc` and `share_org` (32 random bytes each).
2. Derive `payload_key`, `manifest_key` and `key_commitment` with HKDF.
3. HPKE-seal each share to its holder's MLKEM1024-P384 (ML-KEM-1024 + P-384) key. `info` binds role, artifact ID, sender org and key ID, recipient org, and service ID.
4. Encrypt the manifest (file name, size, classification, description).
5. Write the prelude and header. Compute `header_hash`.
6. Stream the payload: STREAM-encrypt each chunk with `aad = header_hash`, and accumulate the payload commitment.
7. Sign `header_hash ‖ chunk_count ‖ payload_commitment` with Ed25519, ML-DSA-87 and SLH-DSA-SHA2-256s (one signature in three parts; all must verify). Write the trailer.

New files always use suite SVX-2 (`0x0004`, format 1.3; SHA-512 throughout). Readers also accept SVX-1H (`0x0003`) and the classical SVX-1 (`0x0001`) so older files still open; see `spec/crypto-profile.md`.

Memory use is O(chunk size). The CLI writes to a temporary file and renames it only on success.

## 4. Opening flow (Managed Mode)

Steps marked ✅ are implemented: in `svx-core`, in `svx-protocol::client`, and server-side in `svx-server` and `svx-keyagent`. The remaining steps belong to the Phase 3 client.

```text
 1. ✅ Parse prelude and header (strict, bounded)
 2. ✅ Check format version and suite (reject unknown; no downgrade)
 3. ✅ Hash pass: recompute payload commitment over every chunk
 4. ✅ Verify sender signature against the trust store or registry
 5. ✅ Identify recipient org and service from the verified header
 6.    Require connectivity (no offline mode in Managed Mode)
 7. ✅ Authenticate the user with the recipient org's IdP (OIDC + PKCE)
 8. ✅ Verify the org identity via the signed registry record
 9. ✅ Release request to the managed service -> policy, expiry, revocation, device/session checks
10. ✅ Release request to the recipient key agent with the service grant
11. ✅ Receive both shares, HPKE-sealed to a per-request ephemeral client key
12. ✅ Derive keys; check key commitment (constant time)
13. ✅ Decrypt the manifest; validate file names
14. ✅ Decrypt the payload, re-checking header hash and commitment (TOCTOU)
15.    Write plaintext to a private temp location, then hand it to the viewer
16.    Audit: artifact_opened (client-reported) and decryption_authorized (server)
```

Any failure at any step means **no plaintext**. There is no "continue anyway" path in the client, the CLI or the SDK.

## 5. Organization identity and trust

An organization record:

```text
org_id                 opaque identifier (e.g. "example-corp")
display_name
verified_domains[]     proven via DNS TXT  _svx-challenge.<domain> = <token>
idp                    { issuer, jwks_uri, client_id, allowed_algs, group_claim }
signing_keys[]         { key_id, ed25519-mldsa65 (or legacy ed25519) public, status, not_before, not_after }
kem_keys[]             { key_id, xwing (or legacy x25519) public, status, not_before, not_after }
key_agent_endpoint
admins[]               subject IDs from the org's own IdP
policies[]             (see section 7)
```

Trust model:

1. **Registration.** An admin proves control of a domain (DNS TXT challenge) and sets up the org's IdP. The first admin login through that IdP binds the admin.
2. **Registry signing.** The service signs each org record with a registry key. Registry signatures use the SVX-2 key with all three parts (Ed25519 + ML-DSA-87 + SLH-DSA). Clients pin the registry key's fingerprint, which ships with the client and is rotated through signed update manifests. A client accepts sender keys only from a signed record. A plain org name is never treated as identity.
3. **Key status.** Keys move from `active` to `retired` to `revoked`. Verification checks that the key was valid at `created_at` and is not revoked.
4. **Later: federation.** Org-to-org trust that does not depend on the managed registry (signed cross-certification). Listed in Future features.

## 6. Key-release protocol

Goal: release the two shares only to an authenticated, authorized user's client, and make sure no intermediary sees them.

```text
Client                                 Managed Service                  Recipient Key Agent
  | generate one-time MLKEM1024-P384 (e_pk, e_sk); txn = random 128-bit
  | OIDC auth with nonce = H("SVX-2 oidc" || e_pk || txn)
  |---- POST /v1/release ----------------->|
  |   header_region, trailer, id_token,    |
  |   e_pk, txn                            |
  |                                        | verify artifact signature (registry key)
  |                                        | validate id_token: iss, aud, sig, exp, nonce==H(e_pk||txn)
  |                                        | user in recipient_org; policy(policy_ref, user, groups, acr, device)
  |                                        | not expired (server clock), not revoked, txn unused
  |                                        | unwrap share_svc; reseal HPKE to e_pk (info binds txn, artifact_id)
  |                                        | grant = Sign_svc(artifact_id, sub, e_pk, txn, exp = now + 60s)
  |                                        | audit decryption_authorized
  |<--- sealed share_svc, grant -----------|
  |---- POST /v1/agent/release -------------------------------------------->|
  |   header_region, id_token, grant, e_pk, txn                              |
  |                                                                          | verify grant (service key)
  |                                                                          | validate id_token itself (own IdP)
  |                                                                          | nonce binding, txn single use
  |                                                                          | unwrap share_org; reseal to e_pk
  |<--- sealed share_org ---------------------------------------------------|
  | open both with e_sk; derive keys; decrypt locally; zeroize e_sk and shares
```

Why it is shaped this way:

- **Nonce binding.** The OIDC nonce is bound to the client's ephemeral key, so a malicious service cannot replay the user's ID token to the key agent with a key of its own choosing.
- **Independent check by the agent.** The key agent validates the user token against its own org's IdP, so it does not rely on the service alone.
- **Single-use transactions.** `txn` values are single use, with a short TTL, and are stored server-side. This prevents replay and gives audit records a correlation ID.
- **Coarse denial reasons.** Responses use only "not authorized", "expired or revoked" and "service unavailable", so they do not leak policy details to an attacker. The audit log holds the precise reason.

## 7. Authorization model

- **Default deny.** Being a member of the recipient org grants nothing.
- **Policy reference.** `policy_ref` in the signed header names a policy that the *recipient* org defines. The sender picks from policies the recipient has published, for example `incident-response`.
- **Policy terms.** A policy is a set of allow rules over:
  - subject (user IDs)
  - groups and roles (from verified IdP claims)
  - required authentication assurance (`acr`/`amr`, such as MFA or phishing-resistant)
  - time window
  - classification ceiling (planned; the classification is in the encrypted manifest, so the Phase 3 client enforces it)
  - device requirement (later phase)
  - optional admin approval (later phase)

  Implemented in Phase 2: subjects, groups, `acr`, time window and maximum age (`svx-server/src/policy.rs`).
- **Expiry.** `min(signed expires_at, policy max-age)` applies. The service can shorten expiry but never extend it.
- **Revocation.** Revocation is per artifact, per sender key, per user, or for a whole org (offboarding).

## 8. Audit

Events: `artifact_registered`, `access_attempted`, `authentication_success/failure`, `authorization_success/failure`, `decryption_authorized`, `artifact_opened`, `artifact_revoked`, `artifact_expired`, `signature_failure`, `integrity_failure`, `policy_violation`.

Each record contains:

- timestamp
- org
- pseudonymous subject
- artifact ID
- transaction ID
- event
- coarse reason
- client version

Records never contain payloads, keys, shares, tokens or file names. Audit logs are append-only and hash-chained per tenant. Admins see only their own org's records.

## 9. Tenant isolation

Every table and query is scoped by `org_id`, which comes from the authenticated principal and never from request parameters. Per-tenant KMS keys are used where the provider supports them. Authorization is always checked server-side.

## 10. What is public in a `.svx` file

| Field | Visible to anyone with the file? | Why |
|-------|----------------------------------|-----|
| Format version, suite | yes | needed to parse |
| Artifact ID | yes | random, opaque; needed for release and revocation |
| Created and expires timestamps | yes | needed for release requests; advisory |
| Sender, recipient and service IDs | yes | routing; opaque identifiers, not display names |
| Policy reference | yes | routing to the right policy; must be an opaque ID |
| Key IDs | yes | key lookup |
| Approximate payload size | yes (chunk count × chunk size) | inherent; senders can pad if this matters |
| File name, exact size, classification, description | **no** | in the encrypted manifest |
| Payload | **no** | encrypted |

## 10a. Personal accounts

A personal account is a one-person organization (`u.<16 hex>`) whose IdP is Google or Apple and whose registry record carries its verified email. The split-key model is unchanged: the service share is released by the service, and the recipient share is sealed to the recipient's own MLKEM1024-P384 key (one envelope per recipient) instead of an org key agent. Authorization is the sender's per-file rules (approval, one-time, expiry, revocation) instead of an org policy, and requests are signed with the device key instead of a fresh OIDC login. Details: [personal.md](personal.md).

## 11. Client layering

```text
   svx CLI         Python SDK (svx)        Node.js SDK (@svx/sdk)
      |            typed results/errors    typed results/errors
      |                   |                        |
      |            svx-py (PyO3)            svx-node (napi-rs)
      |                   |                        |
      +-------------------+------------------------+
                          |
              svx-client  (Client facade; open, pack, status, admin)
                          |
     svx-protocol (release, registry records)  svx-oidc  svx-core (format, crypto)
```

There is one implementation of every client-side security decision, in
`svx-client` and below. The CLI and both SDKs are presentation layers:

- local verification before any login;
- recipient and expiry checks;
- per-open, key-bound login;
- release from both the service and the key agent;
- fail-closed decryption with private temporary files and no-clobber rename.

The binding crates contain no hand-written `unsafe` code (CI checks this).
They pass structured results across the boundary as JSON, and every SDK
error carries the CLI's error category and exit code, so applications can
tell a security refusal from an outage.

