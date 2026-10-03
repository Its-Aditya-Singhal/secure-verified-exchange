# SVX Managed Service API (v1)

JSON over HTTPS. Binary blobs are standard base64; keys, IDs and transaction IDs are lowercase hex. Wire types live in `crates/svx-protocol`.

- **Errors:** every error has the body `{"error": "<reason>"}`.
  - **Reasons:** `invalid_request`, `invalid_artifact`, `not_authorized`, `expired_or_revoked`, `unavailable`, and for personal files `already_opened` and `declined`.
  - **Release endpoints** return only these coarse reasons. The precise reason goes to the audit log.
  - **Admin endpoints** may add a `"detail"` string.

| Status | Meaning |
|--------|---------|
| 400 | invalid request |
| 401 | admin authentication failed |
| 403 | not authorized, or expired or revoked |
| 404 | not found |
| 409 | conflict |
| 422 | invalid or untrusted artifact |
| 503 | unavailable (including internal errors, which are never echoed) |

## Public

### `GET /v1/service`
The service's public keys. Nothing here is trusted by itself. Clients pin `registry_fingerprint` out of band and accept `registry_public` only if its fingerprint matches the pin (see `spec/crypto-profile.md` §13). Key agents pin `grant_public` (as a key file). Both keys are hybrid Ed25519 + ML-DSA-65.
```json
{ "service_id": "svx.example", "kem_public": "<hex1216 X-Wing>", "grant_public": "<hex1984 Ed25519 + ML-DSA-65>", "registry_public": "<hex1984 Ed25519 + ML-DSA-65>", "registry_fingerprint": "<hex32>" }
```

### `GET /v1/service/record`
The service's public keys, signed with the registry key under context `"SVX-1 service\0"` (hybrid signature, both halves must verify). Records older than 15 minutes are rejected. `grant_public` must be a hybrid key.
```json
{ "record": "<b64 JSON {v, service_id, kem_public, grant_public, issued_at}>", "signature": "<b64>" }
```
Senders take the service KEM key from here instead of from the unsigned `/v1/service`.

### `GET /v1/registry/orgs/{org_id}`
Signed record of a **verified** organization. Returns 404 otherwise.
```json
{ "record": "<b64 JSON OrgRecord>", "signature": "<b64 Ed25519 ‖ ML-DSA-65, 3373 bytes>" }
```
The signature uses context `"SVX-1 registry\0"` over the exact record bytes. Clients reject records older than 15 minutes.

`OrgRecord` fields:

| Field | Value |
|-------|-------|
| `v` | protocol version (`2`: post-quantum hybrid keys; records of another version are refused) |
| `org_id` | org identifier |
| `display_name` | display name |
| `domain` | verified domain |
| `idp_issuer` | OIDC issuer |
| `key_agent_url` | key agent URL |
| `keys` | list of `{key_id, kind, public_key (hex), status: active\|retired\|revoked}`. `kind` is `ed25519-mldsa65` (1984-byte signing key, signs new files), `xwing` (1216-byte X25519 + ML-KEM-768 key, receives new files), or the classical `ed25519` / `x25519` (32 bytes, kept for older files) |
| `issued_at` | Unix seconds |
| `kind` | `company` (default) or `personal` |
| `account_email` | personal accounts only: the verified email the directory finds |

The service record also lists `personal_idps` (`{name, issuer, client_id, client_secret?}`): the sign-in providers for personal accounts.

## Organization lifecycle

### `POST /v1/orgs`
Register an organization. Returns the DNS challenge.

Request:
```json
{ "org_id": "example-corp", "display_name": "Example Corp", "domain": "example-corp.example",
  "idp_issuer": "https://login.example-corp.example", "idp_client_id": "svx",
  "group_claim": "groups", "key_agent_url": "https://svx-agent.example-corp.example" }
```

Response:
```json
{ "txt_name": "_svx-challenge.example-corp.example", "txt_value": "svx-verification=<hex>" }
```

Rules:
- **Registration conflicts.** A verified `org_id` cannot be registered again. A pending registration can be replaced after 7 days.
- **URLs.** `idp_issuer` and `key_agent_url` must be `https://`. Plain-http loopback URLs are accepted only in dev mode.

### `POST /v1/orgs/{org_id}/verify`
Request: `{"id_token": "<JWT from the org's IdP>"}`

The service checks:
- the TXT record;
- the ID token against the configured IdP (issuer, audience, signature, expiry, freshness);
- that the domain is not already owned by another verified org.

The token's `sub` becomes the first administrator.

## Administration
All admin endpoints share the same rules:
- **Authentication.** `Authorization: Bearer <ID token>` from **that org's** IdP.
- **Admin check.** The token's subject must be an administrator of the org named in the path.
- **Scope.** The path only selects the org. A token from another IdP, or from a non-admin, is refused (401) and audited.

| Method and path | Body | Effect |
|-----------------|------|--------|
| `GET /v1/admin/orgs/{org}` | none | Overview: settings, administrators (`{subject, added_at}`), keys with their lifecycle times |
| `PATCH /v1/admin/orgs/{org}` | `{display_name?, key_agent_url?, remove_key_agent?}` | Change the display name or key agent URL. The IdP can't be changed (it would hand over the org). |
| `PUT /v1/admin/orgs/{org}/keys` | `{kind, public_key, status}` | Add a key or change its status. `key_id` is derived by the server. Allowed transitions: active→retired→revoked, and active→revoked. Revocation is terminal. |
| `POST /v1/admin/orgs/{org}/admins` | `{subject}` | Add an administrator |
| `DELETE /v1/admin/orgs/{org}/admins/{subject}` | none | Remove an administrator; the last one can't be removed (409) |
| `PUT /v1/admin/orgs/{org}/policies/{name}` | `Policy` | Create or replace a policy |
| `DELETE /v1/admin/orgs/{org}/policies/{name}` | none | Delete a policy; files naming it are denied from then on |
| `POST /v1/admin/orgs/{org}/artifacts/{artifact_id}/revoke` | none | Revoke future access. Effective only if this org is the sender or recipient in the artifact's signed header. |
| `GET /v1/admin/orgs/{org}/policies` | none | All policies, as `{name: Policy}` |
| `GET /v1/admin/orgs/{org}/audit?limit=N&before_seq=S&event=E` | none | The latest N records (maximum 1000), optionally older than `S` and of one event kind, with `chain_valid` (record hashes, and links between records when not filtered) |

Admin and registration errors carry a human-readable `detail` (for example
"the last administrator can't be removed"); release errors never do.

`Policy`:
```json
{ "allow_users": ["alice"], "allow_groups": ["incident-response"], "require_acr": ["phr"],
  "max_age_secs": 604800, "not_before": null, "not_after": null }
```
Evaluation is default-deny. A user is allowed only if they match `allow_users` or `allow_groups` **and** every configured constraint holds. Expiry is `min(signed expires_at, created_at + max_age_secs)`.

## Artifacts and key release

### `POST /v1/artifacts` (optional)
- **Auth:** `Authorization: Bearer <ID token>` from the sender org's IdP.
- **Body:** `{header_region, trailer}`.
- **Effect:** records the artifact for the sender-side audit log (`artifact_registered`) and the recipient-side one (`artifact_shared`). Release does not depend on it.

### `POST /v1/release`
```json
{ "header_region": "<b64>", "trailer": "<b64>", "id_token": "<JWT>",
  "client_key": "<hex1216 X-Wing>", "txn": "<hex16>" }
```
The service checks, in order:
1. **The artifact.** Its header parses and names this service. Its signature verifies against the sender org's registered active key, or a retired key if the artifact was created before retirement. The recipient org is verified.
2. **The ID token.** It is validated against the **recipient** org's IdP, with `nonce == hex(SHA-256("SVX-1H oidc\0" ‖ client_key ‖ txn))`. The one-time `client_key` must be an X-Wing key; a classical key is refused with 400.
3. **Revocation.** Neither party has revoked the artifact.
4. **Policy and expiry.** The recipient org's policy `policy_ref` allows the user, and the artifact has not expired by the server's clock.
5. **Replay.** `txn` has not been used before. Transaction IDs are single-use.

On success it responds:
```json
{ "share": { "encapped_key": "<b64, 1120-byte X-Wing enc>", "ciphertext": "<b64>" },
  "grant": { "payload": "<b64 JSON Grant>", "signature": "<b64>", "key_id": "<hex16>" } }
```
- `share` is the service share, HPKE-sealed to `client_key` (crypto profile §12).
- `grant` is valid for 60 s and commits to:

| Grant field | Value |
|-------------|-------|
| `artifact_id` | the artifact |
| `header_hash` | hash of the verified header |
| `recipient_org` | the recipient org |
| `issuer`, `sub` | the authenticated user |
| `client_key_id` | the client's ephemeral key |
| `txn` | the transaction ID |
| `exp` | expiry |

## Personal accounts

See [personal.md](personal.md). Except for sign-up, every endpoint here needs a request signed with the account's device key: headers `svx-account`, `svx-key-id` (hex), `svx-time` (Unix seconds), `svx-nonce` (hex16) and `svx-signature` (base64), a hybrid signature under context `"SVX-1 account request\0"` over

```
METHOD \n path?query \n hex(SHA-256(body)) \n time \n hex(nonce) \n account \n hex(key_id)
```

The key must be an active `ed25519-mldsa65` key of the account, the time within 60 s, and the nonce unused (replays get 401 and an audit record).

| Endpoint | What |
|----------|------|
| `POST /v1/accounts` | Sign up or register this device: `{issuer, id_token, signing_public, kem_public, reset}`. The token's `nonce` must be `hex(SHA-256("SVX-1 sign-up\0" ‖ u16 len ‖ signing ‖ u16 len ‖ kem))` and its email verified. Same identity with other keys → 409 unless `reset`; keys of another account → 409. Returns `{account, email, issuer, created_at}`. |
| `GET /v1/me` | The account. |
| `GET /v1/directory?email=` | The signed registry record of the account with this email (30 lookups a minute per account). Clients check the signature and that `account_email` matches. |
| `POST /v1/me/files` | Register a file just made: `{header_region, trailer, rules: {require_approval, one_time, expires_at}}`. The sender must be the caller and every recipient a personal account. The rules' expiry can't be later than the signed one. |
| `GET /v1/me/files/{id}` | The sender's view: rules, revocation, each recipient's state (`not_opened`, `requested`, `approved`, `opened`, `declined`, `revoked`). |
| `PATCH /v1/me/files/{id}` | `{require_approval?, one_time?, expires_at?, revoke, revoke_recipients}`. |
| `POST /v1/personal/release` | `{header_region, trailer, client_key, txn}`. Checks registration, recipient, revocation, expiry, one-time use, approval, single-use `txn`. Answers `{"status": "pending", request_id, sender_email, expires_at}` (repeat the same request to poll) or `{"status": "released", share}`. |
| `POST /v1/personal/opened` | `{artifact_id, txn}`: decryption finished; a one-time open is final. |
| `GET /v1/me/requests` | Pending requests for the caller's files. |
| `POST /v1/me/requests/{id}/approve`, `…/decline` | Decide (only while pending). An approval lasts 24 h. |
| `GET /v1/me/history` | `{sent: [file status], received: [{artifact_id, sender, sender_email, created_at, state, requested_at, opened_at}]}`. |

The company `POST /v1/release` refuses personal and multi-recipient files.

### Relayed sign-in (Apple)

| Endpoint | What |
|----------|------|
| `POST /v1/auth/relay/start` | `{issuer, nonce, secret_hash}` for a provider with `relay: true` → `{relay_id, authorize_url, expires_at}`. The URL carries the service's `state`, PKCE challenge and `response_mode=form_post`. |
| `GET`/`POST /v1/auth/relay/callback` | The provider's return (query or form post). Exchanges the code with the service's client secret (Apple: ES256 JWT) and validates the ID token with the app's nonce. Shows a plain page; each `state` completes once. |
| `POST /v1/auth/relay/poll` | `{relay_id, secret}` (`SHA-256(secret)` must match) → `{"status": "pending"}`, `{"status": "done", id_token}` (once) or `{"status": "failed", reason}`. Wrong secret → 401. Sign-ins expire after 10 minutes. |

Relayed providers' client secrets are never published in the service record.

## Key agent

### `POST /v1/agent/release`
The agent is operated by the recipient org.
```json
{ "header_region": "<b64>", "id_token": "<JWT>", "client_key": "<hex1216 X-Wing>", "txn": "<hex16>", "grant": { ... } }
```
The agent checks:
1. **The grant.** It verifies under the **pinned** service grant key and is fresh.
2. **Grant binding.** The grant matches the header hash, the org, the service, the txn and the client key.
3. **The ID token.** It is validated against the agent's **own** IdP with the same nonce binding, and its `iss` and `sub` equal the grant's.
4. **Replay.** `txn` has not been used at this agent.

On success it returns `{"share": {...}}`, the recipient-org share HPKE-sealed to `client_key`.

### `GET /v1/agent/keys`
The KEM keys the agent holds: `{"org_id": "...", "keys": [{"key_id": "<hex16>", "kind": "xwing"}]}`. Public information, no authentication. Administrators' apps use it to activate a new encryption key only once the agent holds it. See [key-agent.md](key-agent.md).
