# SVX Managed Service API (v1)

JSON over HTTPS. Binary blobs are standard base64; keys, IDs and transaction IDs are lowercase hex. Wire types live in `crates/svx-protocol`.

- **Errors:** every error has the body `{"error": "<reason>"}`.
  - **Reasons:** `invalid_request`, `invalid_artifact`, `not_authorized`, `expired_or_revoked`, `unavailable`.
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
The service's public keys. Clients **pin** `registry_public` out of band. Key agents pin `grant_public`.
```json
{ "service_id": "svx.example", "kem_public": "<hex1216 X-Wing>", "grant_public": "<hex32>", "registry_public": "<hex32>" }
```

### `GET /v1/service/record`
The service's public keys, signed with the registry key under context `"SVX-1 service\0"`. Records older than 15 minutes are rejected.
```json
{ "record": "<b64 JSON {v, service_id, kem_public, grant_public, issued_at}>", "signature": "<b64>" }
```
Senders take the service KEM key from here instead of from the unsigned `/v1/service`.

### `GET /v1/registry/orgs/{org_id}`
Signed record of a **verified** organization. Returns 404 otherwise.
```json
{ "record": "<b64 JSON OrgRecord>", "signature": "<b64 Ed25519>" }
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
| `PUT /v1/admin/orgs/{org}/keys` | `{kind, public_key, status}` | Add a key or change its status. `key_id` is derived by the server. Allowed transitions: active→retired→revoked, and active→revoked. Revocation is terminal. |
| `POST /v1/admin/orgs/{org}/admins` | `{subject}` | Add an administrator |
| `PUT /v1/admin/orgs/{org}/policies/{name}` | `Policy` | Create or replace a policy |
| `POST /v1/admin/orgs/{org}/artifacts/{artifact_id}/revoke` | none | Revoke future access. Effective only if this org is the sender or recipient in the artifact's signed header. |
| `GET /v1/admin/orgs/{org}/policies` | none | All policies, as `{name: Policy}` |
| `GET /v1/admin/orgs/{org}/audit?limit=N` | none | The latest N records (maximum 1000), returned with `chain_valid` |

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
