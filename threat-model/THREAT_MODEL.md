# SVX Threat Model

Status: draft for SVX 1.1 (post-quantum hybrid suite SVX-1H). It has not had an independent security review yet. No strong security claims should be made until that review is done.

## 1. What SVX protects

SVX protects one **artifact**: a file that Company A sends to Company B over infrastructure neither of them trusts. The goals are:

| ID | Property | Mechanism |
|----|----------|-----------|
| G1 | **Confidentiality in transit and at rest.** Holding a `.svx` file is not enough to read its payload or private metadata. | ChaCha20-Poly1305 payload encryption. The key is derived from two shares, each HPKE-sealed with X-Wing (X25519 + ML-KEM-768). |
| G2 | **Integrity.** Any change to any byte is detected before plaintext is released. | STREAM AEAD with the header hash as AAD, a payload commitment, and a composite Ed25519 + ML-DSA-65 signature (both must verify). |
| G3 | **Sender authenticity.** The recipient can check which organization signed the artifact. | Ed25519 + ML-DSA-65 signature checked against a trust store (Phase 1) or the organization registry (Phase 2). |
| G4 | **Recipient binding.** Only the named recipient organization can take part in decryption. | One share is sealed to the recipient org's key. HPKE `info` binds the artifact and both organization IDs. |
| G5 | **Managed access.** A user must be authenticated by their own org's IdP and authorized for this specific artifact before they get decryption capability. | The managed service releases the service share only after authN and authZ (Phase 2). |
| G6 | **Expiration and revocation.** Access can end at a set time or on demand. | Enforced server-side when keys are released. The signed `expires_at` is advisory on the client. |
| G7 | **Limited blast radius.** Compromising the managed service alone does not expose payloads. | Split key: the service never holds the recipient-org share. |
| G8 | **Metadata minimization.** Inspecting the file reveals only opaque routing identifiers. | File names, sizes, classification and description are kept in an encrypted manifest. |
| G9 | **Auditability.** Access attempts and key releases are recorded. | Managed-service audit log (Phase 2). |

## 2. Non-goals

SVX does **not** and cannot:

- protect plaintext after an authorized user has decrypted it (screenshots, copies, malware on the endpoint);
- erase plaintext that was already decrypted, even after revocation;
- hide that an exchange happened, its approximate size, or the opaque sender, recipient and service identifiers;
- replace TLS, enterprise identity providers, SIEM or EDR;
- execute code. A `.svx` file is passive data, and no field is ever interpreted as code.

SVX must never be marketed as "unhackable", "impossible to leak" or "100% secure".

## 3. Actors and trust assumptions

| Actor | Trusted for | Not trusted for |
|-------|-------------|-----------------|
| Sender org (Acme) | Content it sends and its signing key | Anything about the recipient |
| Recipient org (Example Corp) | Its IdP's assertions about its own users; its key agent | Other orgs' artifacts |
| Managed service (`svx.example`) | Enforcing policy and releasing the service share; audit | Seeing plaintext. It must not be able to decrypt on its own. |
| Recipient org's key agent | Releasing the org share to authenticated members after a service authorization | Deciding policy on its own |
| SVX client | Following the protocol and failing closed | Being uncompromised. A compromised endpoint is out of scope (see 2). |
| Transport (email, cloud, USB, HTTP) | Nothing | Everything |
| Eve (passive or active network attacker, file thief) | Nothing | Everything |
| Mallory (malicious organization or insider) | Her own org's keys | Impersonating others |

Cryptographic assumptions: ChaCha20-Poly1305 is a secure AEAD; HPKE (RFC 9180) with X-Wing is IND-CCA2 as long as **either** X25519 or ML-KEM-768 (FIPS 203) is secure; the composite signature is unforgeable as long as **either** Ed25519 (SUF-CMA under strict verification) or ML-DSA-65 (FIPS 204) is; for older SVX-1 files, X25519 and Ed25519 must hold; SHA-256 and HKDF-SHA256 behave as PRFs or random oracles where the profile relies on it; the OS CSPRNG is sound.

## 4. Threats and expected outcomes

Status key: ✅ enforced and tested (test names in parentheses). 🔜 designed here, built in a later phase.

### T1. Eve steals or intercepts `incident.svx`
- **Outcome:** Eve gets ciphertext plus the public header: opaque org IDs, artifact ID, timestamps, policy reference and chunk count. She gets no plaintext, file name or classification. ✅
- **Why:** the payload and manifest keys come from two 256-bit shares, each HPKE-sealed to a key Eve does not hold. There is no password, so offline guessing does not apply.
- **Test:** `intercepted_file_reveals_no_plaintext_or_private_metadata`.

### T2. Eve modifies the file
- **Outcome:** rejected before any plaintext is released. ✅
- **Why:** the header hash covers the prelude and every header byte. It is the AAD for every chunk and is signed. The payload commitment covers every chunk record and is signed. Chunk nonces bind position and finality. The trailer must be followed by EOF.
- **Tests:** `any_single_byte_modification_is_rejected` flips every byte. `chunk_reorder_rejected` and `truncation_and_extension_rejected` cover the rest. The invalid test vectors cover the same cases.

### T3. Eve replays an old artifact
- **Outcome:** the artifact still verifies, because it is authentic. Access is decided at key release, against the artifact's current state: expiry, revocation, and the policy at that moment. ✅
- **Mitigations:** unique 128-bit `artifact_id`; signed `created_at` and `expires_at`; recipient binding; server-side artifact registry; per-release transaction IDs with single-use nonces from the client; `suspicious_repeated_attempts` audit events after 5 denials within 10 minutes. ✅ (`replayed_transactions_are_rejected_by_service_and_agent`)
- Replaying an artifact *into a different context* fails. Envelopes are bound to artifact ID, sender, recipient and service, so they cannot be moved to a new artifact, and the header cannot be re-signed by someone else without breaking every chunk AEAD.

### T4. Eve steals an authorized user's copy
- **Outcome:** same as T1. The file on Alice's disk is still encrypted, and opening it still needs Alice's IdP session plus authorization. ✅ (`alice_authorized_decrypts_and_is_audited`, `bob_authenticated_but_not_authorized`)

### T5. Mallory pretends to be Acme (sender impersonation)
- **Outcome:** rejected. The signature must verify under a key that is trusted *for the claimed organization*. A valid key belonging to another org does not count. ✅
- **Test:** `untrusted_or_impersonating_sender_rejected`, vector `invalid-untrusted-signer`.

### T6. Someone pretends to be Example Corp (recipient impersonation)
- **Outcome:** fails. Identity assertions are accepted only from the IdP registered for that org, with issuer, audience, signature, expiry and nonce validated. The org share is sealed to Example Corp's key. ✅ (`eve_with_wrong_idp_or_no_token_is_denied`, `org_verification_requires_dns_and_idp`)
- Org registration requires domain verification (DNS TXT) plus an administrator-controlled IdP configuration. See `docs/architecture.md` §5.

### T7. An authenticated Example Corp employee who is not authorized
- **Outcome:** authentication succeeds, authorization fails, no share is released, no decryption happens. The event is audited. ✅ (`bob_authenticated_but_not_authorized`)
- Membership of the recipient org is never enough by itself. Policies name users, groups or roles, and default to deny.

### T8. Expired artifact
- **Outcome:** the service refuses key release after `expires_at`, using its own clock, not the client's. The client also refuses (fail closed) when its own clock says the artifact has expired. ✅ (`expired_artifacts_are_denied`, CLI `tampered_and_expired_are_refused_before_login`)
- Service-side policy can shorten expiry but never extend it past the signed value.

### T9. Revoked artifact
- **Outcome:** the service refuses key release from the moment of revocation. Only the sender org or the recipient org named in the signed header can revoke. ✅ (`revoked_artifact_is_denied_after_revocation`)
- **Limitation:** plaintext that was already decrypted cannot be recalled. This is documented in the client UI and in the docs.

### T10. Compromised recipient endpoint
- **Out of scope** for prevention. Malware on an authorized endpoint can read the plaintext once it is decrypted. Mitigations to reduce exposure: audit logs, short expiry, the device-trust policies planned for later phases, controlled viewers, and keeping plaintext persistence to a minimum.

### T11. Malicious or compromised managed service
- **Outcome:** the service can unwrap only the *service* share. Without the recipient-org share, which is sealed to a key held in the recipient's KMS or key agent, it cannot derive the payload key. ✅ (crypto property, tested in `file_alone_is_insufficient_one_share_is_insufficient`)
- **Key agent safeguard:** the recipient key agent independently validates the user's ID token against its own IdP and requires the nonce binding. A compromised service that holds the grant key still cannot obtain the org share for a key of its own. ✅ (`compromised_service_cannot_get_org_share`)
- **Residual risk:** a malicious service can deny access, release its share to the wrong user, or lie in audit logs. Releasing its share to the wrong user still needs the recipient org's key agent to cooperate. Keeping the org key agent separate from the service is what makes this split meaningful. Deployments where one operator runs both lose G7, and the docs must say so.
- **Residual risk:** a service that also compromises the recipient org's key agent can decrypt. Defense in depth: KMS/HSM-held keys and separate operators.

### T12. Compromised recipient-org key agent
- **Outcome:** the agent alone holds only one share. It still needs the service share, which is released only after policy checks. ✅ (crypto property)
- **Hardening:** the packaged agent runs as an unprivileged user (container: distroless, read-only, no capabilities; systemd: dynamic user, strict sandbox, keys as credentials), refuses world-readable key files and refuses to start without a post-quantum key. Its `GET /v1/agent/keys` lists only public key IDs. ✅ (`keys_are_checked`, `readable_secret_keys_are_refused`, CI `keyagent-package`)
- **Rotation safety:** a new encryption key is activated in the registry only after the agent reports holding it, so no file is sealed to a key the agent can't use. ✅ (`encryption_key_rotation_waits_for_the_agent`)

### T12a. Administration abuse
- **Outcome:** every admin action is authorized by the service against the org's own IdP and admin list, and audited. An organization can't be left without an administrator, its IdP can't be swapped through the API, and admin error details never appear on release endpoints. ✅ (`admins_settings_policies_and_audit`)

### T13. Sender signing-key compromise
- **Storage:** keys created in the desktop app live in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) and are only used inside the Rust client layer; the UI never sees them. Each sender's device has its own registered key, so one lost device means revoking one key. ✅ (`keychain_signing_key_signs_files`)
- **Outcome:** an attacker can create artifacts that look like they came from Acme. Response: revoke the key in the registry (key status `revoked`, with a `not_after` timestamp) so verifiers reject it, then rotate. Retired keys still verify artifacts created before retirement. Revoked keys never do. ✅ (`revoked_sender_key_is_rejected`) See `docs/key-hierarchy.md`.

### T14. Recipient KEM-key or service-key compromise
- **Outcome:** one share is exposed for every artifact sealed to that key. The other share still protects them. Response: rotate (new `key_id`). Org KEM key rotation is supported: the key agent and the service both hold several KEM keys and pick one by the envelope's key ID. The service publishes its first X-Wing key. ✅

### T15. Downgrade
- **Outcome:** prevented. Readers accept two suites: SVX-1H (`0x0003`, post-quantum hybrid) and, to open older files, SVX-1 (`0x0001`). There is no negotiation: the suite is fixed in each file's prelude, which the header hash covers and the signature signs. Every writer (client, CLI, SDKs, desktop app) produces only SVX-1H. Suite `0x0003` requires the v2 envelope field and a 1120-byte X-Wing `enc`, and suite `0x0001` forbids it, so a rewritten suite ID fails parsing even before the signature check. Every key-derivation, envelope, release and signature label names its suite, so values from one suite are useless in the other. Unknown suite IDs and unknown *critical* header fields are rejected; unknown non-critical fields are still covered by the signature. ✅ (`hybrid_cannot_be_downgraded_or_mixed`, `suite_and_envelope_layout_must_agree`, `signatures_do_not_cross_suites`, test vector `hybrid-invalid-downgraded-suite`)

### T16. Malicious input aimed at the parser (DoS, memory exhaustion, parser bugs)
- **Mitigations:** Rust with `#![forbid(unsafe_code)]`; every length is bounded before allocation (header ≤ 1 MiB, field ≤ 256 KiB, chunk ≤ 16 MiB, ≤ 16 envelopes, manifest ≤ 64 KiB); strict TLV ordering; no recursion; streaming with O(chunk) memory; no compression, so decompression bombs cannot occur. ✅
- **Tests:** proptest over random and mutated inputs, every truncation point, and cargo-fuzz targets `parse`, `verify_open` and `manifest`.

### T17. Path traversal and malicious file names in the manifest
- **Outcome:** the manifest is validated even though it is authenticated. Path separators, `..`, control characters, Windows reserved names and trailing dots or spaces are all rejected. ✅
- The client writes output only into the directory the user chose (default `~/SVX`, 0700) and joins only a single validated path component. ✅ (`output_paths`, CLI `alice_opens_bob_is_denied`)

### T18. Key-share confusion (partitioning or invisible-salamander style attacks)
- **Outcome:** prevented. The header carries an HKDF-derived **key commitment**, which is checked in constant time before any decryption, so a wrong share cannot produce a "valid" different plaintext. ✅

### T19. Artifact swapped between verification and decryption (TOCTOU)
- **Outcome:** rejected. Decryption recomputes the header hash and the payload commitment and compares them to the values that were verified. ✅ (`artifact_swapped_between_verify_and_decrypt`)

### T20. Key or plaintext leakage through logs or memory
- **Mitigations:** every secret type zeroizes on drop and has a redacted `Debug`. The CLI never prints key material. Plaintext buffers are zeroized. Audit records will never contain payloads, keys or tokens. ✅ (key redaction tested)
- **Limitation:** Rust cannot guarantee that no copies remain, for example after a reallocation, in swap, or in core dumps. Production clients should disable core dumps and use mlock where available.
- The client keeps plaintext in a private 0600 temp file and renames it into place only after full authentication. Partial output is deleted on failure. The admin session file is 0600 and short-lived, and it can never release shares because release requires a key-bound nonce. ✅ (`docs/client.md`)

### T21. Network interception between client and service
- **Outcome:** TLS 1.3 with no plaintext fallback, using the post-quantum hybrid key exchange X25519MLKEM768 (offered first by the client and preferred by the service and key agent). In addition, released shares are HPKE-sealed with X-Wing to a per-request one-time client key, so TLS-terminating middleboxes never see share plaintext; classical one-time keys are refused. The OIDC nonce binds the ID token to that key. ✅ (`token_bound_to_another_key_is_rejected`, `compromised_service_cannot_get_org_share`, `classical_client_keys_are_refused`, `tls_pq`)

### T22. IdP or authorization-service outage
- **Outcome:** fail closed. No cached decryption capability survives outside the current session. A successful release that cannot be audited is refused. When the service is unreachable the client exits with code 3 and writes nothing. ✅ (CLI `service_unavailable_fails_closed`)

### T23. Harvest now, decrypt later (a future quantum computer)
- **Threat:** Eve records `.svx` files, or the TLS traffic of a key release, today and keeps them until a large quantum computer can break X25519 and Ed25519 (Shor's algorithm), possibly 10–15 years from now.
- **Outcome:** mitigated for every file made with SVX 1.1 or later. ✅
  - Both key shares are sealed with X-Wing, the hybrid of X25519 and ML-KEM-768. Recovering a share needs breaking **both**.
  - Released shares are re-sealed to an X-Wing one-time key, and the TLS connection itself uses X25519MLKEM768, so a recording of the release reveals nothing later.
  - Files are signed with Ed25519 **and** ML-DSA-65; a forgery needs breaking both.
  - The service signs registry records, the service record and release grants with Ed25519 **and** ML-DSA-65 too, so a quantum attacker cannot forge an organization's keys and make senders seal files to the attacker. Clients pin a 256-bit fingerprint of the hybrid registry key.
  - Payload and manifest encryption use 256-bit ChaCha20-Poly1305 keys, which keep a large margin against quantum search (Grover).
- **Limitations:** files made before the upgrade (suite SVX-1) remain classical; re-issue the ones that must stay confidential for decades. TLS server certificates are still classical (the WebPKI has no ML-DSA certificates yet); certificate authentication happens live during the handshake, so a recording gives nothing later, and the key exchange is already post-quantum. OIDC tokens and IdP TLS depend on each organization's IdP.
- **Tests:** KATs for X-Wing (HPKE PQ vectors) and ML-DSA-65 (NIST ACVP); `hybrid_signature_needs_both_halves`; `legacy_classical_files_still_open`; hybrid test vectors; `context_signatures_are_hybrid_and_domain_separated`, `context_signatures_refuse_classical_keys`, `registry_key_must_match_the_pinned_fingerprint`, `setup_verifies_against_the_pin`, the Ed25519-only grant refused by the key agent (`managed_flow`).

### T24. Personal accounts (Phase 5d)
Personal accounts sign in with Google or Apple once per device, then sign each request with the device key; the recipient's half of every file key is sealed to their own X-Wing key in the keychain. See [docs/personal.md](../docs/personal.md).
- **Stolen device keys.** A thief with the keychain can make signed requests as the account and unseal its halves, but the service still enforces each sender's rules (approval, one-time, expiry, revocation). The owner stops it by resetting the keys from another device (old keys retire; signed requests with them fail). ⚠️ Keys are software keychain keys, not hardware-bound (Secure Enclave/TPM later).
- **Captured sign-in token.** The ID token's nonce binds the device's two public keys, so it can't register an attacker's keys. Sign-up requires `email_verified`. A backup's keys can't be registered to another account.
- **Replayed or altered requests.** Every signed request covers method, path, body hash, time and a nonce: ±60 s and single-use (`signed_requests_are_single_use_and_bound`, demo check 16).
- **Wrong person in the directory.** The email ↔ keys binding is inside the registry-signed record; clients check the signature with the pinned key and that the record's email is the one they asked for. Lookups need a signed-in account and are rate-limited (30/min), which limits enumeration.
- **Approval phishing.** Someone asks the sender to approve while pretending to be the recipient. Only the named recipients' keys can unseal the recipient half, so an outsider gains nothing from an approval; the residual risk is a recipient's compromised device. The app asks the sender to confirm by another channel; emails have no links and no file names.
- **One-time limits.** One-time stops re-opening and forwarding the `.svx` (the service won't release again), not copies of plaintext already decrypted. A 10-minute window after release allows a retry after a crash, unless the receipt already made it final.
- **Service sees metadata.** Who sent to whom and when, not file names or contents (names stay in the app's local `history.json`). Emails go through the configured SMTP provider over TLS.
- **Apple private-relay emails** are per-app addresses; the directory finds such an account only by that address.
- **Relayed sign-in (Apple).** The service receives the provider's callback and holds the ID token for at most 10 minutes. Only the holder of the app's random secret (the service stores its hash) can collect it, once; the nonce still binds the app's own keys, so a token taken from the service can't register other keys. The callback page reflects nothing from the request (CSP `default-src 'none'`), each `state` completes once, and Apple's client secret never leaves the service (tests `relayed_sign_in`, `refused_or_forged_callbacks`, `apple_style_sign_in_is_relayed_by_the_service`).

## 5. Security claims we will make (after review)

- "Encrypted before transfer."
- "Recipient-bound access."
- "Cryptographically verifiable integrity and sender authenticity."
- "Organization-based authentication and per-artifact authorization."
- "Managed expiration and revocation of future access."
- "The `.svx` file alone is not enough to decrypt protected content."
- "Neither the managed service nor the recipient's key agent can decrypt alone."

Each claim maps to G1 to G7 above and to tests in the repository.
