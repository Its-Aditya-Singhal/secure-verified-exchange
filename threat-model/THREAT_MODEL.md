# SVX Threat Model

Status: draft for SVX 1.0, Phase 3. It has not had an independent security review yet. No strong security claims should be made until that review is done.

## 1. What SVX protects

SVX protects one **artifact**: a file that Company A sends to Company B over infrastructure neither of them trusts. The goals are:

| ID | Property | Mechanism |
|----|----------|-----------|
| G1 | **Confidentiality in transit and at rest.** Holding a `.svx` file is not enough to read its payload or private metadata. | ChaCha20-Poly1305 payload encryption. The key is derived from two HPKE-sealed shares. |
| G2 | **Integrity.** Any change to any byte is detected before plaintext is released. | STREAM AEAD with the header hash as AAD, a payload commitment, and an Ed25519 signature. |
| G3 | **Sender authenticity.** The recipient can check which organization signed the artifact. | Ed25519 signature checked against a trust store (Phase 1) or the organization registry (Phase 2). |
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

Cryptographic assumptions: ChaCha20-Poly1305 is a secure AEAD; X25519 and HPKE (RFC 9180) are IND-CCA2; Ed25519 is SUF-CMA under strict verification; SHA-256 and HKDF-SHA256 behave as PRFs or random oracles where the profile relies on it; the OS CSPRNG is sound.

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

### T13. Sender signing-key compromise
- **Outcome:** an attacker can create artifacts that look like they came from Acme. Response: revoke the key in the registry (key status `revoked`, with a `not_after` timestamp) so verifiers reject it, then rotate. Retired keys still verify artifacts created before retirement. Revoked keys never do. ✅ (`revoked_sender_key_is_rejected`) See `docs/key-hierarchy.md`.

### T14. Recipient KEM-key or service-key compromise
- **Outcome:** one share is exposed for every artifact sealed to that key. The other share still protects them. Response: rotate (new `key_id`). Org KEM key rotation is supported, and the key agent accepts several keys. 🔜 Service KEM key rotation (several active service keys) is planned.

### T15. Downgrade
- **Outcome:** impossible by construction. SVX 1.0 defines exactly one suite, an unknown suite ID is rejected, and there is no negotiation. Unknown *critical* header fields are rejected. Unknown non-critical fields are still covered by the signature. ✅

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
- **Outcome:** TLS 1.3 with no plaintext fallback. In addition, released shares are HPKE-sealed to a per-request ephemeral client key, so TLS-terminating middleboxes never see share plaintext. The OIDC nonce binds the ID token to that key. ✅ (`token_bound_to_another_key_is_rejected`, `compromised_service_cannot_get_org_share`)

### T22. IdP or authorization-service outage
- **Outcome:** fail closed. No cached decryption capability survives outside the current session. A successful release that cannot be audited is refused. When the service is unreachable the client exits with code 3 and writes nothing. ✅ (CLI `service_unavailable_fails_closed`)

## 5. Security claims we will make (after review)

- "Encrypted before transfer."
- "Recipient-bound access."
- "Cryptographically verifiable integrity and sender authenticity."
- "Organization-based authentication and per-artifact authorization."
- "Managed expiration and revocation of future access."
- "The `.svx` file alone is not enough to decrypt protected content."
- "Neither the managed service nor the recipient's key agent can decrypt alone."

Each claim maps to G1 to G7 above and to tests in the repository.
