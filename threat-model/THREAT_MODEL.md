# SVX Threat Model

Status: draft for SVX 1.3 (maximum-strength suite SVX-2; SVX-1H and SVX-1 files still open). It has not had an independent security review yet. No strong security claims should be made until that review is done.

## 1. What SVX protects

SVX protects one **artifact**: a file that Company A sends to Company B over infrastructure neither of them trusts. The goals are:

| ID | Property | Mechanism |
|----|----------|-----------|
| G1 | **Confidentiality in transit and at rest.** Holding a `.svx` file is not enough to read its payload or private metadata. | ChaCha20-Poly1305 payload encryption. The key is derived from two shares, each HPKE-sealed with MLKEM1024-P384 (ML-KEM-1024 + P-384). |
| G2 | **Integrity.** Any change to any byte is detected before plaintext is released. | STREAM AEAD with the header hash as AAD, a payload commitment, and a triple Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s signature (all three must verify). |
| G3 | **Sender authenticity.** The recipient can check which organization signed the artifact. | Ed25519 + ML-DSA-87 + SLH-DSA signature checked against a trust store (Phase 1) or the organization registry (Phase 2). |
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

Cryptographic assumptions: ChaCha20-Poly1305 is a secure AEAD; HPKE (RFC 9180) with MLKEM1024-P384 is IND-CCA2 as long as **either** P-384 or ML-KEM-1024 (FIPS 203) is secure; the triple signature is unforgeable as long as **any one** of Ed25519 (SUF-CMA under strict verification), ML-DSA-87 (FIPS 204) or SLH-DSA-SHA2-256s (FIPS 205; security rests only on SHA-2) is; SHA-512 and HKDF-SHA512 behave as PRFs or random oracles where the profile relies on it; the OS CSPRNG is sound. For older files: X-Wing and Ed25519 + ML-DSA-65 with SHA-256 (SVX-1H), X25519 and Ed25519 (SVX-1).

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
- **Outcome:** one share is exposed for every artifact sealed to that key. The other share still protects them. Response: rotate (new `key_id`). Org KEM key rotation is supported: the key agent and the service both hold several KEM keys and pick one by the envelope's key ID. The service publishes its first MLKEM1024-P384 key. ✅

### T15. Downgrade
- **Outcome:** prevented. Readers accept three suites: SVX-2 (`0x0004`, maximum strength) and, to open older files, SVX-1H (`0x0003`) and SVX-1 (`0x0001`). There is no negotiation: the suite is fixed in each file's prelude, which the header hash covers and the signature signs. Every writer (client, CLI, SDKs, desktop app) produces only SVX-2. Suite `0x0004` requires the v2 envelope field with 1665-byte MLKEM1024-P384 `enc`s, suite `0x0003` requires 1120-byte X-Wing `enc`s, and suite `0x0001` forbids the v2 field, so a rewritten suite ID fails parsing even before the signature check. The signature length and `sig_alg` are fixed per suite too. Every key-derivation, envelope, release and signature label names its suite, so values from one suite are useless in the other. Unknown suite IDs and unknown *critical* header fields are rejected; unknown non-critical fields are still covered by the signature. ✅ (`hybrid_cannot_be_downgraded_or_mixed`, `suite_and_envelope_layout_must_agree`, `signatures_do_not_cross_suites`, test vectors `hybrid-invalid-downgraded-suite` and `max-invalid-downgraded-suite`)

### T16. Malicious input aimed at the parser (DoS, memory exhaustion, parser bugs)
- **Mitigations:** Rust with `#![forbid(unsafe_code)]`; every length is bounded before allocation (header ≤ 1 MiB, field ≤ 256 KiB, chunk ≤ 16 MiB, ≤ 16 envelopes, manifest ≤ 64 KiB); strict TLV ordering; no recursion; streaming with O(chunk) memory; no compression, so decompression bombs cannot occur. ✅
- **Tests:** proptest over random and mutated inputs, every truncation point, and cargo-fuzz targets `parse`, `verify_open` and `manifest` for the container, plus `backup_open`, `grant_verify`, `registry_record`, `request_auth`, `wire_json`, `folder_extract`, `keyfile_parse`, `password_check` and `update_manifest` for everything else that parses untrusted input. CI runs a short smoke run; `scripts/fuzz-local.sh` runs them for hours with a kept corpus.

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
- **Outcome:** TLS 1.3 with no plaintext fallback, using the post-quantum hybrid key exchange X25519MLKEM768 (offered first by the client and preferred by the service and key agent). In addition, released shares are HPKE-sealed with MLKEM1024-P384 to a per-request one-time client key, so TLS-terminating middleboxes never see share plaintext; X25519 and X-Wing one-time keys are refused. The OIDC nonce binds the ID token to that key. ✅ (`token_bound_to_another_key_is_rejected`, `compromised_service_cannot_get_org_share`, `older_client_keys_are_refused`, `tls_pq`)

### T22. IdP or authorization-service outage
- **Outcome:** fail closed. No cached decryption capability survives outside the current session. A successful release that cannot be audited is refused. When the service is unreachable the client exits with code 3 and writes nothing. ✅ (CLI `service_unavailable_fails_closed`)

### T23. Harvest now, decrypt later (a future quantum computer)
- **Threat:** Eve records `.svx` files, or the TLS traffic of a key release, today and keeps them until a large quantum computer can break X25519 and Ed25519 (Shor's algorithm), possibly 10–15 years from now.
- **Outcome:** mitigated for every file made with SVX 1.1 or later, at NIST's highest category (5) since SVX 1.3. ✅
  - Both key shares are sealed with MLKEM1024-P384, the hybrid of ML-KEM-1024 and P-384. Recovering a share needs breaking **both**.
  - Released shares are re-sealed to an MLKEM1024-P384 one-time key, and the TLS connection itself uses X25519MLKEM768, so a recording of the release reveals nothing later. (TLS is only a second layer here: the shares inside are already sealed end-to-end at category 5.)
  - Files are signed with Ed25519 **and** ML-DSA-87 **and** SLH-DSA-SHA2-256s; a forgery needs breaking all three (see T25).
  - The service signs registry records and the service record with all three, and release grants with Ed25519 **and** ML-DSA-87, so a quantum attacker cannot forge an organization's keys and make senders seal files to the attacker. Clients pin a 256-bit fingerprint of the SVX-2 registry key.
  - Header hash, payload commitment and key schedule use SHA-512 and HKDF-SHA512.
  - Payload and manifest encryption use 256-bit ChaCha20-Poly1305 keys, which keep a large margin against quantum search (Grover).
- **Limitations:** files made before SVX 1.3 stay at their own suite's strength (SVX-1H: category 3; SVX-1: classical); re-issue the ones that must stay confidential for decades; re-issue the ones that must stay confidential for decades. TLS server certificates are still classical (the WebPKI has no ML-DSA certificates yet); certificate authentication happens live during the handshake, so a recording gives nothing later, and the key exchange is already post-quantum. OIDC tokens and IdP TLS depend on each organization's IdP.
- **Tests:** KATs for X-Wing and MLKEM1024-P384 (HPKE PQ vectors), ML-DSA-65, ML-DSA-87 and SLH-DSA-SHA2-256s (NIST ACVP); `hybrid_signature_needs_both_halves`, `max_signature_needs_all_three_parts`, `max_context_signatures_full_and_fast`, `max_suite_properties`; `max-*` test vectors; `legacy_classical_files_still_open`; hybrid test vectors; `context_signatures_are_hybrid_and_domain_separated`, `context_signatures_refuse_classical_keys`, `registry_key_must_match_the_pinned_fingerprint`, `setup_verifies_against_the_pin`, the Ed25519-only grant refused by the key agent (`managed_flow`).

### T24. Personal accounts (Phase 5d)
Personal accounts sign in with Google, or with an email address and a password (T26), once per device, then sign each request with the device key; the recipient's half of every file key is sealed to their own MLKEM1024-P384 key in the keychain. See [docs/personal.md](../docs/personal.md).
- **Stolen device keys.** A thief with the keychain can make signed requests as the account and unseal its halves, but the service still enforces each sender's rules (approval, one-time, expiry, revocation). The owner stops it by resetting the keys from another device (old keys retire; signed requests with them fail). ⚠️ Keys are software keychain keys, not hardware-bound; the desktop app asks for Touch ID or the password before using them (T27).
- **Captured sign-in token.** The ID token's nonce binds the device's two public keys, so it can't register an attacker's keys. Sign-up requires `email_verified`. A backup's keys can't be registered to another account.
- **Replayed or altered requests.** Every signed request covers method, path, body hash, time and a nonce: ±60 s and single-use (`signed_requests_are_single_use_and_bound`, demo check 16).
- **Wrong person in the directory.** The email ↔ keys binding is inside the registry-signed record; clients check the signature with the pinned key and that the record's email is the one they asked for. Lookups need a signed-in account and are rate-limited (30/min), which limits enumeration.
- **Approval phishing.** Someone asks the sender to approve while pretending to be the recipient. Only the named recipients' keys can unseal the recipient half, so an outsider gains nothing from an approval; the residual risk is a recipient's compromised device. The app asks the sender to confirm by another channel; emails have no links and no file names.
- **One-time limits.** One-time stops re-opening and forwarding the `.svx` (the service won't release again), not copies of plaintext already decrypted. A 10-minute window after release allows a retry after a crash, unless the receipt already made it final.
- **Service sees metadata.** Who sent to whom and when, not file names or contents (names stay in the app's local `history.json`). Emails go through the configured SMTP provider over TLS.

### T25. A break of one signature family (lattices, elliptic curves or hashes)
- **Threat:** a cryptanalytic advance against lattice problems breaks ML-DSA (and ML-KEM), or a quantum computer breaks Ed25519 and P-384, and Eve forges a file or a registry record.
- **Outcome:** mitigated. SVX-2 signatures on files and on registry and service records need Ed25519 **and** ML-DSA-87 **and** SLH-DSA-SHA2-256s to verify. SLH-DSA's security rests only on the hash function, so it survives a break of both lattices and elliptic curves. Release grants and account requests carry Ed25519 + ML-DSA-87 only: they expire within about a minute and are bound to one transaction, so a forgery would have to happen live. Encryption has the matching hedge in the KEM: MLKEM1024-P384 stays secure if either half holds. ✅ (`max_signature_needs_all_three_parts`, `max_context_signatures_full_and_fast`, vectors `max-invalid-{ed25519,mldsa,slhdsa}-tampered`)
- **Limitations:**
  - The SLH-DSA library (RustCrypto `slh-dsa`) is a release candidate, pinned to `=0.2.0-rc.5` and checked against NIST ACVP key-generation and verification vectors. Because every part must verify, a bug in it can cause false refusals but never accept a forgery that the other two parts reject. Move to the stable release when it ships.
  - SLH-DSA-SHA2-256s was chosen over the SHAKE variant and over `256f`: SHA2 is several times faster in software, and `s` signatures are about half the size of `f`. Signing a file takes about 0.2 s and adds about 34 KB.
  - No cipher cascade: the payload stays a single ChaCha20-Poly1305 layer with a 256-bit key (discussed and declined). A code-based KEM (Classic McEliece) was also considered and declined: it has no audited Rust implementation and very large keys.

### T26. Email + password accounts
People without Google create an account with an email address and a password; the service is their sign-in provider. See [docs/personal.md](../docs/personal.md#email-accounts).
- **Claiming someone else's address** (to receive files sent to `bob@…`): every step that binds keys needs a fresh 6-digit code sent to that address. Codes are random, stored only as a hash, used once, valid 10 minutes, 5 tries each, and at most 5 codes an hour per address, so guessing succeeds with probability about 25 in a million per address per hour. ✅ (`codes_are_single_use_short_lived_and_limited`)
- **Taking over an existing account** needs both the password and the code from the inbox; ten wrong passwords lock the account for 15 minutes. A new device still can't open old files without the backup; resetting keys is visible to the owner (other devices stop working). ✅ (`new_device_lock_out_reset_and_change`)
- **Account discovery.** Code requests answer the same whether or not an account exists, and sign-in and reset codes go only to email accounts, so the endpoint doesn't reveal who has one. The signed directory already shows that an address has an account to signed-in users (T24). ✅ (`code_requests_dont_reveal_accounts`)
- **Weak or reused passwords:** 12–128 characters, zxcvbn score ≥ 3, not made from the person's name or email; checked again by the service (`weak_passwords_bad_names_and_taken_emails_are_refused`). Hashes are Argon2id (64 MiB, t=3); a stolen database still costs that per guess, and a cracked password alone is not enough (the code is needed too). Codes never sit in the database or mail queue in clear.
- **A compromised mailbox** gives an attacker the codes; with the password too, they can register their own keys (a key reset), which the owner notices because their devices stop working. Files already sent to the owner's old keys stay unreadable to the attacker.
- **Name spoofing:** names are shown next to the verified address and can't contain `@`, `<` or `>`.
- **Mail volume:** a global limit (120 codes a minute) protects the sending account (Gmail allows about 500 a day).
- **No Apple sign-in:** removed (it needs a paid Apple developer account). Migration 0006 drops the relay table.

### T27. Someone using an unlocked computer
- **Threat:** a colleague or thief at the user's unlocked computer sends files as them, opens files sent to them, approves a request, or exports a backup of their keys.
- **Outcome:** mitigated in the desktop app. The client library asks for Touch ID or the computer's password (Windows Hello) once per session, before sending, opening, changing or revoking files, and every time before approving, saving a backup, changing the password, signing out or changing organization keys. A refusal fails closed before anything is signed, decrypted or written. Turning the check off, or making sessions longer, needs a confirmation. ✅ (`presence_gate_is_enforced_by_the_client`, `presence_settings_need_a_confirmation`)
- **Limitations:** a software gate. Malware running as the user can call the keychain directly (subject to the keychain's own prompts) or edit `desktop.json`; only keys bound to the Secure Enclave or a TPM would stop that, and those need an app signed with a paid Developer ID. Development services and the CLI (without `--require-presence`) don't ask. Linux has no prompt.

### T28. A malicious app update
- **Threat:** an attacker who controls the update server, the network or the SVX service ships a modified app, or an old vulnerable version, to every user.
- **Outcome:** mitigated. The app installs an update only if (1) the release manifest verifies with all three signatures of the SVX-2 release key whose fingerprint is built into the app, (2) its version is newer than the running one, (3) the package's Tauri (minisign) signature verifies, including the version it records, and (4) the download's size and SHA-512 match the signed manifest. Both keys are kept offline; the service only serves files. ✅ (`signed_updates_newer_only_and_matching`, `sign_verify_and_tamper`, `update_manifest` fuzz target)
- **Limitations:** a malicious server can withhold updates (freeze), not roll back. The installers themselves are unsigned (no paid certificates), so the first download relies on its https channel, and macOS Gatekeeper warns once. Losing a release key means users must reinstall by hand; see [docs/releasing.md](../docs/releasing.md).

### T29. A recipient keeps a view-only file (Phase 7)
- **Threat:** a recipient of a file the sender limited to viewing saves, copies, prints, captures or shares it anyway, or asks the sender for permission under false pretences.
- **What the design does:**
  1. **The flag is signed into the file** (format 1.4, critical field `0x8010`, SVX-2 only). Older apps and the SDKs refuse such a file outright; the service registers a file only with the rule that matches the flag, and refuses to make a normal file view-only later (it holds nothing the viewer can show). A company open of a flagged file is refused before any sign-in. ✅ (`max-valid-view-only`, `the_registered_rule_must_match_the_signed_flag`, `a_company_open_never_saves_a_view_only_file`)
  2. **The service releases the key for *saving* only with the sender's permission** (an approved share request, valid 24 h, or the sender turning view-only off), and refuses before using up a one-time open. On a one-time file whose single view is used, an approved share request allows exactly one save (with the retry window) and no further view (`an_approved_copy_works_once_even_after_a_one_time_view`). Share requests are their own kind of request: approving one doesn't open the file, approving an open doesn't allow saving, a decline stands for 24 h, one request waits at a time, emails name the requester only, and everything is audited. ✅ (`a_view_only_file_can_be_saved_only_with_the_senders_permission`, `view_only_rules_are_the_senders_to_change`, `share_requests_and_open_requests_stay_apart`)
  3. **Viewing keeps everything in memory.** `Client::view_personal` decrypts into a buffer that is reserved up front and never reallocates (no stray copies), checks the container strictly, hands the display copy to the viewer and wipes it when the view ends. Nothing is written to disk, no temporary file, no container. Saving (once allowed) writes the sender's original, never the container. ✅ (`viewing_stays_in_memory_and_asks_every_time`, `saving_writes_the_original_not_the_container`, `the_buffer_never_grows`)
  4. **The viewer shows pictures only.** The document is opened by `svx-viewer` (pure Rust, fuzzed, size and page limits); the web layer of the viewer window receives rendered pages as raw pixels with the recipient's email, the time and a short file ID **burned into the pixels in Rust**, never the document, its text or its bytes, so there is nothing to copy, save or print. The keyboard and context-menu handlers in the page are only friction. Each view command answers only the window its session belongs to. ✅ (`pages_come_out_as_pixels_with_the_size_up_front`, `a_view_answers_only_its_own_window`, watermark tests in `svx-viewer`)
  5. **The window is hidden from screenshots and recordings by the operating system** (`content_protected`: macOS window sharing type, Windows `WDA_EXCLUDEFROMCAPTURE`). It is created hidden, protected at creation and again afterwards, and shown only once that worked; if it can't be set there is no viewer. Locking the app closes every viewer.
  6. **Fails closed where it can't be kept:** Linux has no such OS support, so the client refuses to show a view-only file there (`view_unsupported`) before asking the service.
  7. Each view asks the service again (nothing is kept on disk), so revoking, expiring or switching a rule takes effect on the next view; a one-time view-only file can be viewed once.
- **What is *not* stopped (do not rely on view-only against a determined recipient):**
  - **A photo of the screen**, or someone reading it over the shoulder. The watermark only discourages it and traces it.
  - **A modified app or client.** The release mode is the client's own claim, so a recipient running a changed app can ask for `view` and write the content out. No design that gives a recipient the key can prevent this; the app is unsigned (no paid certificates), so it can't be attested either. The signed flag only means an honest older app can't save by mistake.
  - **Malware or a debugger on the recipient's computer** reading the app's memory, or the operating system paging memory to disk (hibernation, swap). Decoded page pictures also live in the web view's memory until it frees them; only the document bytes are wiped.
  - **Capture that ignores the OS flag.** Some screen-capture paths (hardware capture cards, a hypervisor, and possibly future macOS versions' newer capture APIs) may not honour a window's "don't capture" flag. This is the main thing to verify on the real machine: `cargo run -p svx-desktop --example viewer_probe` and try each way of capturing. **Windows is not tested** (no Windows machine); the claim there rests on the documented Windows behaviour.
  - **Linux:** refused, not protected.
  - **A malicious sender** sending a hostile PDF or image: the parsers are memory-safe Rust under catch_unwind with limits and fuzzing (see T16), but a bug could still crash the viewer. Office files are converted on the *sender's* computer from their own file; the recipient never parses an Office format.
  - **After the sender approves a copy,** the saved file is an ordinary file; approving can't be taken back.
- **Related:** T4 (a copy of a decrypted file), T10 (a compromised recipient endpoint), T16 (hostile input).

### T30. Abuse of the public service (floods, sign-up and email spam)
- **Threat:** strangers flood the free public service (a small VM), create accounts in bulk, use sign-up codes to send email to arbitrary addresses (burning the mail account's daily quota or reputation), poll releases or registry lookups to exhaust CPU (SLH-DSA signing), or fill the database with files.
- **What the design does:** per-address limits on all requests, codes, new accounts, company registrations and registry lookups (IPv6 counted per /64); per-account limits on files, releases and share requests; a daily email budget below the provider's cap; at most two registry signatures at a time; existing per-address code limits, password lock-out and a hashing semaphore. Behind Cloudflare the address comes from `CF-Connecting-IP`, trusted only because the firewall admits only Cloudflare's ranges. The operator can suspend an account (no sign-in, no record, its files stop opening) or erase it (`svx-admin`). ✅ (`crates/svx-server/tests/abuse.rs`)
- **What is *not* stopped:** a distributed attack from many addresses (Cloudflare's own protection is the only defence there), counters reset when the service restarts, and a determined sender with many addresses can still create accounts within the per-address limits. Erasure keeps entries about the erased account in other accounts' audit logs.

## 5. Security claims we will make (after review)

- "Encrypted before transfer."
- "Recipient-bound access."
- "Cryptographically verifiable integrity and sender authenticity."
- "Organization-based authentication and per-artifact authorization."
- "Managed expiration and revocation of future access."
- "The `.svx` file alone is not enough to decrypt protected content."
- "Neither the managed service nor the recipient's key agent can decrypt alone."

Each claim maps to G1 to G7 above and to tests in the repository.
