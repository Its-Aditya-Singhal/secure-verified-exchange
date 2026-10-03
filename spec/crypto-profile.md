# SVX-1 Cryptographic Profile

Version: 1.0 (draft). The key words MUST, MUST NOT, SHOULD and MAY are used as defined in RFC 2119.

SVX does not define new primitives. This profile shows how standard primitives are combined.

## 1. Suite

Two suites are defined.

| `suite_id` | Name | Payload AEAD | Envelope HPKE (RFC 9180 base mode, HKDF-SHA256 `0x0001`, ChaCha20-Poly1305 `0x0003`) | Signature | Hash / KDF |
|-----------|------|---------------|---------------|-----------|------------|
| `0x0001` | SVX-1 | ChaCha20-Poly1305 (RFC 8439) | KEM DHKEM(X25519, HKDF-SHA256) `0x0020` | Ed25519 (RFC 8032), `sig_alg = 0x0001` | SHA-256, HKDF-SHA256 (RFC 5869) |
| `0x0003` | SVX-1H (post-quantum hybrid, since 1.1) | ChaCha20-Poly1305 | KEM X-Wing `0x647a` (X25519 + ML-KEM-768, FIPS 203; draft-connolly-cfrg-xwing-kem, draft-ietf-hpke-pq) | Ed25519 **and** ML-DSA-65 (FIPS 204), `sig_alg = 0x0002`, §9.1 | SHA-256, HKDF-SHA256 |

`0x0002` is reserved for a future AES-256-GCM variant and is **not** defined.

Readers MUST reject any other `suite_id`, and any `sig_alg` other than the one listed for the artifact's suite. There is no negotiation and no fallback. Writers SHOULD produce suite `0x0003` for new artifacts; the reference client produces nothing else.

**Rationale.** ChaCha20-Poly1305 runs in constant time in software on every platform, including those without AES-NI. X25519 and Ed25519 have mature, misuse-resistant implementations. SVX-1H adds the NIST post-quantum standards in *hybrid* form: X-Wing combines X25519 and ML-KEM-768 so the shared secret is safe as long as **either** holds, and the composite signature requires **both** Ed25519 and ML-DSA-65 to verify. This protects files recorded today against decryption by a future quantum computer ("harvest now, decrypt later"), without betting everything on the newer algorithms. 256-bit symmetric keys (ChaCha20, HKDF-SHA256) are already quantum-safe and are unchanged.

**Labels.** Every domain-separation label below starts with the suite name: `"SVX-1 …\0"` for `0x0001` and `"SVX-1H …\0"` for `0x0003` (for example `"SVX-1H envelope\0"`). Nothing produced under one suite can be accepted under the other.

## 2. Notation

- `‖` means concatenation.
- `LE16`, `LE32`, `LE64` and `BE32` are fixed-width integer encodings.
- `lp(x) = u8(len(x)) ‖ x`. This is only used for identifiers, which are at most 128 bytes long.
- Every domain-separation string ends in `\0`, which also ends the string unambiguously.

## 3. Randomness

The writer MUST draw all of the following from a CSPRNG:

- `artifact_id` (16 bytes)
- `nonce_prefix` (7 bytes)
- `share_svc` and `share_org` (32 bytes each)
- the HPKE ephemeral keys

## 4. Key schedule

```text
salt           = "<suite> artifact\0" ‖ artifact_id      (<suite> = SVX-1 or SVX-1H)
prk            = HKDF-Extract(SHA-256, salt, share_svc ‖ share_org)
payload_key    = HKDF-Expand(prk, "svx/1/payload",    32)
manifest_key   = HKDF-Expand(prk, "svx/1/manifest",   32)
key_commitment = HKDF-Expand(prk, "svx/1/commitment", 32)
```

`key_commitment` is stored in the header. A reader MUST compare it in constant time against the value it derives, before any decryption. This makes the scheme key-committing even though ChaCha20-Poly1305 is not key-committing by itself.

## 5. Key envelopes

For each `role` (`0x01` = Service, `0x02` = RecipientOrg), with `pk` being that party's KEM public key (X25519 for SVX-1, X-Wing for SVX-1H):

```text
info = "<suite> envelope\0" ‖ u8(role) ‖ artifact_id ‖ sender_key_id ‖ key_id(pk)
       ‖ lp(sender_org) ‖ lp(recipient_org) ‖ lp(service_id)
(enc, ct) = HPKE.SealBase(pk, info, aad = "", pt = share_role)
```

`ct` is 48 bytes. `enc` is 32 bytes (X25519, envelope layout V1) or 1120 bytes (X-Wing, layout V2). A party's key kind MUST match the suite: a writer MUST NOT seal an SVX-1H envelope to an X25519 key.

Because `info` binds the envelope to the artifact, both organizations, the sender's signing key and the role, envelopes cannot be moved to another artifact, re-attributed to another sender, or swapped between roles.

## 6. Header hash

```text
header_hash = SHA-256("SVX-1 header\0" ‖ prelude ‖ header_bytes)
```

The hash covers the exact bytes on the wire, including unknown non-critical fields.

## 7. Payload: STREAM

Payload encryption uses the STREAM construction of Hoang, Reyhanitabar, Rogaway and Vizár (CRYPTO 2015), with ChaCha20-Poly1305:

```text
nonce_i = nonce_prefix (7) ‖ BE32(i) ‖ u8(is_final)
ct_i    = ChaCha20-Poly1305.Seal(payload_key, nonce_i, aad = header_hash, pt_i)
```

The chunk rules are:

- `i` counts up from 0, and at most 2³² chunks are allowed.
- Every chunk except the last has exactly `chunk_size` bytes of plaintext.
- The final chunk has between 1 and `chunk_size` bytes. It may be empty only when the whole payload is empty, in which case it is the only chunk.

Each property comes from a specific part of the construction:

- Reordering, duplicating or dropping a chunk fails authentication, because the counter is part of the nonce.
- Truncation is caught in two ways. A non-final chunk presented as final fails, because the flag is part of the nonce. A stream that ends without a final chunk is rejected outright.
- Extension after the final chunk is rejected structurally, and the stream refuses to process any further chunk.
- Any header change invalidates every chunk, because the header hash is the AAD.
- Nonces never repeat under one key, because `payload_key` is unique per artifact and the counter is unique per chunk.

## 8. Manifest

```text
manifest_ct = ChaCha20-Poly1305.Seal(manifest_key, nonce = 0^12,
                                     aad = "SVX-1 manifest\0" ‖ artifact_id, manifest_json)
```

A fixed nonce is safe here because `manifest_key` is unique per artifact and used exactly once.

`manifest_json` is UTF-8 JSON with at most 64 KiB of plaintext:

```json
{"svx_manifest":1,"files":[{"name":"evidence.zip","size":123,"content_type":"application/zip"}],
 "classification":"TLP:AMBER","description":"..."}
```

Readers MUST check that:

- `svx_manifest` is 1;
- there is exactly one file;
- the file name is a single safe path component (no `/`, `\`, `:`, control characters, `.` or `..`, Windows reserved names, or trailing dot or space);
- the total decrypted length equals `size`.

## 9. Payload commitment and signature

```text
payload_commitment = SHA-256("SVX-1 payload\0" ‖ header_hash ‖ Σ_i (u8(flag_i) ‖ LE32(ct_len_i) ‖ ct_i))
message            = "<suite> signature\0" ‖ header_hash ‖ LE64(chunk_count) ‖ payload_commitment
signature          = Ed25519.Sign(sender_signing_key, message)                        (SVX-1)
```

### 9.1 Composite signature (SVX-1H)

```text
signature = Ed25519.Sign(ed_sk, message) ‖ ML-DSA-65.Sign(ml_sk, message, ctx = "SVX-1H")
          = 64 bytes ‖ 3309 bytes
```

- The sender's SVX-1H signing key is a pair `(Ed25519, ML-DSA-65)`; its public form is `ed_pk (32) ‖ ml_pk (1952)` and its key ID covers all 1984 bytes.
- ML-DSA-65 signing SHOULD be hedged (FIPS 204 randomized signing).
- Verifiers MUST require `sig_len = 3373` and MUST accept only if **both** the strict Ed25519 verification and the ML-DSA-65 verification (FIPS 204 `ML-DSA.Verify` with context `"SVX-1H"`) succeed. There is no "either" mode.

Verifiers MUST:

- use *strict* Ed25519 verification, which rejects non-canonical `S` and small-order `R` and `A`;
- reject weak public keys;
- verify the signature only after recomputing `payload_commitment` from the chunks and checking that it equals the trailer value, compared in constant time.

## 10. Verification order (normative)

1. Parse the prelude and header (format spec §6).
2. Check `suite_id`.
3. Check that both required envelopes are present.
4. Resolve the sender key by `(sender_org, sender_key_id)` from the trust source. The key MUST be trusted *for that organization*.
5. Stream all chunk records and compute `payload_commitment`.
6. Parse the trailer and require EOF.
7. Check `chunk_count` and `payload_commitment` against the trailer.
8. Verify the signature.

Only after all of these steps succeed MAY the reader request key release or decrypt anything.

Decryption MUST then:

- recompute `header_hash` and require it to equal the verified value;
- check `key_commitment`;
- decrypt the manifest;
- STREAM-decrypt the chunks, writing each one only after it authenticates;
- recompute `payload_commitment` and require it to equal the verified value;
- check the total length.

If any of these fail, the reader MUST discard all output.

## 11. Implementation notes (reference implementation)

| Function | Rust crate |
|----------|------------|
| AEAD | `chacha20poly1305` 0.11 |
| HPKE | `hpke` 0.14 (`x25519`, `mlkem` features; X-Wing via RustCrypto `x-wing` / `ml-kem`) |
| Ed25519 | `ed25519-dalek` 3 (`verify_strict`) |
| ML-DSA-65 | `ml-dsa` 0.1 (RustCrypto, FIPS 204) |
| HKDF / SHA-256 | `hkdf` 0.13 / `sha2` 0.11 |
| Zeroization | `zeroize` |

- All secret types zeroize on drop and redact `Debug`.
- No primitive is implemented locally.
- The public API offers purpose-specific operations, not raw primitives.
- Known-answer tests pin X-Wing HPKE (HPKE PQ draft vectors) and ML-DSA-65 key generation and verification (NIST ACVP) in `crates/svx-crypto/tests/kat.rs`.

**Key identifiers.** `key_id = SHA-256("SVX-1 key-id\0" ‖ kind ‖ public_key)[..16]` with `kind` = `0x01` Ed25519, `0x02` X25519, `0x03` X-Wing, `0x04` Ed25519 + ML-DSA-65.

## 12. Managed Mode key release

A released share never travels in plaintext, even inside TLS. The releasing party (managed service or recipient key agent) re-seals it to a per-request key `e_pk` generated by the client. Current clients use an **X-Wing** `e_pk`, so a recorded release response cannot be decrypted later by a quantum computer; releasing parties accept only X-Wing `e_pk`.

```text
info      = "<suite> release\0" ‖ u8(role) ‖ artifact_id ‖ txn (16) ‖ key_id(e_pk)
(enc, ct) = HPKE.SealBase(e_pk, info, aad = "", share)
```

`txn` is a random 128-bit, single-use transaction identifier. Releasing parties MUST reject a reused `txn`.

The client binds `e_pk` and `txn` into its OIDC login through the `nonce` parameter:

```text
nonce = hex(SHA-256("<suite> oidc\0" ‖ e_pk ‖ txn))        (<suite> = SVX-1H for an X-Wing e_pk)
```

Releasing parties MUST require this nonce in the ID token. As a result, a token can only cause shares to be released to the key pair that requested it. A party that captures the token, including a compromised managed service, cannot redirect the release to a key of its own.

## 13. Context signatures

Grants and registry records are signed with Ed25519 over `label ‖ bytes`, where `bytes` are the exact JSON bytes transmitted and no canonicalization is applied.

| Object | Label |
|--------|-------|
| Release grant | `"SVX-1 grant\0"` |
| Registry record | `"SVX-1 registry\0"` |
| Service record | `"SVX-1 service\0"` |

The labels keep these signatures disjoint from each other and from artifact signatures (`"SVX-1 signature\0"`).
