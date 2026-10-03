# SVX-1 Cryptographic Profile

Version: 1.0 (draft). The key words MUST, MUST NOT, SHOULD and MAY are used as defined in RFC 2119.

SVX does not define new primitives. This profile shows how standard primitives are combined.

## 1. Suite

SVX 1.0 defines a single suite.

| `suite_id` | Payload AEAD | Envelope HPKE | Signature | Hash / KDF |
|-----------|---------------|---------------|-----------|------------|
| `0x0001` | ChaCha20-Poly1305 (RFC 8439) | RFC 9180 base mode: DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`, ChaCha20-Poly1305 `0x0003` | Ed25519 (RFC 8032), `sig_alg = 0x0001` | SHA-256, HKDF-SHA256 (RFC 5869) |

`0x0002` is reserved for a future AES-256-GCM variant and is **not** defined in 1.0.

Readers MUST reject any other `suite_id` or `sig_alg`. There is no negotiation and no fallback.

**Rationale.** ChaCha20-Poly1305 runs in constant time in software on every platform, including those without AES-NI. X25519 and Ed25519 have mature, misuse-resistant implementations. A single suite removes downgrade attacks entirely. Post-quantum migration (for example HPKE with X-Wing, or ML-KEM hybrids, together with ML-DSA) will be a new suite ID in a later minor or major version.

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
salt           = "SVX-1 artifact\0" ‖ artifact_id
prk            = HKDF-Extract(SHA-256, salt, share_svc ‖ share_org)
payload_key    = HKDF-Expand(prk, "svx/1/payload",    32)
manifest_key   = HKDF-Expand(prk, "svx/1/manifest",   32)
key_commitment = HKDF-Expand(prk, "svx/1/commitment", 32)
```

`key_commitment` is stored in the header. A reader MUST compare it in constant time against the value it derives, before any decryption. This makes the scheme key-committing even though ChaCha20-Poly1305 is not key-committing by itself.

## 5. Key envelopes

For each `role` (`0x01` = Service, `0x02` = RecipientOrg), with `pk` being that party's X25519 public key:

```text
info = "SVX-1 envelope\0" ‖ u8(role) ‖ artifact_id ‖ sender_key_id ‖ key_id(pk)
       ‖ lp(sender_org) ‖ lp(recipient_org) ‖ lp(service_id)
(enc, ct) = HPKE.SealBase(pk, info, aad = "", pt = share_role)
```

`ct` is 48 bytes and `enc` is 32 bytes.

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
message            = "SVX-1 signature\0" ‖ header_hash ‖ LE64(chunk_count) ‖ payload_commitment
signature          = Ed25519.Sign(sender_signing_key, message)
```

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
| HPKE | `hpke` 0.14 |
| Ed25519 | `ed25519-dalek` 3 (`verify_strict`) |
| HKDF / SHA-256 | `hkdf` 0.13 / `sha2` 0.11 |
| Zeroization | `zeroize` |

- All secret types zeroize on drop and redact `Debug`.
- No primitive is implemented locally.
- The public API offers purpose-specific operations, not raw primitives.

## 12. Managed Mode key release

A released share never travels in plaintext, even inside TLS. The releasing party (managed service or recipient key agent) re-seals it to a per-request X25519 key `e_pk` generated by the client:

```text
info      = "SVX-1 release\0" ‖ u8(role) ‖ artifact_id ‖ txn (16) ‖ key_id(e_pk)
(enc, ct) = HPKE.SealBase(e_pk, info, aad = "", share)
```

`txn` is a random 128-bit, single-use transaction identifier. Releasing parties MUST reject a reused `txn`.

The client binds `e_pk` and `txn` into its OIDC login through the `nonce` parameter:

```text
nonce = hex(SHA-256("SVX-1 oidc\0" ‖ e_pk ‖ txn))
```

Releasing parties MUST require this nonce in the ID token. As a result, a token can only cause shares to be released to the key pair that requested it. A party that captures the token, including a compromised managed service, cannot redirect the release to a key of its own.

## 13. Context signatures

Grants and registry records are signed with Ed25519 over `label ‖ bytes`, where `bytes` are the exact JSON bytes transmitted and no canonicalization is applied.

| Object | Label |
|--------|-------|
| Release grant | `"SVX-1 grant\0"` |
| Registry record | `"SVX-1 registry\0"` |

The labels keep these signatures disjoint from each other and from artifact signatures (`"SVX-1 signature\0"`).
