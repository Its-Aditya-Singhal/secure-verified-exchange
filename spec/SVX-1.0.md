# SVX 1.x Container Format Specification

Status: Draft 4. Covers SVX 1.0, SVX 1.1, which adds the post-quantum hybrid suite `0x0003` (envelope layout V2, §3.2), SVX 1.2, which adds artifacts with several recipients (§3.3), SVX 1.3, which adds the maximum-strength suite `0x0004` (SVX-2), and SVX 1.4, which adds view-only artifacts (§3.4). Cryptographic operations are defined in [`crypto-profile.md`](crypto-profile.md). The key words MUST, MUST NOT, SHOULD and MAY are used as defined in RFC 2119.

## 1. Overview

An SVX container is a single binary file with the extension `.svx` and the media type `application/vnd.svx` (provisional). It is **passive data**: no field is ever interpreted as code.

```text
+----------------------+  16 bytes
| Prelude              |  magic, version, suite, header length
+----------------------+  header_len bytes  ─┐
| Header (TLV fields)  |                     ├─ header region → header_hash
+----------------------+                    ─┘
| Chunk record 0       |  flag, ct_len, ciphertext
| Chunk record 1       |
| ...                  |
| Chunk record N-1     |  flag = FINAL
+----------------------+
| Trailer              |  count, payload commitment, signature
+----------------------+  EOF (nothing may follow)
```

All integers are little-endian unless stated otherwise. The only exception is the STREAM nonce counter, which is big-endian and does not appear on the wire.

## 2. Prelude (16 bytes)

| Offset | Size | Field | Value |
|-------:|-----:|-------|-------|
| 0 | 8 | magic | `89 53 56 58 0D 0A 1A 0A` (`\x89SVX\r\n\x1a\n`) |
| 8 | 1 | major | `1` |
| 9 | 1 | minor | `0` for suite `0x0001`; `1` for suite `0x0003` (`2` with several recipients); `3` for suite `0x0004` (`4` when view-only) |
| 10 | 2 | suite_id | `0x0001` (SVX-1), `0x0003` (SVX-1H, post-quantum hybrid) or `0x0004` (SVX-2, maximum strength) |
| 12 | 4 | header_len | ≤ 1 048 576 |

The magic follows the design of the PNG signature. A high-bit byte, CR LF, SUB and LF detect 7-bit stripping, newline translation and text-mode truncation.

Readers MUST reject:

- a magic mismatch;
- `major ≠ 1`;
- `header_len` > 1 MiB, before allocating anything.

Readers MUST accept any `minor` when `major` is 1. A newer minor version can only add fields. Fields a reader must understand are marked critical (§3).

## 3. Header

The header is a sequence of TLV fields:

```text
field = tag (u16) ‖ len (u32) ‖ value (len bytes)
```

- Tags MUST appear in strictly ascending order. Duplicate tags are therefore impossible.
- `len` ≤ 262 144, and there are at most 64 fields.
- Bit 15 of the tag (`0x8000`) marks a field as **critical**. Readers MUST reject any unknown critical tag. Readers MUST skip unknown non-critical tags, which are still covered by the header hash and the signature.

| Tag | Name | Req | Value |
|-----|------|-----|-------|
| `0x8001` | artifact_id | yes | 16 random bytes |
| `0x8002` | created_at | yes | i64 Unix seconds UTC, ≥ 0 |
| `0x8003` | expires_at | no | i64 Unix seconds UTC, > created_at. Advisory; enforced by the managed service. |
| `0x8004` | sender_org | yes | identifier (§4) |
| `0x8005` | sender_key_id | yes | 16 bytes (crypto profile, key IDs) |
| `0x8006` | recipient_org | yes | identifier |
| `0x8007` | service_id | yes | identifier of the managed service |
| `0x8008` | policy_ref | yes | identifier of an authorization policy. This is an opaque reference, never policy text. |
| `0x8009` | chunk_size | yes | u32, 64 ≤ n ≤ 16 777 216 |
| `0x800A` | nonce_prefix | yes | 7 bytes |
| `0x800B` | key_commitment | yes | 32 bytes |
| `0x800C` | key_envelopes | yes | see §3.1 |
| `0x800D` | encrypted_manifest | yes | 16 ≤ len ≤ 65 552 bytes (AEAD ciphertext and tag) |
| `0x800E` | key_envelopes_v2 | (suites `0x0003`, `0x0004`) | see §3.2. Since 1.1. |
| `0x800F` | recipients | no | see §3.3. Since 1.2; suites `0x0003` and `0x0004` only. |
| `0x8010` | view_only | no | empty; see §3.4. Since 1.4; suite `0x0004` only. |

Exactly one of `0x800C` and `0x800E` MUST be present: `0x800C` for suite `0x0001`, `0x800E` for suites `0x0003` and `0x0004`. Any other combination MUST be rejected (this also stops a suite downgrade, since the prelude is covered by the header hash and the signature).

Every fixed-size value MUST have exactly its stated length.

### 3.1 Key envelopes

```text
key_envelopes = count (u8, 1..=16) ‖ envelope{count}
envelope      = role (u8) ‖ key_id (16) ‖ enc (32) ‖ ct_len (u16, 1..=1024) ‖ ct
```

Roles:

- `0x01`: Service.
- `0x02`: RecipientOrg.

Unknown roles MUST be rejected. Each role MUST appear at most once, except RecipientOrg in an artifact with a recipients list (§3.3). Both roles MUST be present, and `ct_len` is 48.

### 3.2 Key envelopes, layout V2 (SVX 1.1)

```text
key_envelopes_v2 = count (u8, 1..=16) ‖ envelope_v2{count}
envelope_v2      = role (u8) ‖ key_id (16) ‖ enc_len (u16, 1..=2048) ‖ enc ‖ ct_len (u16, 1..=1024) ‖ ct
```

Roles and their rules are as in §3.1. For suite `0x0003`, `enc` is an X-Wing ciphertext and `enc_len` MUST be exactly 1120. For suite `0x0004`, `enc` is an MLKEM1024-P384 ciphertext and `enc_len` MUST be exactly 1665. Readers MUST reject any envelope whose `enc_len` doesn't match the prelude's suite; this stops a downgrade between the two post-quantum suites. The tag is critical, so a 1.0 reader rejects 1.1 hybrid files instead of misreading them. A 1.1 or 1.2 reader rejects SVX-2 files because it doesn't know suite `0x0004`.

### 3.3 Several recipients (SVX 1.2)

```text
recipients = count (u8, 2..=15) ‖ { len (u8, 1..=128) ‖ identifier }{count}
```

An artifact for more than one recipient carries this critical field. Writers MUST set the prelude minor version to 2 (3 for suite `0x0004`) and MUST NOT write the field for a single recipient (that is written as in 1.1). When it is present, readers MUST check that:

- the envelope layout is V2 (suite `0x0003` or `0x0004`);
- the identifiers are distinct and the first equals `recipient_org`;
- there is exactly one Service envelope and exactly `count` RecipientOrg envelopes, with pairwise distinct `key_id`s.

Each RecipientOrg envelope seals the **same** recipient share to a different recipient key; its HPKE `info` (crypto profile) already binds the envelope's `key_id`. A recipient finds its envelope by its own key ID. Because the field is critical and part of the signed header, a 1.1 reader rejects such artifacts, and no recipient can be added or removed without breaking the signature. The managed service releases its share only to an authenticated account named in this list.

### 3.4 View-only artifacts (SVX 1.4)

A sender can limit an artifact to viewing inside the recipient's application. Such an artifact carries the critical field `view_only` (`0x8010`) with an **empty** value; writers MUST set the prelude minor version to 4 and MUST NOT write the field in any suite other than `0x0004`. Readers MUST reject the field with a non-empty value or in another suite.

Because the field is critical and covered by the signature:

- a reader that predates 1.4 rejects the artifact instead of treating it as an ordinary one;
- the flag can't be removed (to pass the artifact off as ordinary) or added without breaking the signature.

What "view-only" means for the payload, and when a recipient may still save it, is decided by the application and the managed service (the sender can later allow saving). The field only records, signed, that the sender created the artifact view-only. It does not and cannot stop a modified application from keeping content it has decrypted.

## 4. Identifiers

Identifiers are ASCII strings of 1 to 128 bytes. The allowed characters are `[a-z0-9._:-]`, and the first character MUST be `[a-z0-9]`.

Uppercase and non-ASCII characters are not allowed, so identifiers have no Unicode confusables and no case-folding or normalization ambiguity in authorization decisions.

Identifiers are opaque. They SHOULD NOT reveal sensitive information, because they are visible to anyone who holds the file.

## 5. Payload chunk records

```text
chunk = flag (u8) ‖ ct_len (u32) ‖ ciphertext (ct_len bytes)
```

- `flag` is `0x00` (more chunks follow) or `0x01` (final chunk). Any other value MUST be rejected.
- For a non-final chunk, `ct_len` MUST equal `chunk_size + 16`.
- For the final chunk, `16 ≤ ct_len ≤ chunk_size + 16`. `ct_len = 16`, an empty final chunk, is allowed **only** as chunk 0.
- There is exactly one final chunk, and it is the last chunk. There are at most 2³² chunks.

Because the record structure is fixed, every payload length has exactly one valid chunking.

## 6. Trailer

| Size | Field |
|-----:|-------|
| 4 | `"SVXT"` |
| 8 | chunk_count (u64), MUST equal the number of chunk records |
| 32 or 64 | payload_commitment (32 bytes; 64 bytes, SHA-512, for suite `0x0004`) |
| 2 | sig_alg (`0x0001` = Ed25519; `0x0002` = Ed25519 + ML-DSA-65; `0x0003` = Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s) |
| 2 | sig_len (1..=65535; exactly 64, 3373 or 34483 for the three `sig_alg`s) |
| sig_len | signature |

End of input MUST follow immediately. Any trailing byte MUST cause rejection.

## 7. Processing rules

**Parsing.** Readers MUST:

- bound every allocation by the limits above *before* allocating;
- treat any structural error as fatal.

There is no partial acceptance and no repair.

**Verification and decryption.** These follow crypto profile §10. Until signature verification succeeds, nothing parsed from the header may be shown as trustworthy. Tools MUST label such output "unverified", as `svx inspect` does.

**Streaming.** A conforming reader can verify and decrypt with O(`chunk_size`) memory. Decryption requires a second pass over the input, or buffering of ciphertext.

**Writing.** Writers MUST:

- produce fields in ascending tag order;
- produce no duplicate fields;
- use the canonical chunking.

Writers SHOULD write to a temporary file and rename it on success.

## 8. Error classes

The reference implementation (`svx-format`, `svx-core`) reports these classes. Clients SHOULD show users only a coarse category, and SHOULD log details locally without including any key material.

| Class | Examples |
|-------|----------|
| `BadMagic` / `UnsupportedVersion` | not SVX; major ≠ 1 |
| `Truncated` / `TrailingData` | incomplete file; data after the trailer |
| `LimitExceeded` / `Malformed` | oversized lengths; bad chunk lengths; bad flags |
| `FieldOrder` / `UnknownCriticalField` / `MissingField` / `InvalidIdentifier` | header structure |
| `UnsupportedSuite` / `UnsupportedSignatureAlgorithm` | no downgrade |
| `UntrustedSender` / `BadSignature` / `CommitmentMismatch` | authenticity and integrity |
| `KeyCommitmentMismatch` / `EnvelopeOpen` / `Decryption` | wrong or forged key material |
| `ArtifactChanged` / `LengthMismatch` / `Manifest` | consistency between passes; manifest rules |

## 9. Versioning and compatibility

- **Minor versions** (1.x) may add non-critical fields, or critical fields together with a new suite or feature that old readers are meant to reject.
- **Major versions** change the layout. A 1.x reader rejects 2.x artifacts.
- **Old artifacts stay readable.** A conforming 1.x reader MUST continue to accept artifacts from every earlier 1.y version.
- **Test vectors** for every version are published under `test-vectors/v<major>`.

## 10. Test vectors

`test-vectors/v1/` contains:

- valid artifacts, each with a JSON file giving every intermediate value (header hash, payload commitment, signature, test-only shares, plaintext);
- invalid artifacts, each with the expected rejection stage (`parse` or `verify`);
- `keys.json` (suite `0x0001`), `keys-hybrid.json` (suite `0x0003`) and `keys-max.json` (suite `0x0004`), which hold **test-only** keys derived from public labels;
- `hybrid-*` vectors for SVX 1.1 / suite `0x0003`, including a downgrade attempt and tampering with each half of the hybrid signature;
- `multi-*` vectors for SVX 1.2: two recipients that each open the file, and a renamed recipient that fails verification;
- `max-*` vectors for SVX 1.3 / suite `0x0004`: a downgrade attempt to `0x0003`, tampering with each of the three signatures, a tampered envelope, a tampered chunk and an untrusted signer; `max-valid-view-only` (1.4) and `max-invalid-view-only-stripped`, the same file with the field removed and the prelude patched to look like 1.3.

The vectors are reproducible byte for byte with `cargo run -p svx-testvectors`.
