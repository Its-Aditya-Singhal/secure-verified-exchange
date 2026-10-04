# SVX Key Hierarchy and Lifecycle

```text
All keys below are suite SVX-2 kinds: "SVX-2 signing" = Ed25519 + ML-DSA-87 +
SLH-DSA-SHA2-256s, "SVX-2 KEM" = MLKEM1024-P384 (ML-KEM-1024 + P-384).

Registry signing key (SVX-2 signing, HSM)            signs org and service records (all three parts); clients pin its fingerprint
│
├── Organization A
│   ├── SVX-2 signing keys [key_id, status]          signs artifacts (all three parts)
│   └── SVX-2 KEM keys [key_id, ...]                 receives share_org when A is a recipient
│
├── Organization B
│   └── ...
│
└── Managed service
    ├── SVX-2 service KEM key  [key_id, ...]         receives share_svc
    └── SVX-2 grant key                              signs short-lived release grants (Ed25519 + ML-DSA-87)

Older keys (hybrid Ed25519 + ML-DSA-65 and X-Wing; classical Ed25519 and
X25519) stay `retired`: they verify and open older SVX-1H and SVX-1 files and
never make new ones.

Personal account u.<id> (Phase 5d; one person, one organization)
    ├── SVX-2 device signing key   signs files (all three parts) and every request to the service (Ed25519 + ML-DSA-87)
    └── SVX-2 KEM key              receives the recipient half (one envelope per recipient)
    Both live in the device's keychain; one *.svxbackup (Argon2id + ChaCha20-Poly1305) restores them.

Per artifact (ephemeral)
  share_svc, share_org (32 B each, CSPRNG)
      └── HKDF ──► payload_key   → STREAM ChaCha20-Poly1305 over chunks
                ├► manifest_key  → ChaCha20-Poly1305 over manifest
                └► key_commitment (public, in header)

Per release (ephemeral)
  client MLKEM1024-P384 key (e_pk / e_sk): shares are re-sealed to it; destroyed after decryption
```

## Key identifiers

`key_id = SHA-256("SVX-1 key-id\0" ‖ kind ‖ public_key)[..16]`, where `kind` is `0x01` for Ed25519 signing keys, `0x02` for X25519 KEM keys, `0x03` for X-Wing KEM keys, `0x04` for Ed25519 + ML-DSA-65 signing keys, `0x05` for MLKEM1024-P384 KEM keys and `0x06` for SVX-2 signing keys, over the full public key.

| Kind | Registry name | Public key | Secret key file | Signature / `enc` |
|------|---------------|-----------|-----------------|-------------------|
| Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s | `ed25519-mldsa87-slhdsa` | 2688 B (32 + 2592 + 64) | 160 B (five 32-byte seeds) | full 34483 B (64 + 4627 + 29792); fast 4691 B (grants, account requests) |
| MLKEM1024-P384 | `mlkem1024-p384` | 1665 B | 32-byte seed | `enc` 1665 B |
| Ed25519 + ML-DSA-65 (older files) | `ed25519-mldsa65` | 1984 B (32 + 1952) | two 32-byte seeds | 3373 B (64 + 3309) |
| X-Wing (older files) | `xwing` | 1216 B | 32-byte seed | `enc` 1120 B |
| Ed25519 (older files) | `ed25519` | 32 B | 32-byte seed | 64 B |
| X25519 (older files) | `x25519` | 32 B | 32 B | `enc` 32 B |

`svx keygen`, the SDKs and the desktop app only generate the SVX-2 kinds. A key ID is derived from the key itself and cannot be chosen. Including the kind byte means a signing key and a KEM key can never share an ID.

## Storage

| Key | Phase 1 | Production target |
|-----|---------|-------------------|
| Org signing key | OS keychain on each sender's device (desktop app), or a JSON key file, mode 0600 (CLI/SDKs) | Hardware-backed (Secure Enclave, TPM) or KMS/HSM sign API |
| Org KEM key | JSON key file, mode 0600, on the key agent (systemd credential or container secret; the agent refuses readable files) | Key agent backed by KMS/HSM (decapsulation in the HSM where supported, otherwise a confidential enclave) |
| Service KEM key | test file | HSM; unwrap only after the policy decision |
| Registry key | n/a | Offline root + online HSM intermediate |
| Shares, artifact keys | memory only, zeroized | same |

Private keys are never stored in plaintext in server databases.

## Rotation

- **Signing keys.** Publish the new key as `active`. Set the old key to `retired`: it can still verify artifacts created before its `not_after`, but it is never used to sign. Clients re-fetch registry records whose signature is fresh.
- **Moving to SVX-2 keys.** Register an `mlkem1024-p384` key and an `ed25519-mldsa87-slhdsa` key as `active`, then set the older keys to `retired`. Keep the old X-Wing and X25519 secret keys in the key agent (`--kem-key` is repeatable) and the service until the older files they protect have expired. The service and key agent start only with an SVX-2 KEM key and SVX-2 grant and registry keys (protocol v4).
- **KEM keys (org or service).** Publish the new key. New artifacts are sealed to it. The old key stays available to the key agent or service only to unwrap existing artifacts until they expire, then it is destroyed. Destroying it makes the remaining artifacts permanently undecryptable, which can be used deliberately as cryptographic erasure.
- **Rotation does not re-encrypt existing artifacts.** Senders re-issue an artifact if it is needed after its keys have been destroyed.

## Revocation and compromise recovery

| Compromised key | Immediate action | Effect |
|-----------------|------------------|--------|
| Org signing key | Mark `revoked` with a compromise time in the registry | Verifiers reject signatures from that key. Artifacts created before the compromise time can be accepted only if they were registered with the service before it. |
| Org KEM key | Revoke; key agent refuses to use it | One share is exposed. The service share still protects the artifacts. Re-issue the artifacts that matter. |
| Service KEM key | Revoke; service refuses release for artifacts sealed to it | One share is exposed. The org share still protects the artifacts. Senders re-issue. |
| Registry key | Roll to a new key through a signed client update anchored in the offline root (clients pin the new fingerprint) | Full trust reset |

## Offboarding

- **User.** IdP deprovisioning plus SVX user revocation. All future releases are denied.
- **Organization.** All org keys are revoked, releases to the org stop, and its audit records are retained for the configured period, then deleted.

## Backup and recovery

**Personal accounts** keep both private keys in the device keychain. The app offers one backup file encrypted with a recovery password (Argon2id, 256 MiB, 4 passes, then ChaCha20-Poly1305; about 0.6 s on an Apple-silicon Mac). Older backups (64 MiB, 3 passes) still restore, because each backup file records its own settings. Restoring registers the same keys on a new device. Without a backup, a lost device means **Reset keys**: new keys, the old ones retired, and files sent to the old keys can no longer be opened.

Org KEM keys need escrow, for example KMS multi-region or HSM backup under the org's own control. Losing them makes every artifact sealed to them unreadable. That is by design, and it must be documented in the desktop app's admin screens. Signing keys do not need backup: generate new ones and rotate.
