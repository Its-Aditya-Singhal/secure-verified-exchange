# SVX Key Hierarchy and Lifecycle

```text
Registry signing key (managed service, HSM)          signs org records and key status
│
├── Organization A
│   ├── Ed25519 signing keys    [key_id, status, validity]   signs artifacts
│   └── X25519 KEM keys         [key_id, ...]                receives share_org when A is a recipient
│
├── Organization B
│   └── ...
│
└── Managed service
    ├── X25519 service KEM key  [key_id, ...]                receives share_svc
    └── Ed25519 grant key                                    signs short-lived release grants

Per artifact (ephemeral)
  share_svc, share_org (32 B each, CSPRNG)
      └── HKDF ──► payload_key   → STREAM ChaCha20-Poly1305 over chunks
                ├► manifest_key  → ChaCha20-Poly1305 over manifest
                └► key_commitment (public, in header)

Per release (ephemeral)
  client X25519 key (e_pk / e_sk): shares are re-sealed to it; destroyed after decryption
```

## Key identifiers

`key_id = SHA-256("SVX-1 key-id\0" ‖ kind ‖ public_key)[..16]`, where `kind` is `0x01` for Ed25519 signing keys and `0x02` for X25519 KEM keys. A key ID is derived from the key itself and cannot be chosen. Including the kind byte means a signing key and a KEM key can never share an ID.

## Storage

| Key | Phase 1 | Production target |
|-----|---------|-------------------|
| Org signing key | JSON key file, mode 0600 | KMS/HSM (sign API); key never leaves it |
| Org KEM key | JSON key file, mode 0600 | Key agent backed by KMS/HSM (decapsulation in the HSM where supported, otherwise a confidential enclave) |
| Service KEM key | test file | HSM; unwrap only after the policy decision |
| Registry key | n/a | Offline root + online HSM intermediate |
| Shares, artifact keys | memory only, zeroized | same |

Private keys are never stored in plaintext in server databases.

## Rotation

- **Signing keys.** Publish the new key as `active`. Set the old key to `retired`: it can still verify artifacts created before its `not_after`, but it is never used to sign. Clients re-fetch registry records whose signature is fresh.
- **KEM keys (org or service).** Publish the new key. New artifacts are sealed to it. The old key stays available to the key agent or service only to unwrap existing artifacts until they expire, then it is destroyed. Destroying it makes the remaining artifacts permanently undecryptable, which can be used deliberately as cryptographic erasure.
- **Rotation does not re-encrypt existing artifacts.** Senders re-issue an artifact if it is needed after its keys have been destroyed.

## Revocation and compromise recovery

| Compromised key | Immediate action | Effect |
|-----------------|------------------|--------|
| Org signing key | Mark `revoked` with a compromise time in the registry | Verifiers reject signatures from that key. Artifacts created before the compromise time can be accepted only if they were registered with the service before it. |
| Org KEM key | Revoke; key agent refuses to use it | One share is exposed. The service share still protects the artifacts. Re-issue the artifacts that matter. |
| Service KEM key | Revoke; service refuses release for artifacts sealed to it | One share is exposed. The org share still protects the artifacts. Senders re-issue. |
| Registry key | Roll to a new key through a signed client update anchored in the offline root | Full trust reset |

## Offboarding

- **User.** IdP deprovisioning plus SVX user revocation. All future releases are denied.
- **Organization.** All org keys are revoked, releases to the org stop, and its audit records are retained for the configured period, then deleted.

## Backup and recovery

Org KEM keys need escrow, for example KMS multi-region or HSM backup under the org's own control. Losing them makes every artifact sealed to them unreadable. That is by design, and it must be documented in the desktop app's admin screens. Signing keys do not need backup: generate new ones and rotate.
