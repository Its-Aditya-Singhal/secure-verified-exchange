-- Suite SVX-2 key kinds: MLKEM1024-P384 KEM keys and Ed25519 + ML-DSA-87 +
-- SLH-DSA-SHA2-256s signing keys. Older kinds stay so older files open.
ALTER TABLE org_keys DROP CONSTRAINT org_keys_kind_length_check;

ALTER TABLE org_keys ADD CONSTRAINT org_keys_kind_length_check CHECK (
    (kind = 'ed25519' AND length(public_key) = 32)
    OR (kind = 'x25519' AND length(public_key) = 32)
    OR (kind = 'xwing' AND length(public_key) = 1216)
    OR (kind = 'ed25519-mldsa65' AND length(public_key) = 1984)
    OR (kind = 'mlkem1024-p384' AND length(public_key) = 1665)
    OR (kind = 'ed25519-mldsa87-slhdsa' AND length(public_key) = 2688)
);

-- SVX-2 header hashes are SHA-512 (64 bytes); older suites use SHA-256.
ALTER TABLE personal_files DROP CONSTRAINT personal_files_header_hash_check;
ALTER TABLE personal_files ADD CONSTRAINT personal_files_header_hash_check
    CHECK (length(header_hash) IN (32, 64));
