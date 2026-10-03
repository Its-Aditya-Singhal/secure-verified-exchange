-- Post-quantum hybrid key kinds (suite SVX-1H): X-Wing (X25519 + ML-KEM-768)
-- KEM keys and Ed25519 + ML-DSA-65 composite signing keys. Each kind has an
-- exact public-key length; classical keys stay valid for older files.

ALTER TABLE org_keys DROP CONSTRAINT org_keys_kind_check;
ALTER TABLE org_keys DROP CONSTRAINT org_keys_public_key_check;

ALTER TABLE org_keys ADD CONSTRAINT org_keys_kind_length_check CHECK (
    (kind = 'ed25519' AND length(public_key) = 32)
    OR (kind = 'x25519' AND length(public_key) = 32)
    OR (kind = 'xwing' AND length(public_key) = 1216)
    OR (kind = 'ed25519-mldsa65' AND length(public_key) = 1984)
);
