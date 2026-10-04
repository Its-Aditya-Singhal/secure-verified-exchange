//! Account password hashes (email accounts): Argon2id with a random salt.
//!
//! Stored as `argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt hex>$<hash hex>`.
//! The parameters are stored with the hash, so they can be raised later
//! without breaking existing accounts ([`needs_rehash`]).

use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Cost of new hashes: 64 MiB, 3 passes (OWASP's Argon2id guidance with
/// a margin), about 0.2 s on a server core.
pub const PASSWORD_HASH_PARAMS: Cost = (64 * 1024, 3, 1);

const HASH_LEN: usize = 32;

/// Argon2id costs: memory in KiB, passes, lanes.
type Cost = (u32, u32, u32);
const PREFIX: &str = "argon2id$v=19$";

fn compute(password: &str, salt: &[u8], (m, t, p): Cost) -> Result<Zeroizing<Vec<u8>>> {
    // Bounds on what a stored string may demand.
    if !(8..=1024 * 1024).contains(&m) || !(1..=10).contains(&t) || !(1..=4).contains(&p) {
        return Err(CryptoError::InvalidKey);
    }
    let params = Params::new(m, t, p, Some(HASH_LEN)).map_err(|_| CryptoError::InvalidKey)?;
    let mut out = Zeroizing::new(vec![0u8; HASH_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(out)
}

/// Hash a password for storage, with [`PASSWORD_HASH_PARAMS`].
pub fn hash_password(password: &str) -> Result<String> {
    hash_password_with(password, PASSWORD_HASH_PARAMS)
}

/// [`hash_password`] with explicit costs (tests use small ones).
pub fn hash_password_with(password: &str, params: Cost) -> Result<String> {
    let salt = crate::random_bytes::<16>();
    let h = compute(password, &salt, params)?;
    let (m, t, p) = params;
    Ok(format!(
        "{PREFIX}m={m},t={t},p={p}${}${}",
        hex::encode(salt),
        hex::encode(&h[..])
    ))
}

fn parse(stored: &str) -> Option<(Cost, Vec<u8>, Vec<u8>)> {
    let rest = stored.strip_prefix(PREFIX)?;
    let mut parts = rest.split('$');
    let (params, salt, hash) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let mut m = None;
    let mut t = None;
    let mut p = None;
    for kv in params.split(',') {
        let (k, v) = kv.split_once('=')?;
        let v: u32 = v.parse().ok()?;
        match k {
            "m" => m = Some(v),
            "t" => t = Some(v),
            "p" => p = Some(v),
            _ => return None,
        }
    }
    let salt = hex::decode(salt)
        .ok()
        .filter(|s| (16..=64).contains(&s.len()))?;
    let hash = hex::decode(hash).ok().filter(|h| h.len() == HASH_LEN)?;
    Some(((m?, t?, p?), salt, hash))
}

/// Whether `password` matches `stored` (constant-time comparison). A
/// malformed stored string never matches.
pub fn verify_password(password: &str, stored: &str) -> bool {
    let Some((params, salt, expected)) = parse(stored) else {
        return false;
    };
    match compute(password, &salt, params) {
        Ok(h) => bool::from(h.as_slice().ct_eq(&expected)),
        Err(_) => false,
    }
}

/// Whether `stored` uses weaker costs than [`PASSWORD_HASH_PARAMS`].
pub fn needs_rehash(stored: &str) -> bool {
    parse(stored).is_none_or(|(params, _, _)| params != PASSWORD_HASH_PARAMS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Cost = (64, 1, 1);

    #[test]
    fn hash_and_verify() {
        let h = hash_password_with("correct horse battery staple", FAST).unwrap();
        assert!(h.starts_with("argon2id$v=19$m=64,t=1,p=1$"));
        assert!(verify_password("correct horse battery staple", &h));
        assert!(!verify_password("correct horse battery stapl", &h));
        // Salted: the same password hashes differently.
        assert_ne!(
            h,
            hash_password_with("correct horse battery staple", FAST).unwrap()
        );
        assert!(needs_rehash(&h));
    }

    #[test]
    fn default_cost() {
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &h));
        assert!(!needs_rehash(&h));
    }

    #[test]
    fn malformed_or_extreme_hashes_never_match() {
        let h = hash_password_with("pw-pw-pw-pw-pw", FAST).unwrap();
        for bad in [
            String::new(),
            "argon2id$v=19$".into(),
            h.replace("m=64", "m=4"),
            h.replace("m=64", "m=99999999"),
            h.replace("t=1", "t=11"),
            h.replace("argon2id", "argon2i"),
            format!("{h}$extra"),
            h[..h.len() - 2].to_string(),
        ] {
            assert!(!verify_password("pw-pw-pw-pw-pw", &bad), "{bad}");
        }
    }
}
