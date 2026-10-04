//! Password-protected backups of a personal account's private keys
//! (`*.svxbackup`): Argon2id derives a key from the recovery password, and
//! ChaCha20-Poly1305 encrypts the keys under it.
//!
//! Layout: `magic(8) ‖ m_kib u32 ‖ t u32 ‖ p u32 ‖ salt(16) ‖ nonce(12) ‖
//! ciphertext`, little-endian, with everything before the ciphertext as
//! associated data. A wrong password and a damaged file both fail
//! authentication.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"SVXBAK1\0";
const HEAD_LEN: usize = 8 + 12 + 16 + 12;

/// Argon2id cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl BackupParams {
    /// What new backups use: 256 MiB, 4 passes (about 1 s on a laptop),
    /// so each password guess against a stolen backup costs an attacker the
    /// same. Older backups (64 MiB, 3 passes) keep opening: the parameters
    /// are stored in the file.
    pub const STRONG: BackupParams = BackupParams {
        m_kib: 256 * 1024,
        t: 4,
        p: 1,
    };

    /// Bounds accepted when reading, so a crafted file can't demand
    /// unbounded memory or time.
    fn check(&self) -> Result<()> {
        if !(8..=1024 * 1024).contains(&self.m_kib)
            || !(1..=10).contains(&self.t)
            || !(1..=4).contains(&self.p)
        {
            return Err(CryptoError::InvalidKey);
        }
        Ok(())
    }
}

fn derive(password: &str, salt: &[u8], p: BackupParams) -> Result<Zeroizing<[u8; 32]>> {
    p.check()?;
    let params = Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|_| CryptoError::InvalidKey)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(key)
}

/// Encrypt `plaintext` under `password`.
pub fn seal_with_password(
    password: &str,
    plaintext: &[u8],
    params: BackupParams,
    rng: &mut impl rand_core::CryptoRng,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let key = derive(password, &salt, params)?;
    let mut out = Vec::with_capacity(HEAD_LEN + plaintext.len() + 16);
    out.extend_from_slice(MAGIC);
    for v in [params.m_kib, params.t, params.p] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    let ct = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .expect("32-byte key")
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &out,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a backup. Fails with [`CryptoError::Decryption`] for a wrong
/// password or a modified file.
pub fn open_with_password(password: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < HEAD_LEN + 16 || &blob[..8] != MAGIC {
        return Err(CryptoError::InvalidKey);
    }
    let u32_at = |i: usize| u32::from_le_bytes(blob[i..i + 4].try_into().expect("4 bytes"));
    let params = BackupParams {
        m_kib: u32_at(8),
        t: u32_at(12),
        p: u32_at(16),
    };
    let salt = &blob[20..36];
    let nonce: [u8; 12] = blob[36..48].try_into().expect("12 bytes");
    let key = derive(password, salt, params)?;
    let pt = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .expect("32-byte key")
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &blob[HEAD_LEN..],
                aad: &blob[..HEAD_LEN],
            },
        )
        .map_err(|_| CryptoError::Decryption)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: BackupParams = BackupParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    #[test]
    fn round_trip_and_failures() {
        let mut rng = crate::os_rng();
        let blob = seal_with_password("correct horse", b"keys", FAST, &mut rng).unwrap();
        assert_eq!(
            &*open_with_password("correct horse", &blob).unwrap(),
            b"keys"
        );
        assert_eq!(
            open_with_password("wrong horse", &blob).unwrap_err(),
            CryptoError::Decryption
        );
        // Any change to the header (e.g. weaker parameters) fails too.
        let mut weaker = blob.clone();
        weaker[12] = 1;
        weaker[8..12].copy_from_slice(&8u32.to_le_bytes());
        assert!(open_with_password("correct horse", &weaker).is_err());
        let mut flipped = blob.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(open_with_password("correct horse", &flipped).is_err());
        assert!(open_with_password("correct horse", &blob[..40]).is_err());
        // Absurd costs are refused before any work.
        let mut huge = blob;
        huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            open_with_password("correct horse", &huge).unwrap_err(),
            CryptoError::InvalidKey
        );
    }
}
