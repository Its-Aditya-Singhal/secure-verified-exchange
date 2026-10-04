//! STREAM chunked AEAD (Hoang, Reyhanitabar, Rogaway, Vizár — "Online
//! Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance", 2015).
//!
//! ```text
//! nonce_i = prefix[7] ‖ BE32(i) ‖ last_flag   (last_flag = 0x01 on the final chunk, else 0x00)
//! ct_i    = ChaCha20-Poly1305(payload_key, nonce_i, aad = header_hash, pt_i)
//! ```
//!
//! Binding the counter and last-flag into the nonce means reordering,
//! dropping, duplicating, truncating or extending chunks all cause
//! authentication failure. Binding the header hash as AAD means any header
//! change invalidates every chunk.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::error::{CryptoError, Result};
use crate::schedule::ArtifactKeys;
use crate::transcript::HeaderHash;

fn nonce(prefix: &[u8; 7], counter: u32, is_final: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(is_final);
    Nonce::from(n)
}

struct StreamState {
    cipher: ChaCha20Poly1305,
    prefix: [u8; 7],
    aad: Vec<u8>,
    counter: u64,
    done: bool,
}

impl StreamState {
    fn new(keys: &ArtifactKeys, prefix: [u8; 7], header_hash: &HeaderHash) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(&keys.payload_key).expect("32-byte key");
        Self {
            cipher,
            prefix,
            aad: header_hash.as_bytes().to_vec(),
            counter: 0,
            done: false,
        }
    }

    fn next_nonce(&mut self, is_final: bool) -> Result<Nonce> {
        if self.done {
            return Err(CryptoError::StreamState("chunk after final chunk"));
        }
        let ctr = u32::try_from(self.counter)
            .map_err(|_| CryptoError::StreamState("chunk counter overflow"))?;
        Ok(nonce(&self.prefix, ctr, is_final))
    }
}

/// Encrypts a payload chunk by chunk.
pub struct StreamEncryptor(StreamState);

impl StreamEncryptor {
    pub fn new(keys: &ArtifactKeys, nonce_prefix: [u8; 7], header_hash: &HeaderHash) -> Self {
        Self(StreamState::new(keys, nonce_prefix, header_hash))
    }

    pub fn encrypt_chunk(&mut self, plaintext: &[u8], is_final: bool) -> Result<Vec<u8>> {
        let n = self.0.next_nonce(is_final)?;
        let ct = self
            .0
            .cipher
            .encrypt(
                &n,
                Payload {
                    msg: plaintext,
                    aad: &self.0.aad,
                },
            )
            .map_err(|_| CryptoError::Encryption)?;
        self.0.counter += 1;
        self.0.done = is_final;
        Ok(ct)
    }
}

/// Decrypts and authenticates a payload chunk by chunk.
pub struct StreamDecryptor(StreamState);

impl StreamDecryptor {
    pub fn new(keys: &ArtifactKeys, nonce_prefix: [u8; 7], header_hash: &HeaderHash) -> Self {
        Self(StreamState::new(keys, nonce_prefix, header_hash))
    }

    pub fn decrypt_chunk(&mut self, ciphertext: &[u8], is_final: bool) -> Result<Vec<u8>> {
        let n = self.0.next_nonce(is_final)?;
        let pt = self
            .0
            .cipher
            .decrypt(
                &n,
                Payload {
                    msg: ciphertext,
                    aad: &self.0.aad,
                },
            )
            .map_err(|_| CryptoError::Decryption)?;
        self.0.counter += 1;
        self.0.done = is_final;
        Ok(pt)
    }

    /// Fail unless the final chunk has been authenticated (truncation check).
    pub fn finish(self) -> Result<()> {
        if self.0.done {
            Ok(())
        } else {
            Err(CryptoError::StreamState("stream ended before final chunk"))
        }
    }
}
