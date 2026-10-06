//! Where a sender's signing key lives: a key file, or the operating
//! system's keychain (macOS Keychain, Windows Credential Manager, Linux
//! Secret Service).
//!
//! A keychain key is created and used inside this library; its secret bytes
//! never reach a UI. Keychain support needs the `keychain` feature; other
//! builds can still use key files.
//!
//! A [`KeyRef`] is written as a path, or as `keychain:<org>/<key_id>`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use svx_core::crypto::{KemSecretKey, KeyKind, SigningKey, os_rng};
use svx_core::format::Identifier;
use svx_core::keyfile;
use zeroize::Zeroizing;

use crate::error::{ClientError, Result};

/// Keychain "service" name under which SVX keeps its entries.
pub const KEYCHAIN_SERVICE: &str = "org.svx.desktop";

/// A reference to a signing key. It names the key; it never contains it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRef {
    File(PathBuf),
    Keychain { org: String, key_id: String },
}

impl KeyRef {
    pub fn parse(s: &str) -> Result<Self> {
        match s.strip_prefix("keychain:") {
            Some(rest) => {
                let (org, key_id) = rest
                    .split_once('/')
                    .ok_or_else(|| ClientError::Config(format!("invalid key reference {s:?}")))?;
                Identifier::new(org)
                    .map_err(|_| ClientError::Config(format!("invalid key reference {s:?}")))?;
                if key_id.len() != 32 || !key_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(ClientError::Config(format!("invalid key reference {s:?}")));
                }
                Ok(KeyRef::Keychain {
                    org: org.to_owned(),
                    key_id: key_id.to_ascii_lowercase(),
                })
            }
            None => Ok(KeyRef::File(PathBuf::from(s))),
        }
    }

    fn entry_name(org: &str, key_id: &str) -> String {
        format!("{org}/{key_id}")
    }
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyRef::File(p) => write!(f, "{}", p.display()),
            KeyRef::Keychain { org, key_id } => write!(f, "keychain:{org}/{key_id}"),
        }
    }
}

impl From<PathBuf> for KeyRef {
    fn from(p: PathBuf) -> Self {
        KeyRef::File(p)
    }
}

/// A store of named secrets. [`os_keychain`] is the real one; tests use
/// [`MemoryStore`].
pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn set(&self, name: &str, secret: &[u8]) -> Result<()>;
    fn delete(&self, name: &str) -> Result<()>;
}

/// The operating system keychain (needs the `keychain` feature), shared by
/// the whole process and read through [`CachedStore`]: each entry is read
/// from the keychain once, so macOS asks at most once per entry per launch
/// (it asks whenever an app it doesn't yet trust reads an entry).
pub fn os_keychain() -> Arc<dyn SecretStore> {
    static STORE: OnceLock<Arc<dyn SecretStore>> = OnceLock::new();
    STORE
        .get_or_init(|| Arc::new(CachedStore::new(OsKeychain, KEYCHAIN_RETRY)))
        .clone()
}

/// After a failed or refused keychain read, how long to wait before asking
/// the keychain (and so the user) again.
const KEYCHAIN_RETRY: Duration = Duration::from_secs(60);

/// A [`SecretStore`] that remembers what it read, for the life of the
/// process. Writes and deletions go through it, so it stays current. Reads
/// are one at a time, so concurrent requests never stack keychain prompts,
/// and after a failed read (for example the user chose Deny) the same entry
/// isn't asked for again until `retry_after` has passed.
pub struct CachedStore<S> {
    inner: S,
    retry_after: Duration,
    state: Mutex<CacheState>,
}

#[derive(Default)]
struct CacheState {
    values: BTreeMap<String, Option<Zeroizing<Vec<u8>>>>,
    failed: BTreeMap<String, (Instant, String)>,
}

impl<S: SecretStore> CachedStore<S> {
    pub fn new(inner: S, retry_after: Duration) -> Self {
        CachedStore {
            inner,
            retry_after,
            state: Mutex::new(CacheState::default()),
        }
    }
}

impl<S: SecretStore> SecretStore for CachedStore<S> {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        // Held across the read: one keychain prompt at a time.
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = st.values.get(name) {
            return Ok(v.clone());
        }
        if let Some((at, msg)) = st.failed.get(name)
            && at.elapsed() < self.retry_after
        {
            return Err(ClientError::Other(msg.clone()));
        }
        match self.inner.get(name) {
            Ok(v) => {
                st.failed.remove(name);
                st.values.insert(name.to_owned(), v.clone());
                Ok(v)
            }
            Err(e) => {
                st.failed
                    .insert(name.to_owned(), (Instant::now(), e.to_string()));
                Err(e)
            }
        }
    }

    fn set(&self, name: &str, secret: &[u8]) -> Result<()> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.inner.set(name, secret)?;
        st.failed.remove(name);
        st.values
            .insert(name.to_owned(), Some(Zeroizing::new(secret.to_vec())));
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.inner.delete(name)?;
        st.failed.remove(name);
        st.values.insert(name.to_owned(), None);
        Ok(())
    }
}

struct OsKeychain;

#[cfg(feature = "keychain")]
mod os {
    use super::*;

    fn entry(name: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(KEYCHAIN_SERVICE, name)
            .map_err(|e| ClientError::Config(format!("the system keychain is unavailable: {e}")))
    }

    impl SecretStore for OsKeychain {
        fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            match entry(name)?.get_secret() {
                Ok(s) => Ok(Some(Zeroizing::new(s))),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(ClientError::Other(format!("reading the keychain: {e}"))),
            }
        }

        fn set(&self, name: &str, secret: &[u8]) -> Result<()> {
            entry(name)?
                .set_secret(secret)
                .map_err(|e| ClientError::Other(format!("writing the keychain: {e}")))
        }

        fn delete(&self, name: &str) -> Result<()> {
            match entry(name)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(ClientError::Other(format!(
                    "deleting from the keychain: {e}"
                ))),
            }
        }
    }
}

#[cfg(not(feature = "keychain"))]
impl SecretStore for OsKeychain {
    fn get(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Err(no_keychain())
    }
    fn set(&self, _: &str, _: &[u8]) -> Result<()> {
        Err(no_keychain())
    }
    fn delete(&self, _: &str) -> Result<()> {
        Err(no_keychain())
    }
}

#[cfg(not(feature = "keychain"))]
fn no_keychain() -> ClientError {
    ClientError::Config("this build has no keychain support; use a key file".into())
}

/// An in-memory [`SecretStore`] for tests.
#[derive(Default)]
pub struct MemoryStore(std::sync::Mutex<std::collections::BTreeMap<String, Zeroizing<Vec<u8>>>>);

impl SecretStore for MemoryStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.0.lock().unwrap().get(name).cloned())
    }
    fn set(&self, name: &str, secret: &[u8]) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .insert(name.to_owned(), Zeroizing::new(secret.to_vec()));
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<()> {
        self.0.lock().unwrap().remove(name);
        Ok(())
    }
}

/// Stored form: `kind byte ‖ secret bytes` (the key ID is in the entry name
/// and re-checked on load).
fn encode(sk: &SigningKey) -> Zeroizing<Vec<u8>> {
    let secret = sk.to_secret_bytes();
    let mut v = Zeroizing::new(Vec::with_capacity(1 + secret.len()));
    v.push(sk.kind().byte());
    v.extend_from_slice(&secret);
    v
}

fn decode(bytes: &[u8], key_id: &str) -> Result<SigningKey> {
    let bad = || ClientError::Other("the keychain entry is not a valid SVX signing key".into());
    let (&kind, secret) = bytes.split_first().ok_or_else(bad)?;
    let kind = KeyKind::from_byte(kind).ok_or_else(bad)?;
    let sk = SigningKey::from_secret_bytes(kind, secret).map_err(|_| bad())?;
    if hex::encode(sk.verifying_key().key_id()) != key_id {
        return Err(bad());
    }
    Ok(sk)
}

/// Load the signing key `r` names, with its owner organization.
pub fn load_signing(store: &dyn SecretStore, r: &KeyRef) -> Result<(Identifier, SigningKey)> {
    match r {
        KeyRef::File(p) => keyfile::load_signing_key(p)
            .map_err(|e| ClientError::Config(format!("loading {}: {e}", p.display()))),
        KeyRef::Keychain { org, key_id } => {
            let secret = store
                .get(&KeyRef::entry_name(org, key_id))?
                .ok_or_else(|| {
                    ClientError::Config(format!(
                        "signing key {key_id} is not in this computer's keychain"
                    ))
                })?;
            let owner = Identifier::new(org)
                .map_err(|_| ClientError::Config(format!("invalid organization {org:?}")))?;
            Ok((owner, decode(&secret, key_id)?))
        }
    }
}

/// Create an SVX-2 signing key for `org` in the keychain.
/// Returns its reference and its public key (to register).
pub fn generate_in_keychain(
    store: &dyn SecretStore,
    org: &str,
) -> Result<(KeyRef, svx_core::crypto::VerifyingKey)> {
    Identifier::new(org)
        .map_err(|_| ClientError::Config(format!("invalid organization {org:?}")))?;
    let sk = SigningKey::generate_max(&mut os_rng());
    store_key(store, org, &sk)
}

/// Move a key file's signing key into the keychain. The file is left alone:
/// the caller should delete it once the keychain copy works.
pub fn import_file(
    store: &dyn SecretStore,
    path: &std::path::Path,
) -> Result<(KeyRef, svx_core::crypto::VerifyingKey)> {
    let (owner, sk) = keyfile::load_signing_key(path)
        .map_err(|e| ClientError::Config(format!("loading {}: {e}", path.display())))?;
    store_key(store, owner.as_str(), &sk)
}

fn store_key(
    store: &dyn SecretStore,
    org: &str,
    sk: &SigningKey,
) -> Result<(KeyRef, svx_core::crypto::VerifyingKey)> {
    let vk = sk.verifying_key();
    let key_id = hex::encode(vk.key_id());
    store.set(&KeyRef::entry_name(org, &key_id), &encode(sk))?;
    Ok((
        KeyRef::Keychain {
            org: org.to_owned(),
            key_id,
        },
        vk,
    ))
}

fn kem_entry_name(org: &str, key_id: &str) -> String {
    format!("{org}/kem-{key_id}")
}

/// Keep a personal account's encryption key in the keychain. Returns its key ID
/// (hex).
pub fn store_kem(store: &dyn SecretStore, org: &str, sk: &KemSecretKey) -> Result<String> {
    Identifier::new(org)
        .map_err(|_| ClientError::Config(format!("invalid organization {org:?}")))?;
    let key_id = hex::encode(sk.public_key().key_id());
    let secret = sk.to_bytes();
    let mut v = Zeroizing::new(Vec::with_capacity(1 + secret.len()));
    v.push(sk.kind().byte());
    v.extend_from_slice(secret.as_ref());
    store.set(&kem_entry_name(org, &key_id), &v)?;
    Ok(key_id)
}

/// Load the encryption key `key_id` (hex) of `org` from the keychain.
pub fn load_kem(store: &dyn SecretStore, org: &str, key_id: &str) -> Result<KemSecretKey> {
    let bytes = store.get(&kem_entry_name(org, key_id))?.ok_or_else(|| {
        ClientError::Config(format!(
            "encryption key {key_id} is not in this computer's keychain"
        ))
    })?;
    let bad = || ClientError::Other("the keychain entry is not a valid SVX encryption key".into());
    let (&kind, secret) = bytes.split_first().ok_or_else(bad)?;
    let kind = KeyKind::from_byte(kind).ok_or_else(bad)?;
    let secret: &[u8; 32] = secret.try_into().map_err(|_| bad())?;
    let sk = KemSecretKey::from_kind_bytes(kind, secret).map_err(|_| bad())?;
    if hex::encode(sk.public_key().key_id()) != key_id {
        return Err(bad());
    }
    Ok(sk)
}

/// Remove an encryption key from the keychain.
pub fn delete_kem(store: &dyn SecretStore, org: &str, key_id: &str) -> Result<()> {
    store.delete(&kem_entry_name(org, key_id))
}

/// Keep a signing key for `org` in the keychain (e.g. restored from a
/// backup).
pub fn store_signing(
    store: &dyn SecretStore,
    org: &str,
    sk: &SigningKey,
) -> Result<(KeyRef, svx_core::crypto::VerifyingKey)> {
    store_key(store, org, sk)
}

/// Remove a keychain key (key files are not touched).
pub fn delete(store: &dyn SecretStore, r: &KeyRef) -> Result<()> {
    match r {
        KeyRef::File(_) => Ok(()),
        KeyRef::Keychain { org, key_id } => store.delete(&KeyRef::entry_name(org, key_id)),
    }
}

#[cfg(test)]
mod tests {

    /// Counts reads and can be told to fail, like a keychain whose user
    /// chose Deny.
    #[derive(Default)]
    struct Counting {
        inner: MemoryStore,
        reads: std::sync::atomic::AtomicUsize,
        deny: std::sync::atomic::AtomicBool,
    }

    impl SecretStore for Counting {
        fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.deny.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ClientError::Other("reading the keychain: denied".into()));
            }
            self.inner.get(name)
        }
        fn set(&self, name: &str, secret: &[u8]) -> Result<()> {
            self.inner.set(name, secret)
        }
        fn delete(&self, name: &str) -> Result<()> {
            self.inner.delete(name)
        }
    }

    #[test]
    fn the_keychain_is_read_once_and_not_pestered_after_a_refusal() {
        use std::sync::atomic::Ordering::SeqCst;
        let c = CachedStore::new(Counting::default(), Duration::from_millis(200));
        c.inner.inner.set("a", b"one").unwrap();
        for _ in 0..5 {
            assert_eq!(c.get("a").unwrap().unwrap().as_slice(), b"one");
        }
        assert_eq!(c.inner.reads.load(SeqCst), 1);
        // Writes and deletions keep it current without reading again.
        c.set("a", b"two").unwrap();
        assert_eq!(c.get("a").unwrap().unwrap().as_slice(), b"two");
        c.delete("a").unwrap();
        assert!(c.get("a").unwrap().is_none());
        assert_eq!(c.inner.reads.load(SeqCst), 1);

        // A refused read isn't asked again until the wait is over.
        c.inner.deny.store(true, SeqCst);
        assert!(c.get("b").is_err());
        assert!(c.get("b").is_err());
        assert_eq!(c.inner.reads.load(SeqCst), 2);
        c.inner.deny.store(false, SeqCst);
        std::thread::sleep(Duration::from_millis(250));
        assert!(c.get("b").unwrap().is_none());
        assert_eq!(c.inner.reads.load(SeqCst), 3);
    }

    use super::*;

    #[test]
    fn refs_parse_and_print() {
        let r = KeyRef::parse("keychain:acme-security/00112233445566778899AABBCCDDEEFF").unwrap();
        assert_eq!(
            r.to_string(),
            "keychain:acme-security/00112233445566778899aabbccddeeff"
        );
        assert_eq!(
            KeyRef::parse("/tmp/acme.sign.key").unwrap(),
            KeyRef::File("/tmp/acme.sign.key".into())
        );
        for bad in [
            "keychain:acme",
            "keychain:Acme Security/00112233445566778899aabbccddeeff",
            "keychain:acme/0011",
            "keychain:acme/zz112233445566778899aabbccddeeff",
        ] {
            assert!(KeyRef::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn keychain_round_trip() {
        let store = MemoryStore::default();
        let (r, vk) = generate_in_keychain(&store, "acme-security").unwrap();
        assert_eq!(vk.kind(), KeyKind::MaxSigning);
        let (owner, sk) = load_signing(&store, &r).unwrap();
        assert_eq!(owner.as_str(), "acme-security");
        assert_eq!(sk.verifying_key(), vk);
        // A tampered entry or another key under this name is refused.
        let KeyRef::Keychain { org, key_id } = &r else {
            unreachable!()
        };
        let name = KeyRef::entry_name(org, key_id);
        let other = SigningKey::generate_max(&mut os_rng());
        store.set(&name, &encode(&other)).unwrap();
        assert!(load_signing(&store, &r).is_err());
        store.set(&name, b"\x04short").unwrap();
        assert!(load_signing(&store, &r).is_err());
        delete(&store, &r).unwrap();
        assert!(matches!(
            load_signing(&store, &r),
            Err(ClientError::Config(_))
        ));
    }

    #[test]
    fn kem_keys_round_trip() {
        let store = MemoryStore::default();
        let sk = KemSecretKey::generate_max(&mut os_rng());
        let id = store_kem(&store, "u.0011223344556677", &sk).unwrap();
        let back = load_kem(&store, "u.0011223344556677", &id).unwrap();
        assert_eq!(back.public_key(), sk.public_key());
        let other = "00".repeat(16);
        assert!(load_kem(&store, "u.0011223344556677", &other).is_err());
        delete_kem(&store, "u.0011223344556677", &id).unwrap();
        assert!(load_kem(&store, "u.0011223344556677", &id).is_err());
    }

    #[test]
    fn import_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("acme");
        crate::keys::generate_signing(&prefix, "acme-security").unwrap();
        let store = MemoryStore::default();
        let (r, vk) = import_file(&store, &dir.path().join("acme.sign.key")).unwrap();
        let (_, from_file) =
            load_signing(&store, &KeyRef::File(dir.path().join("acme.sign.key"))).unwrap();
        assert_eq!(from_file.verifying_key(), vk);
        assert_eq!(load_signing(&store, &r).unwrap().1.verifying_key(), vk);
    }
}
