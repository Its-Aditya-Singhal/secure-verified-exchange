//! Compatibility of account backups: the parameters are stored in each
//! file, so a backup made by an older build (cheaper Argon2id) must keep
//! opening, and the committed fixture pins the current file format.
//! Regenerate the fixture only for a deliberate format change:
//! `cargo test -p svx-crypto --test backup_compat -- --ignored make_fixture`

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use svx_crypto::{BackupParams, open_with_password, seal_with_password};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/backup-v1.svxbackup"
);
const PASSWORD: &str = "fictional recovery password for tests";
const PLAINTEXT: &[u8] = b"fictional key material, test only";

#[test]
fn backups_from_the_older_cost_still_open() {
    // Phase 5d backups: 64 MiB, 3 passes.
    let old = BackupParams {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let blob = seal_with_password(PASSWORD, PLAINTEXT, old, &mut rng).unwrap();
    assert_eq!(&*open_with_password(PASSWORD, &blob).unwrap(), PLAINTEXT);
    assert!(open_with_password("another password entirely", &blob).is_err());
}

#[test]
fn the_committed_backup_still_opens() {
    let blob = std::fs::read(FIXTURE).unwrap();
    assert_eq!(&*open_with_password(PASSWORD, &blob).unwrap(), PLAINTEXT);
    assert!(open_with_password("another password entirely", &blob).is_err());
}

#[test]
#[ignore = "writes the fixture"]
fn make_fixture() {
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let blob = seal_with_password(PASSWORD, PLAINTEXT, BackupParams::STRONG, &mut rng).unwrap();
    std::fs::write(FIXTURE, blob).unwrap();
}
