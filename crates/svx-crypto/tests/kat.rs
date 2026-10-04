//! Known-answer tests for the post-quantum primitives SVX-1H relies on,
//! from official vectors (see `tests/data/*.json` for sources):
//!
//! * X-Wing HPKE (X25519 + ML-KEM-768, HKDF-SHA256, ChaCha20-Poly1305, base
//!   mode) from the HPKE PQ draft vectors shipped with rust-hpke;
//! * ML-DSA-65 key generation and signature verification from NIST ACVP;
//!
//! and for suite SVX-2:
//!
//! * MLKEM1024-P384 HPKE (`draft-ietf-hpke-pq`) from the same rust-hpke
//!   vectors (the only published vector pairs it with HKDF-SHA384 and
//!   AES-256-GCM; the KEM part is what SVX-2 adds);
//! * ML-DSA-87 and SLH-DSA-SHA2-256s key generation and signature
//!   verification from NIST ACVP.
//!
//! They pin both the libraries and how `svx-crypto` wires them up.

use hpke::{Deserializable, Kem as _, OpModeR, Serializable};
use ml_dsa::signature::Keypair as _;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, MlDsa87};
use serde_json::Value;
use svx_crypto::{KemSecretKey, KeyKind, SigningKey, VerifyingKey};

fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

#[test]
fn xwing_hpke_known_answer() {
    let v: Value = serde_json::from_str(include_str!("data/xwing-hpke.json")).unwrap();
    assert_eq!(v["kem_id"], 0x647a);
    assert_eq!(v["kdf_id"], 1);
    assert_eq!(v["aead_id"], 3);

    // Our key derivation gives the vector's key pair.
    let sk = KemSecretKey::derive_kind(KeyKind::XWingKem, &hex(&v["ikmR"])).unwrap();
    assert_eq!(sk.to_bytes().as_slice(), hex(&v["skRm"]).as_slice());
    assert_eq!(sk.public_key().to_vec(), hex(&v["pkRm"]));
    let restored = KemSecretKey::from_kind_bytes(
        KeyKind::XWingKem,
        hex(&v["skRm"]).as_slice().try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(restored.public_key().to_vec(), hex(&v["pkRm"]));

    // The library decrypts the vector's first message (sequence 0 = single-shot).
    type K = hpke::kem::XWing;
    let skr = <K as hpke::Kem>::PrivateKey::from_bytes(&hex(&v["skRm"])).unwrap();
    let enc = <K as hpke::Kem>::EncappedKey::from_bytes(&hex(&v["enc"])).unwrap();
    let e = &v["encryptions"][0];
    let pt = hpke::single_shot_open::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, K>(
        &OpModeR::Base,
        &skr,
        &enc,
        &hex(&v["info"]),
        &hex(&e["ct"]),
        &hex(&e["aad"]),
    )
    .unwrap();
    assert_eq!(pt, hex(&e["pt"]));
    assert_eq!(K::sk_to_pk(&skr).to_bytes().to_vec(), hex(&v["pkRm"]));
}

#[test]
fn mldsa65_keygen_known_answers() {
    let v: Value = serde_json::from_str(include_str!("data/mldsa65-acvp.json")).unwrap();
    let cases = v["keyGen"].as_array().unwrap();
    assert!(!cases.is_empty());
    for t in cases {
        let seed: [u8; 32] = hex(&t["seed"]).try_into().unwrap();
        let pk = hex(&t["pk"]);
        let ml = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed.into());
        assert_eq!(
            ml.verifying_key().encode().as_slice(),
            pk.as_slice(),
            "tc {}",
            t["tcId"]
        );
        // A hybrid key built from this ML-DSA seed publishes exactly that key.
        let hybrid = SigningKey::hybrid_from_seeds(&[9; 32], &seed).verifying_key();
        assert_eq!(&hybrid.to_vec()[32..], pk.as_slice());
        // And it round-trips through our decoder.
        VerifyingKey::from_kind_bytes(KeyKind::HybridSigning, &hybrid.to_vec()).unwrap();
    }
}

#[test]
fn mldsa65_sigver_known_answers() {
    let v: Value = serde_json::from_str(include_str!("data/mldsa65-acvp.json")).unwrap();
    let cases = v["sigVer"].as_array().unwrap();
    let (mut valid, mut invalid) = (0, 0);
    for t in cases {
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(hex(&t["pk"]).as_slice()).unwrap();
        let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
        let sig = hex(&t["signature"]);
        let ok = ml_dsa::Signature::<MlDsa65>::try_from(sig.as_slice())
            .map(|s| vk.verify_with_context(&hex(&t["message"]), &hex(&t["context"]), &s))
            .unwrap_or(false);
        let expected = t["testPassed"].as_bool().unwrap();
        assert_eq!(ok, expected, "tc {} ({})", t["tcId"], t["reason"]);
        if expected { valid += 1 } else { invalid += 1 }
    }
    assert!(valid > 0 && invalid > 0);
}

#[test]
fn mlkem1024_p384_hpke_known_answer() {
    let v: Value = serde_json::from_str(include_str!("data/mlkem1024p384-hpke.json")).unwrap();
    assert_eq!(v["kem_id"], 0x0051);
    let sk = KemSecretKey::derive_kind(KeyKind::MaxKem, &hex(&v["ikmR"])).unwrap();
    assert_eq!(sk.to_bytes().as_slice(), hex(&v["skRm"]).as_slice());
    assert_eq!(sk.public_key().to_vec(), hex(&v["pkRm"]));
    let restored = KemSecretKey::from_kind_bytes(
        KeyKind::MaxKem,
        hex(&v["skRm"]).as_slice().try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(restored.public_key().to_vec(), hex(&v["pkRm"]));

    type K = hpke::kem::MlKem1024P384;
    assert_eq!(v["kdf_id"], 2); // HKDF-SHA384
    assert_eq!(v["aead_id"], 2); // AES-256-GCM
    let skr = <K as hpke::Kem>::PrivateKey::from_bytes(&hex(&v["skRm"])).unwrap();
    let enc = <K as hpke::Kem>::EncappedKey::from_bytes(&hex(&v["enc"])).unwrap();
    let e = &v["encryptions"][0];
    let pt = hpke::single_shot_open::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, K>(
        &OpModeR::Base,
        &skr,
        &enc,
        &hex(&v["info"]),
        &hex(&e["ct"]),
        &hex(&e["aad"]),
    )
    .unwrap();
    assert_eq!(pt, hex(&e["pt"]));
}

#[test]
fn mldsa87_keygen_known_answers() {
    let v: Value = serde_json::from_str(include_str!("data/mldsa87-acvp.json")).unwrap();
    let cases = v["keyGen"].as_array().unwrap();
    assert!(!cases.is_empty());
    for t in cases {
        let seed: [u8; 32] = hex(&t["seed"]).try_into().unwrap();
        let pk = hex(&t["pk"]);
        let ml = ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed.into());
        assert_eq!(
            ml.verifying_key().encode().as_slice(),
            pk.as_slice(),
            "tc {}",
            t["tcId"]
        );
        // A Max key built from this ML-DSA seed publishes exactly that key.
        let mut secret = vec![9u8; 32];
        secret.extend_from_slice(&seed);
        secret.extend_from_slice(&[7u8; 96]);
        let max = SigningKey::from_secret_bytes(KeyKind::MaxSigning, &secret)
            .unwrap()
            .verifying_key()
            .to_vec();
        assert_eq!(&max[32..32 + 2592], pk.as_slice());
        VerifyingKey::from_kind_bytes(KeyKind::MaxSigning, &max).unwrap();
    }
}

#[test]
fn mldsa87_sigver_known_answers() {
    let v: Value = serde_json::from_str(include_str!("data/mldsa87-acvp.json")).unwrap();
    let (mut valid, mut invalid) = (0, 0);
    for t in v["sigVer"].as_array().unwrap() {
        let enc = EncodedVerifyingKey::<MlDsa87>::try_from(hex(&t["pk"]).as_slice()).unwrap();
        let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&enc);
        let sig = hex(&t["signature"]);
        let ok = ml_dsa::Signature::<MlDsa87>::try_from(sig.as_slice())
            .map(|s| vk.verify_with_context(&hex(&t["message"]), &hex(&t["context"]), &s))
            .unwrap_or(false);
        let expected = t["testPassed"].as_bool().unwrap();
        assert_eq!(ok, expected, "tc {} ({})", t["tcId"], t["reason"]);
        if expected { valid += 1 } else { invalid += 1 }
    }
    assert!(valid > 0 && invalid > 0);
}

#[test]
fn slhdsa_sha2_256s_keygen_known_answers() {
    let v: Value = serde_json::from_str(include_str!("data/slhdsa-sha2-256s-acvp.json")).unwrap();
    let cases = v["keyGen"].as_array().unwrap();
    assert!(!cases.is_empty());
    for t in cases {
        // Our secret layout: Ed25519 seed ‖ ML-DSA-87 seed ‖ SK.seed ‖ SK.prf ‖ PK.seed.
        let mut secret = vec![9u8; 32];
        secret.extend_from_slice(&[8u8; 32]);
        secret.extend_from_slice(&hex(&t["skSeed"]));
        secret.extend_from_slice(&hex(&t["skPrf"]));
        secret.extend_from_slice(&hex(&t["pkSeed"]));
        let key = SigningKey::from_secret_bytes(KeyKind::MaxSigning, &secret).unwrap();
        let public = key.verifying_key().to_vec();
        assert_eq!(
            &public[32 + 2592..],
            hex(&t["pk"]).as_slice(),
            "tc {}",
            t["tcId"]
        );
        // And the seeds round-trip.
        assert_eq!(key.to_secret_bytes().as_slice(), secret.as_slice());
    }
}

#[test]
fn slhdsa_sha2_256s_sigver_known_answers() {
    use slh_dsa::{Sha2_256s, Signature, VerifyingKey as SlhKey};
    let v: Value = serde_json::from_str(include_str!("data/slhdsa-sha2-256s-acvp.json")).unwrap();
    let (mut valid, mut invalid) = (0, 0);
    for t in v["sigVer"].as_array().unwrap() {
        let vk = SlhKey::<Sha2_256s>::try_from(hex(&t["pk"]).as_slice()).unwrap();
        let sig = hex(&t["signature"]);
        let ok = Signature::<Sha2_256s>::try_from(sig.as_slice())
            .map(|s| {
                vk.try_verify_with_context(&hex(&t["message"]), &hex(&t["context"]), &s)
                    .is_ok()
            })
            .unwrap_or(false);
        let expected = t["testPassed"].as_bool().unwrap();
        assert_eq!(ok, expected, "tc {} ({})", t["tcId"], t["reason"]);
        if expected { valid += 1 } else { invalid += 1 }
    }
    assert!(valid > 0 && invalid > 0);
}
