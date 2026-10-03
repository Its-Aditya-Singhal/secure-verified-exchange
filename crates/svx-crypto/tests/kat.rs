//! Known-answer tests for the post-quantum primitives SVX-1H relies on,
//! from official vectors (see `tests/data/*.json` for sources):
//!
//! * X-Wing HPKE (X25519 + ML-KEM-768, HKDF-SHA256, ChaCha20-Poly1305, base
//!   mode) from the HPKE PQ draft vectors shipped with rust-hpke;
//! * ML-DSA-65 key generation and signature verification from NIST ACVP.
//!
//! They pin both the libraries and how `svx-crypto` wires them up.

use hpke::{Deserializable, Kem as _, OpModeR, Serializable};
use ml_dsa::signature::Keypair as _;
use ml_dsa::{EncodedVerifyingKey, MlDsa65};
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
