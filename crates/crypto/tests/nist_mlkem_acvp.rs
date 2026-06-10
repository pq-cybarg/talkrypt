//! NIST FIPS-203 ACVP known-answer tests for ML-KEM-1024 (SECURITY-AUDIT R-5).
//!
//! Verifies talkrypt's ML-KEM-1024 (via the `ml-kem` 0.2.3 dependency, FIPS-203
//! *final*) against the official NIST ACVP vectors in
//! `tests/data/nist_mlkem1024_acvp.txt` — key generation, encapsulation, and
//! decapsulation. This is genuine CAVP traceability: the inputs and expected
//! outputs are NIST's, not ours. The startup self-test (`selftest::kem_kat`)
//! pins the compact keyGen digests from this same vector; this test additionally
//! checks the full encaps/decaps shared secrets.

use ml_kem::kem::Decapsulate;
use ml_kem::{Encoded, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem1024, B32};
use sha3::Digest;

const DATA: &str = include_str!("data/nist_mlkem1024_acvp.txt");

fn field(name: &str) -> Vec<u8> {
    let line = DATA
        .lines()
        .find(|l| l.starts_with(name))
        .unwrap_or_else(|| panic!("missing field {name}"));
    let hexs = line.split('=').nth(1).expect("field has a value").trim();
    (0..hexs.len() / 2)
        .map(|i| u8::from_str_radix(&hexs[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn field_str(name: &str) -> String {
    DATA.lines()
        .find(|l| l.starts_with(name))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| panic!("missing field {name}"))
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

type Ek = <MlKem1024 as KemCore>::EncapsulationKey;
type Dk = <MlKem1024 as KemCore>::DecapsulationKey;

#[test]
fn ml_kem_1024_keygen_matches_nist_acvp() {
    let d = B32::try_from(&field("keygen_d")[..]).unwrap();
    let z = B32::try_from(&field("keygen_z")[..]).unwrap();
    let (dk, ek) = MlKem1024::generate_deterministic(&d, &z);
    assert_eq!(
        hexs(&sha3::Sha3_256::digest(ek.as_bytes().as_slice())),
        field_str("keygen_ek_sha3_256"),
        "ML-KEM-1024 keyGen ek does not match the NIST ACVP vector"
    );
    assert_eq!(
        hexs(&sha3::Sha3_256::digest(dk.as_bytes().as_slice())),
        field_str("keygen_dk_sha3_256"),
        "ML-KEM-1024 keyGen dk does not match the NIST ACVP vector"
    );
}

#[test]
fn ml_kem_1024_encaps_matches_nist_acvp() {
    let ekb = field("encaps_ek");
    let m = field("encaps_m");
    let ek = Ek::from_bytes(&Encoded::<Ek>::try_from(&ekb[..]).unwrap());
    let (_c, k) = ek
        .encapsulate_deterministic(&B32::try_from(&m[..]).unwrap())
        .unwrap();
    assert_eq!(
        hexs(k.as_slice()),
        field_str("encaps_k"),
        "ML-KEM-1024 encapsulation shared secret does not match the NIST ACVP vector"
    );
}

#[test]
fn ml_kem_1024_decaps_matches_nist_acvp() {
    let dkb = field("decaps_dk");
    let cb = field("decaps_c");
    let dk = Dk::from_bytes(&Encoded::<Dk>::try_from(&dkb[..]).unwrap());
    let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(&cb[..]).unwrap();
    let k = dk.decapsulate(&ct).unwrap();
    assert_eq!(
        hexs(k.as_slice()),
        field_str("decaps_k"),
        "ML-KEM-1024 decapsulation shared secret does not match the NIST ACVP vector"
    );
}
