//! RFC 9420 (MLS) key-schedule crypto primitives for ciphersuite 1
//! (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`): `ExpandWithLabel`,
//! `DeriveSecret`, and `RefHash`, with the MLS variable-length vector
//! ("varint") encoding from RFC 9420 §2.1.2.
//!
//! Validated against the MLS working group's official `crypto-basics` test
//! vectors (see the tests). These use the ciphersuite's own hash/KDF
//! (SHA-256 / HKDF-SHA-256), independent of talkrypt's default SHA3 KDF.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Hash output length for SHA-256 (`KDF.Nh`).
pub const NH: u16 = 32;

/// Append an RFC 9420 §2.1.2 variable-length integer (QUIC varint).
fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < (1 << 30) {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// Append an `opaque x<V>` field: varint length prefix then the bytes.
pub(crate) fn put_opaque(out: &mut Vec<u8>, data: &[u8]) {
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// Build a labeled content blob `{ opaque label<V> = "MLS 1.0 "+label;
/// opaque content<V> }` — the body that `SignWithLabel`/`EncryptWithLabel`
/// sign/encrypt over.
pub(crate) fn labeled_content(label: &str, content: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    put_opaque(&mut b, &[b"MLS 1.0 ", label.as_bytes()].concat());
    put_opaque(&mut b, content);
    b
}

/// `ExpandWithLabel(secret, label, context, length)` =
/// `HKDF-Expand(secret, KDFLabel, length)`.
pub fn expand_with_label(secret: &[u8], label: &str, context: &[u8], length: u16) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&length.to_be_bytes());
    let full_label = [b"MLS 1.0 ", label.as_bytes()].concat();
    put_opaque(&mut info, &full_label);
    put_opaque(&mut info, context);

    let hk = Hkdf::<Sha256>::from_prk(secret).expect("secret is a valid PRK length");
    let mut out = vec![0u8; length as usize];
    hk.expand(&info, &mut out).expect("hkdf expand");
    out
}

/// `DeriveSecret(secret, label)` = `ExpandWithLabel(secret, label, "", Nh)`.
pub fn derive_secret(secret: &[u8], label: &str) -> Vec<u8> {
    expand_with_label(secret, label, &[], NH)
}

/// `KDF.Extract(salt, ikm)` (HKDF-SHA256 extract), returning the PRK.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.to_vec()
}

/// The epoch secrets derived from `epoch_secret` (RFC 9420 §8).
pub struct EpochSecrets {
    pub sender_data: Vec<u8>,
    pub encryption: Vec<u8>,
    pub exporter: Vec<u8>,
    pub external: Vec<u8>,
    pub confirmation_key: Vec<u8>,
    pub membership_key: Vec<u8>,
    pub resumption_psk: Vec<u8>,
    pub epoch_authenticator: Vec<u8>,
    pub init_next: Vec<u8>,
}

/// Compute the next epoch's secrets from the previous `joiner_secret`,
/// `psk_secret`, and serialized `group_context` (RFC 9420 §8 key schedule).
/// Returns `(welcome_secret, epoch_secret, EpochSecrets)`.
pub fn epoch_key_schedule(
    joiner_secret: &[u8],
    psk_secret: &[u8],
    group_context: &[u8],
) -> (Vec<u8>, Vec<u8>, EpochSecrets) {
    let prk = extract(joiner_secret, psk_secret);
    let welcome_secret = expand_with_label(&prk, "welcome", &[], NH);
    let epoch_secret = expand_with_label(&prk, "epoch", group_context, NH);
    let secrets = EpochSecrets {
        sender_data: derive_secret(&epoch_secret, "sender data"),
        encryption: derive_secret(&epoch_secret, "encryption"),
        exporter: derive_secret(&epoch_secret, "exporter"),
        external: derive_secret(&epoch_secret, "external"),
        confirmation_key: derive_secret(&epoch_secret, "confirm"),
        membership_key: derive_secret(&epoch_secret, "membership"),
        resumption_psk: derive_secret(&epoch_secret, "resumption"),
        epoch_authenticator: derive_secret(&epoch_secret, "authentication"),
        init_next: derive_secret(&epoch_secret, "init"),
    };
    (welcome_secret, epoch_secret, secrets)
}

/// `RefHash(label, value)` = `Hash(RefHashInput)` where
/// `RefHashInput = { opaque label<V>; opaque value<V> }`.
pub fn ref_hash(label: &str, value: &[u8]) -> [u8; 32] {
    let mut input = Vec::new();
    put_opaque(&mut input, label.as_bytes());
    put_opaque(&mut input, value);
    Sha256::digest(&input).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Official MLS `crypto-basics` vectors, cipher_suite 1
    // (mlswg/mls-implementations test-vectors/crypto-basics.json).

    #[test]
    fn expand_with_label_matches_rfc9420_vector() {
        let secret = hex("1499360a561335f4ef51d0a1b0d586900dc8007ae405b1ab79bf4207bb3d67e4");
        let context = hex("2ff8c1f9d9c1248f82e372ddb5791c771695e01882abca6a64097bd2f04c971f");
        let out = expand_with_label(&secret, "ExpandWithLabel", &context, 16);
        assert_eq!(out, hex("c1e8eb360391526c0c64039f13e0c5b1"));
    }

    #[test]
    fn derive_secret_matches_rfc9420_vector() {
        let secret = hex("1a9ce178a53f8752d2513c27efe9c85133f6c0a97f7b35ac200695024a77228e");
        let out = derive_secret(&secret, "DeriveSecret");
        assert_eq!(
            out,
            hex("3b08c195a246c4ad469c1d11c10e62890d8fa6b684494ff925409efdb1ff0464")
        );
    }

    #[test]
    fn ref_hash_matches_rfc9420_vector() {
        let value = hex("40312db83f651883c05ab26fa12c6af61930015c81947cfd0f129e6d99210bb2");
        let out = ref_hash("RefHash", &value);
        assert_eq!(
            out.to_vec(),
            hex("e8027fffc5f9bb469f29172538dc0f3a78f14f323495bbd2217eba7a77fb242a")
        );
    }

    #[test]
    fn epoch_key_schedule_matches_rfc9420_vector() {
        // Official key-schedule.json, cipher_suite 1, first epoch.
        let joiner = hex("4fb996ba26b29a70f3ce6c310151ce8701cb812d027f4d4bbf5cc4e9f884638d");
        let psk = hex("e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b");
        let gc = hex("0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00");

        let (welcome, _epoch, s) = epoch_key_schedule(&joiner, &psk, &gc);
        assert_eq!(
            welcome,
            hex("ddcd9ced2d264798f876cbd00a200cdc4d77311dfef96975257efb66b0ef2c4d")
        );
        assert_eq!(
            s.sender_data,
            hex("9b3995e08589548b75e149190060cf35228df0eefe3527ea2fb39e49a84125b4")
        );
        assert_eq!(
            s.encryption,
            hex("01588615c93d02c83bda0b587473303b1637a92bf80783206d963f9197c40a13")
        );
        assert_eq!(
            s.exporter,
            hex("5a097e149f2a375d0b9e1d1f4dc3a9c6c1788df888e5441f41a8791f4dc56cea")
        );
        assert_eq!(
            s.external,
            hex("b5cb5666cfb9c501ed76715c6ed1cafbed5061cd6b86898ae5d3fd4cb05abb26")
        );
        assert_eq!(
            s.confirmation_key,
            hex("feabd690de3b4ce985a3dfad86a4c4e6a0be9b84e7cc764842784f2a6b938b75")
        );
        assert_eq!(
            s.membership_key,
            hex("970744ba7edd21700a3e106cb4e2b4c657cef6b41a1fe5b5a1418f86e76e037e")
        );
        assert_eq!(
            s.resumption_psk,
            hex("d78ca815e192823f5c7c94b0156bdc7af4791cfb3f240fff613c0c03c01dabd5")
        );
        assert_eq!(
            s.epoch_authenticator,
            hex("7375d449cde2c5a856c13c8eb52c16bf9ef29eceef59b09d1f946bd1bac24643")
        );
        assert_eq!(
            s.init_next,
            hex("505be2ce2ff922aa11e0a03d76346dda2981f1d9edf5cf98ecfc8757f69b00c9")
        );
    }

    #[test]
    fn varint_encoding_boundaries() {
        let mut b = Vec::new();
        put_varint(&mut b, 63);
        assert_eq!(b, [63]); // 1-byte form
        let mut b = Vec::new();
        put_varint(&mut b, 64);
        assert_eq!(b, [0x40, 0x40]); // 2-byte form
    }
}
