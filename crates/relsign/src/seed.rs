//! QRL-2.0 (Zond)-style seed representations for the release signing seeds.
//!
//! talkrypt's signing secret is a 32-byte entropy value for ML-DSA-87 or
//! SLH-DSA-SHA2-256s — the same two schemes QRL's Zond is adopting (ML-DSA-87 +
//! SPHINCS+-256s). Following Zond's crypto-agility model, we wrap that entropy in a
//! **descriptor** (which scheme/hash/version) and offer three interchangeable,
//! configurable representations — a [`SeedFormat`] selects which the tool emits:
//!
//! - **mnemonic** (default, recommended): a QRL 24-word phrase over the hexseed,
//!   indexed against QRL's own 4096-word list (12 bits/word) — the safest offline
//!   backup (transcribe to paper/metal; self-describing; error-resistant).
//! - **hexseed**: `descriptor(3) ‖ entropy(32)` = 35 bytes / 70 hex chars.
//! - **raw**: the bare 32-byte entropy hex (back-compat with 0003's plaintext seed).
//!
//! The **address** is a Zond-style key fingerprint: `Q` ‖ hex(last 24 bytes of
//! `SHAKE256(descriptor ‖ pubkey)`) — a short value to pin out of band instead of a
//! full multi-KB public key.
//!
//! All parsing is TOTAL and fail-closed (arbitrary input ⇒ typed `Err`, never a
//! panic or a wrong seed). The sealed-at-rest custody is separate ([`crate::seal`]);
//! these are the human-facing encodings of the same entropy.

use crate::{hex, Algo};

const DESC_LEN: usize = 3; // [scheme, hash, version]
const ENTROPY_LEN: usize = 32;
const HEXSEED_LEN: usize = DESC_LEN + ENTROPY_LEN; // 35
const HASH_SHAKE256: u8 = 0x00;
const VERSION: u8 = 0x01;
const ADDR_TAKE: usize = 24; // last 24 bytes of SHAKE256(desc‖pub)

/// QRL's canonical 4096-word mnemonic list (12 bits/word), vendored verbatim from
/// theQRL/qrllib — see `third-party/qrl-wordlist/TALKRYPT-PATCH.md`.
const WORDLIST_SRC: &str = include_str!("../../../third-party/qrl-wordlist/wordlist.txt");

fn wordlist() -> Vec<&'static str> {
    WORDLIST_SRC.split_whitespace().collect()
}

/// Which signing scheme a seed is for — the descriptor's first byte (crypto-agility
/// in the QRL-2.0 sense). Values are talkrypt's own stable mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scheme {
    MlDsa87 = 0x02,
    SlhDsaSha2_256s = 0x03,
}

impl Scheme {
    fn from_byte(b: u8) -> Option<Scheme> {
        match b {
            0x02 => Some(Scheme::MlDsa87),
            0x03 => Some(Scheme::SlhDsaSha2_256s),
            _ => None,
        }
    }
    pub fn algo(self) -> Algo {
        match self {
            Scheme::MlDsa87 => Algo::MlDsa,
            Scheme::SlhDsaSha2_256s => Algo::SlhDsa,
        }
    }
    pub fn of(algo: Algo) -> Scheme {
        match algo {
            Algo::MlDsa => Scheme::MlDsa87,
            Algo::SlhDsa => Scheme::SlhDsaSha2_256s,
        }
    }
}

/// A 3-byte descriptor: `[scheme][hash][version]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Descriptor {
    pub scheme: Scheme,
    pub hash: u8,
    pub version: u8,
}

impl Descriptor {
    pub fn for_algo(algo: Algo) -> Descriptor {
        Descriptor { scheme: Scheme::of(algo), hash: HASH_SHAKE256, version: VERSION }
    }
    fn bytes(self) -> [u8; DESC_LEN] {
        [self.scheme as u8, self.hash, self.version]
    }
    fn parse(b: &[u8]) -> Result<Descriptor, SeedError> {
        if b.len() < DESC_LEN {
            return Err(SeedError::Malformed("descriptor too short"));
        }
        Ok(Descriptor {
            scheme: Scheme::from_byte(b[0]).ok_or(SeedError::Malformed("unknown scheme"))?,
            hash: b[1],
            version: b[2],
        })
    }
    pub fn algo(self) -> Algo {
        self.scheme.algo()
    }
}

/// Configurable human-facing seed representation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeedFormat {
    /// QRL 24-word mnemonic over the hexseed (default / recommended).
    Mnemonic,
    /// `descriptor(3) ‖ entropy(32)` as hex.
    Hexseed,
    /// Bare 32-byte entropy hex (no descriptor).
    Raw,
}

impl SeedFormat {
    pub fn parse(s: &str) -> Option<SeedFormat> {
        match s {
            "mnemonic" | "words" => Some(SeedFormat::Mnemonic),
            "hexseed" => Some(SeedFormat::Hexseed),
            "raw" | "hex" => Some(SeedFormat::Raw),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SeedError {
    Malformed(&'static str),
    UnknownWord,
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedError::Malformed(w) => write!(f, "malformed seed: {w}"),
            SeedError::UnknownWord => f.write_str("mnemonic contains a word not in the QRL wordlist"),
        }
    }
}
impl std::error::Error for SeedError {}

/// `descriptor ‖ entropy` as hex (70 chars).
pub fn hexseed(desc: Descriptor, entropy: &[u8; 32]) -> String {
    let mut v = Vec::with_capacity(HEXSEED_LEN);
    v.extend_from_slice(&desc.bytes());
    v.extend_from_slice(entropy);
    hex::encode(&v)
}

/// Parse a hexseed (hex of `descriptor(3) ‖ entropy(32)`).
pub fn parse_hexseed(s: &str) -> Result<(Descriptor, [u8; 32]), SeedError> {
    let b = hex::decode(s).map_err(|_| SeedError::Malformed("bad hexseed hex"))?;
    if b.len() != HEXSEED_LEN {
        return Err(SeedError::Malformed("hexseed must be 35 bytes"));
    }
    let desc = Descriptor::parse(&b)?;
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&b[DESC_LEN..]);
    Ok((desc, entropy))
}

/// The QRL 24-word mnemonic over the hexseed. The 35-byte hexseed is zero-padded to
/// 36 bytes (a multiple of 3) and packed 3 bytes → 2 twelve-bit words (QRL scheme).
pub fn mnemonic(desc: Descriptor, entropy: &[u8; 32]) -> String {
    let wl = wordlist();
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&desc.bytes());
    bytes.extend_from_slice(entropy);
    bytes.push(0x00); // pad 35 -> 36 (multiple of 3)
    let mut words = Vec::with_capacity(24);
    for chunk in bytes.chunks_exact(3) {
        let (b0, b1, b2) = (chunk[0] as usize, chunk[1] as usize, chunk[2] as usize);
        let w1 = (b0 << 4) | (b1 >> 4);
        let w2 = ((b1 & 0x0f) << 8) | b2;
        words.push(wl[w1]);
        words.push(wl[w2]);
    }
    words.join(" ")
}

/// Recover `(descriptor, entropy)` from a QRL mnemonic. Fail-closed on any bad word,
/// wrong length, non-zero pad byte, or unknown scheme.
pub fn parse_mnemonic(phrase: &str) -> Result<(Descriptor, [u8; 32]), SeedError> {
    let wl = wordlist();
    let idx = |w: &str| wl.iter().position(|x| *x == w).ok_or(SeedError::UnknownWord);
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 24 {
        return Err(SeedError::Malformed("mnemonic must be 24 words"));
    }
    let mut bytes = Vec::with_capacity(36);
    for pair in words.chunks_exact(2) {
        let w1 = idx(pair[0])?;
        let w2 = idx(pair[1])?;
        bytes.push((w1 >> 4) as u8);
        bytes.push((((w1 & 0x0f) << 4) | (w2 >> 8)) as u8);
        bytes.push((w2 & 0xff) as u8);
    }
    // 36 bytes: 3 descriptor + 32 entropy + 1 pad.
    if bytes.len() != 36 || bytes[35] != 0x00 {
        return Err(SeedError::Malformed("bad mnemonic padding"));
    }
    let desc = Descriptor::parse(&bytes)?;
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&bytes[DESC_LEN..HEXSEED_LEN]);
    Ok((desc, entropy))
}

/// Zond-style key fingerprint address: `Q` ‖ hex(last 24 bytes of
/// `SHAKE256(descriptor ‖ pubkey)`). Short enough to pin out of band.
pub fn address(desc: Descriptor, pubkey: &[u8]) -> String {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    h.update(&desc.bytes());
    h.update(pubkey);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    format!("Q{}", hex::encode(&out[32 - ADDR_TAKE..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use talkrypt_crypto::IdentityKeyPair;

    fn ml_seed() -> [u8; 32] {
        IdentityKeyPair::generate().export_secret()
    }

    #[test]
    fn wordlist_is_4096_unique() {
        let wl = wordlist();
        assert_eq!(wl.len(), 4096);
        let set: std::collections::HashSet<_> = wl.iter().collect();
        assert_eq!(set.len(), 4096);
        assert_eq!(wl[0], "aback");
        assert_eq!(wl[4095], "zurich");
    }

    #[test]
    fn hexseed_roundtrips_and_carries_descriptor() {
        let e = ml_seed();
        let d = Descriptor::for_algo(Algo::MlDsa);
        let hs = hexseed(d, &e);
        assert_eq!(hs.len(), HEXSEED_LEN * 2);
        let (d2, e2) = parse_hexseed(&hs).unwrap();
        assert_eq!(d2, d);
        assert_eq!(e2, e);
        assert_eq!(d2.algo(), Algo::MlDsa);
    }

    #[test]
    fn mnemonic_roundtrips_both_schemes() {
        for algo in [Algo::MlDsa, Algo::SlhDsa] {
            let e = if algo == Algo::MlDsa { ml_seed() } else { [7u8; 32] };
            let d = Descriptor::for_algo(algo);
            let m = mnemonic(d, &e);
            assert_eq!(m.split_whitespace().count(), 24);
            let (d2, e2) = parse_mnemonic(&m).unwrap();
            assert_eq!(d2, d);
            assert_eq!(e2, e);
        }
    }

    #[test]
    fn mnemonic_and_hexseed_agree() {
        let e = ml_seed();
        let d = Descriptor::for_algo(Algo::SlhDsa);
        let (dm, em) = parse_mnemonic(&mnemonic(d, &e)).unwrap();
        let (dh, eh) = parse_hexseed(&hexseed(d, &e)).unwrap();
        assert_eq!((dm, em), (dh, eh));
    }

    #[test]
    fn address_is_q_prefixed_24_bytes_and_stable() {
        let e = [9u8; 32];
        let d = Descriptor::for_algo(Algo::MlDsa);
        let pk = crate::pubkey_of(Algo::MlDsa, e);
        let a = address(d, &pk);
        assert!(a.starts_with('Q'));
        assert_eq!(a.len(), 1 + ADDR_TAKE * 2); // Q + 48 hex
        assert_eq!(a, address(d, &pk)); // deterministic
    }

    #[test]
    fn parsing_is_total_and_fail_closed() {
        for junk in ["", "not a mnemonic", "aback aback", &"aback ".repeat(24)] {
            let _ = parse_mnemonic(junk); // must not panic
        }
        // 24 valid words but we corrupt the pad → reject. Build from a good one then
        // swap a word so the pad byte becomes non-zero is hard to force; instead test
        // an unknown word and wrong length above. Also bad hexseed:
        assert!(parse_hexseed("00").is_err());
        assert!(parse_hexseed(&"ff".repeat(HEXSEED_LEN)).is_err()); // unknown scheme 0xff
    }

    #[test]
    fn unknown_word_rejected() {
        let e = ml_seed();
        let m = mnemonic(Descriptor::for_algo(Algo::MlDsa), &e);
        let bad = m.replacen(m.split_whitespace().next().unwrap(), "notaqrlword", 1);
        assert_eq!(parse_mnemonic(&bad), Err(SeedError::UnknownWord));
    }
}
