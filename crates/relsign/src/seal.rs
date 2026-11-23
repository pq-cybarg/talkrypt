//! Passphrase-sealed signing seeds (`.seed.enc`) — Argon2id + AES-256-GCM.
//!
//! The release signing seed is a long-lived offline root secret, so it never sits
//! in plaintext: it is sealed under a passphrase with the SAME construction as the
//! app's at-rest `TKS1` seal (`core/src/seal.rs`) — Argon2id(passphrase, salt) →
//! 32-byte key, AES-256-GCM(seed) with the full header bound as AEAD AAD — only at
//! a stronger Argon2id work factor befitting an offline root key.
//!
//! The format is a small UTF-8 text blob (greppable, diff-able) whose header
//! carries the KDF params, salt, nonce, signing algo, and the **public** key in the
//! clear — so deriving/publishing the pubkey needs NO passphrase, while the seed
//! itself is recoverable only with the passphrase.
//!
//! The parser is TOTAL: arbitrary bytes yield a typed `Err`, never a panic and
//! never a partial/wrong seed (see `docs/plans/0004-keyvault.md`, FV obligation 2).
//! The derived key and recovered seed are zeroized on every path.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{hex, Algo};

const MAGIC: &str = "talkrypt-relsign-sealed-seed v1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 32;

/// The passphrase KDF a sealed seed uses. Stored (with params) in the header so a
/// blob is **self-describing and portable**: whatever platform sealed it, any
/// platform can unseal it provided it can run that KDF+params. Two families:
///
/// - **Argon2id** (RFC 9106): memory-hard, strongest against offline cracking.
///   Default on desktop. NOT FIPS-approved.
/// - **PBKDF2-HMAC-SHA384** (NIST SP 800-132): the FIPS-approved PBKDF, and the
///   memory-light choice for iOS / embedded where a large Argon2id arena can OOM.
///
/// Platform/policy selection (allow/disallow/default a KDF per build) lives in the
/// caller; this seam just executes + records whatever KDF it is handed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kdf {
    /// Argon2id with m (KiB), t (passes), p (lanes).
    Argon2id { m: u32, t: u32, p: u32 },
    /// PBKDF2-HMAC-SHA384 with an iteration count.
    Pbkdf2 { iter: u32 },
}

impl Kdf {
    /// Desktop default: Argon2id 256 MiB / 3 passes — strong, for an offline root key.
    pub const fn desktop() -> Kdf {
        Kdf::Argon2id { m: 262_144, t: 3, p: 1 }
    }
    /// Mobile default: Argon2id 64 MiB / 3 passes — strong but within an iOS app's
    /// memory budget (256 MiB risks the OS terminating the app).
    pub const fn mobile() -> Kdf {
        Kdf::Argon2id { m: 65_536, t: 3, p: 1 }
    }
    /// Embedded default: Argon2id 16 MiB / 2 passes — fits tight RAM.
    pub const fn embedded() -> Kdf {
        Kdf::Argon2id { m: 16_384, t: 2, p: 1 }
    }
    /// FIPS / standards default: PBKDF2-HMAC-SHA384 (SP 800-132), 600k iterations.
    pub const fn fips() -> Kdf {
        Kdf::Pbkdf2 { iter: 600_000 }
    }
}

/// A non-leaky sealing error (messages never include secret material).
#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    NotSealed,
    Malformed(&'static str),
    BadPassphraseOrTampered,
    Argon2,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SealError::NotSealed => "not a talkrypt sealed seed",
            SealError::Malformed(w) => return write!(f, "malformed sealed seed: {w}"),
            SealError::BadPassphraseOrTampered => {
                "wrong passphrase, or the sealed seed was tampered"
            }
            SealError::Argon2 => "key derivation (argon2id) failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for SealError {}

fn derive_key(pw: &[u8], salt: &[u8], kdf: Kdf) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let mut key = Zeroizing::new([0u8; 32]);
    match kdf {
        Kdf::Argon2id { m, t, p } => {
            let params = Params::new(m, t, p, Some(32)).map_err(|_| SealError::Argon2)?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(pw, salt, key.as_mut())
                .map_err(|_| SealError::Argon2)?;
        }
        Kdf::Pbkdf2 { iter } => {
            if iter == 0 {
                return Err(SealError::Argon2); // reuse the "KDF failed" variant
            }
            // PBKDF2-HMAC-SHA384 (NIST SP 800-132): the FIPS-approved PBKDF.
            pbkdf2::pbkdf2_hmac::<sha2::Sha384>(pw, salt, iter, key.as_mut());
        }
    }
    Ok(key)
}

/// Serialize a KDF to its header line value (the part after `kdf: `). Parsed back by
/// [`parse_kdf`]; the two MUST round-trip so the AAD matches on unseal.
fn kdf_line(kdf: Kdf) -> String {
    match kdf {
        Kdf::Argon2id { m, t, p } => format!("argon2id m={m} t={t} p={p}"),
        Kdf::Pbkdf2 { iter } => format!("pbkdf2-hmac-sha384 iter={iter}"),
    }
}

/// The canonical header text (everything before the `ct:` line). Produced both when
/// writing the blob and when rebuilding the AEAD AAD on unseal — the two MUST be
/// byte-identical, so one function serves both.
fn canonical_header(algo: Algo, kdf: Kdf, salt: &[u8], nonce: &[u8], pubkey: &[u8]) -> String {
    format!(
        "{MAGIC}\nalg: {}\nkdf: {}\nsalt: {}\nnonce: {}\npub: {}\n",
        algo.tag(),
        kdf_line(kdf),
        hex::encode(salt),
        hex::encode(nonce),
        hex::encode(pubkey),
    )
}

/// Is this text a talkrypt sealed seed? (Cheap check of the magic first line.)
pub fn is_sealed(data: &str) -> bool {
    data.trim_start().starts_with(MAGIC)
}

/// Seal a 32-byte `seed` for `algo` under `passphrase` with the desktop default KDF
/// (Argon2id 256 MiB). `pubkey` is stored in the clear header.
pub fn seal(passphrase: &[u8], algo: Algo, seed: &[u8; 32], pubkey: &[u8]) -> Result<String, SealError> {
    seal_with_kdf(passphrase, algo, seed, pubkey, Kdf::desktop())
}

/// As [`seal`] but with an explicit [`Kdf`] (platform preset or custom params). The
/// KDF + params are recorded in the header, so [`unseal`] uses exactly these — the
/// blob is portable to any platform that can run that KDF.
pub fn seal_with_kdf(
    passphrase: &[u8],
    algo: Algo,
    seed: &[u8; 32],
    pubkey: &[u8],
    kdf: Kdf,
) -> Result<String, SealError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt, kdf)?;
    let header = canonical_header(algo, kdf, &salt, &nonce, pubkey);
    // AAD = the exact header bytes, so no header field can be altered or stripped.
    let ct = talkrypt_crypto::aead::seal(&key, &nonce, seed, header.as_bytes())
        .map_err(|_| SealError::Argon2)?; // aead::seal only fails on a bad key length
    Ok(format!("{header}ct: {}\n", hex::encode(&ct)))
}

/// Read the public key from a sealed blob WITHOUT the passphrase (it is stored in
/// the clear header). Also returns the algo. Fails closed on any malformation.
pub fn read_public(blob: &str) -> Result<(Algo, Vec<u8>), SealError> {
    let f = Fields::parse(blob)?;
    Ok((f.algo, f.pubkey))
}

/// Recover the 32-byte seed from a sealed blob with the `passphrase`. A wrong
/// passphrase or any tampering yields `BadPassphraseOrTampered` (the AEAD open
/// fails) — never a partial or wrong seed. The derived key and all scratch are
/// zeroized; the returned seed is in a zeroizing wrapper the caller must guard.
pub fn unseal(passphrase: &[u8], blob: &str) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let f = Fields::parse(blob)?;
    let key = derive_key(passphrase, &f.salt, f.kdf)?;
    let header = canonical_header(f.algo, f.kdf, &f.salt, &f.nonce, &f.pubkey);
    let pt = talkrypt_crypto::aead::open(&key, &f.nonce, &f.ct, header.as_bytes())
        .map_err(|_| SealError::BadPassphraseOrTampered)?;
    if pt.len() != SEED_LEN {
        // A correctly-authenticated blob always holds 32 bytes; any other length
        // means a malformed (but somehow authenticating) blob — refuse it.
        let mut pt = pt;
        use zeroize::Zeroize;
        pt.zeroize();
        return Err(SealError::Malformed("sealed seed is not 32 bytes"));
    }
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&pt);
    // zeroize the heap plaintext copy too.
    {
        use zeroize::Zeroize;
        let mut pt = pt;
        pt.zeroize();
    }
    Ok(seed)
}

/// Parsed header + ciphertext. Parsing is total and allocation-bounded.
struct Fields {
    algo: Algo,
    kdf: Kdf,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    pubkey: Vec<u8>,
    ct: Vec<u8>,
}

impl Fields {
    fn parse(blob: &str) -> Result<Fields, SealError> {
        if !is_sealed(blob) {
            return Err(SealError::NotSealed);
        }
        let mut algo = None;
        let mut kdf = None;
        let mut salt = None;
        let mut nonce = None;
        let mut pubkey = None;
        let mut ct = None;

        for line in blob.lines() {
            let line = line.trim();
            if line.is_empty() || line == MAGIC || line.starts_with('#') {
                continue;
            }
            let (k, v) = line.split_once(':').ok_or(SealError::Malformed("missing ':'"))?;
            let v = v.trim();
            match k.trim() {
                "alg" => algo = Some(Algo::parse(v).ok_or(SealError::Malformed("bad alg"))?),
                "kdf" => kdf = Some(parse_kdf(v)?),
                "salt" => {
                    let b = hex::decode(v).map_err(|_| SealError::Malformed("bad salt hex"))?;
                    salt = Some(to_arr::<SALT_LEN>(&b, "salt")?);
                }
                "nonce" => {
                    let b = hex::decode(v).map_err(|_| SealError::Malformed("bad nonce hex"))?;
                    nonce = Some(to_arr::<NONCE_LEN>(&b, "nonce")?);
                }
                "pub" => {
                    pubkey = Some(hex::decode(v).map_err(|_| SealError::Malformed("bad pub hex"))?)
                }
                "ct" => ct = Some(hex::decode(v).map_err(|_| SealError::Malformed("bad ct hex"))?),
                _ => return Err(SealError::Malformed("unknown field")),
            }
        }
        Ok(Fields {
            algo: algo.ok_or(SealError::Malformed("missing alg"))?,
            kdf: kdf.ok_or(SealError::Malformed("missing kdf"))?,
            salt: salt.ok_or(SealError::Malformed("missing salt"))?,
            nonce: nonce.ok_or(SealError::Malformed("missing nonce"))?,
            pubkey: pubkey.ok_or(SealError::Malformed("missing pub"))?,
            ct: ct.ok_or(SealError::Malformed("missing ct"))?,
        })
    }
}

fn parse_kdf(v: &str) -> Result<Kdf, SealError> {
    // "argon2id m=<u32> t=<u32> p=<u32>"  |  "pbkdf2-hmac-sha384 iter=<u32>"
    let mut parts = v.split_whitespace();
    let kind = parts.next().ok_or(SealError::Malformed("empty kdf"))?;
    let num = |val: &str| val.parse::<u32>().map_err(|_| SealError::Malformed("bad kdf number"));
    match kind {
        "argon2id" => {
            let (mut m, mut t, mut p) = (None, None, None);
            for kv in parts {
                let (k, val) = kv.split_once('=').ok_or(SealError::Malformed("bad kdf param"))?;
                let n = num(val)?;
                match k {
                    "m" => m = Some(n),
                    "t" => t = Some(n),
                    "p" => p = Some(n),
                    _ => return Err(SealError::Malformed("unknown argon2 param")),
                }
            }
            Ok(Kdf::Argon2id {
                m: m.ok_or(SealError::Malformed("missing kdf m"))?,
                t: t.ok_or(SealError::Malformed("missing kdf t"))?,
                p: p.ok_or(SealError::Malformed("missing kdf p"))?,
            })
        }
        "pbkdf2-hmac-sha384" => {
            let mut iter = None;
            for kv in parts {
                let (k, val) = kv.split_once('=').ok_or(SealError::Malformed("bad kdf param"))?;
                match k {
                    "iter" => iter = Some(num(val)?),
                    _ => return Err(SealError::Malformed("unknown pbkdf2 param")),
                }
            }
            Ok(Kdf::Pbkdf2 { iter: iter.ok_or(SealError::Malformed("missing kdf iter"))? })
        }
        _ => Err(SealError::Malformed("unsupported kdf")),
    }
}

fn to_arr<const N: usize>(b: &[u8], what: &'static str) -> Result<[u8; N], SealError> {
    if b.len() != N {
        return Err(SealError::Malformed(what));
    }
    let mut a = [0u8; N];
    a.copy_from_slice(b);
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use talkrypt_crypto::IdentityKeyPair;

    fn fresh_ml_seed() -> [u8; 32] {
        IdentityKeyPair::generate().export_secret()
    }

    /// A cheap KDF for the bulk of the suite (PBKDF2 at 1k iters is instant even in
    /// debug, where Argon2id at any real memory cost is not). Exercises the full
    /// seal/unseal/AEAD path; the Argon2id path is covered explicitly by the matrix
    /// test below with minimum params.
    const FAST: Kdf = Kdf::Pbkdf2 { iter: 1000 };
    fn cseal(pw: &[u8], algo: Algo, seed: &[u8; 32], pk: &[u8]) -> String {
        super::seal_with_kdf(pw, algo, seed, pk, FAST).unwrap()
    }

    #[test]
    fn seal_unseal_roundtrips() {
        let seed = fresh_ml_seed();
        let pk = crate::pubkey_of(Algo::MlDsa, seed);
        let blob = cseal(b"correct horse battery staple", Algo::MlDsa, &seed, &pk);
        assert!(is_sealed(&blob));
        let out = unseal(b"correct horse battery staple", &blob).unwrap();
        assert_eq!(*out, seed);
    }

    #[test]
    fn pubkey_and_algo_readable_without_passphrase() {
        let seed = [9u8; 32];
        let pk = crate::pubkey_of(Algo::SlhDsa, seed);
        let blob = cseal(b"pw", Algo::SlhDsa, &seed, &pk);
        let (algo, got_pk) = read_public(&blob).unwrap();
        assert_eq!(algo, Algo::SlhDsa);
        assert_eq!(got_pk, pk);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let seed = fresh_ml_seed();
        let pk = crate::pubkey_of(Algo::MlDsa, seed);
        let blob = cseal(b"right", Algo::MlDsa, &seed, &pk);
        assert_eq!(unseal(b"WRONG", &blob), Err(SealError::BadPassphraseOrTampered));
    }

    #[test]
    fn tampered_header_or_ct_fails_closed() {
        let seed = fresh_ml_seed();
        let pk = crate::pubkey_of(Algo::MlDsa, seed);
        let blob = cseal(b"pw", Algo::MlDsa, &seed, &pk);

        // Flip a hex nibble in the ciphertext line.
        let mut t = blob.replace("ct: ", "ct: 0");
        // (prepending a hex digit shifts/bloats ct → bad length or bad tag)
        assert!(unseal(b"pw", &t).is_err());

        // Tamper the salt: AAD no longer matches → open fails.
        t = blob.clone();
        let salt_line = blob.lines().find(|l| l.starts_with("salt: ")).unwrap();
        let bad = format!("salt: {}", "00".repeat(SALT_LEN));
        t = t.replace(salt_line, &bad);
        assert!(unseal(b"pw", &t).is_err());
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_fail_closed() {
        for junk in [
            "",
            "garbage",
            MAGIC, // magic only, no fields
            &format!("{MAGIC}\nalg: ml-dsa\n"),
            &format!("{MAGIC}\nalg: bogus\nkdf: argon2id m=1 t=1 p=1\nsalt: 00\nnonce: 00\npub: 00\nct: 00\n"),
            &format!("{MAGIC}\nkdf: md5\n"),
            &format!("{MAGIC}\nsalt: zz\n"),
        ] {
            let r = unseal(b"pw", junk);
            assert!(r.is_err(), "junk must fail: {junk:?}");
            let _ = read_public(junk); // must not panic either
        }
    }

    #[test]
    fn no_plaintext_seed_in_blob() {
        let seed = [0x5au8; 32];
        let pk = crate::pubkey_of(Algo::MlDsa, seed);
        let blob = cseal(b"pw", Algo::MlDsa, &seed, &pk);
        assert!(
            !blob.as_bytes().windows(seed.len()).any(|w| w == seed),
            "raw seed must not appear in the sealed blob"
        );
    }

    #[test]
    fn distinct_seals_differ_fresh_salt_and_nonce() {
        let seed = [1u8; 32];
        let pk = crate::pubkey_of(Algo::MlDsa, seed);
        let a = cseal(b"pw", Algo::MlDsa, &seed, &pk);
        let b = cseal(b"pw", Algo::MlDsa, &seed, &pk);
        assert_ne!(a, b);
    }

    #[test]
    fn sealed_seed_then_sign_verifies() {
        // End-to-end: seal a seed, unseal it, sign, and verify under the stored pub.
        let seed = fresh_ml_seed();
        let pk = crate::pubkey_of(Algo::MlDsa, seed);
        let blob = cseal(b"pw", Algo::MlDsa, &seed, &pk);
        let (algo, pub_from_blob) = read_public(&blob).unwrap();
        let recovered = unseal(b"pw", &blob).unwrap();
        let sig = crate::sign(algo, *recovered, b"manifest bytes");
        assert!(crate::verify(algo, &pub_from_blob, b"manifest bytes", &sig));
    }

    #[test]
    fn preset_constructors_select_the_expected_kdf() {
        assert_eq!(Kdf::desktop(), Kdf::Argon2id { m: 262_144, t: 3, p: 1 });
        assert_eq!(Kdf::mobile(), Kdf::Argon2id { m: 65_536, t: 3, p: 1 });
        assert_eq!(Kdf::embedded(), Kdf::Argon2id { m: 16_384, t: 2, p: 1 });
        assert_eq!(Kdf::fips(), Kdf::Pbkdf2 { iter: 600_000 });
    }

    #[test]
    fn kdf_line_header_tokens_are_what_the_parser_expects() {
        // The header must self-describe the KDF so a blob is portable across
        // platforms. Argon2id (desktop/mobile/embedded) and PBKDF2 (fips).
        let seed = [3u8; 32];
        let pk = crate::pubkey_of(Algo::MlDsa, seed);
        let a = super::seal_with_kdf(b"pw", Algo::MlDsa, &seed, &pk, Kdf::Argon2id { m: 16, t: 1, p: 1 }).unwrap();
        assert!(a.contains("kdf: argon2id m=16 t=1 p=1"), "{a}");
        let b = super::seal_with_kdf(b"pw", Algo::MlDsa, &seed, &pk, Kdf::Pbkdf2 { iter: 1000 }).unwrap();
        assert!(b.contains("kdf: pbkdf2-hmac-sha384 iter=1000"), "{b}");
    }

    /// The matrix the operator asked for: EVERY KDF family × EVERY signing scheme,
    /// seal→read_public(no pw)→unseal→sign→verify, plus fail-closed on wrong pw. A
    /// blob sealed with one KDF unseals purely from its self-describing header, so
    /// the "current default" never matters — this is what makes a mobile-sealed blob
    /// readable on desktop and vice-versa. Argon2id uses MINIMUM params here (the
    /// real presets' memory cost is validated by `preset_constructors_*`, not run).
    #[test]
    fn full_kdf_x_algo_matrix_roundtrips_and_fails_closed() {
        let kdfs = [
            Kdf::Argon2id { m: 8, t: 1, p: 1 }, // argon2id path (min params = fast)
            Kdf::Pbkdf2 { iter: 1000 },         // pbkdf2 path
        ];
        let algos = [Algo::MlDsa, Algo::SlhDsa];
        for kdf in kdfs {
            for algo in algos {
                let seed = if algo == Algo::MlDsa { fresh_ml_seed() } else { [0x11u8; 32] };
                let pk = crate::pubkey_of(algo, seed);
                let blob = super::seal_with_kdf(b"pw-correct", algo, &seed, &pk, kdf).unwrap();

                // pubkey + algo readable with NO passphrase.
                let (ra, rpk) = read_public(&blob).unwrap();
                assert_eq!(ra, algo, "algo survives {kdf:?}");
                assert_eq!(rpk, pk, "pub survives {kdf:?}");

                // correct passphrase recovers the seed and a signature verifies.
                let recovered = unseal(b"pw-correct", &blob).unwrap();
                assert_eq!(*recovered, seed, "roundtrip {algo:?}/{kdf:?}");
                let sig = crate::sign(algo, *recovered, b"SHA384SUMS bytes");
                assert!(crate::verify(algo, &rpk, b"SHA384SUMS bytes", &sig));

                // wrong passphrase fails closed under EITHER KDF.
                assert_eq!(
                    unseal(b"pw-WRONG", &blob),
                    Err(SealError::BadPassphraseOrTampered),
                    "wrong pw must fail for {algo:?}/{kdf:?}"
                );

                // a one-byte flip in the ciphertext fails closed.
                let last_ct = blob.rfind("ct: ").unwrap() + 4;
                let mut t: Vec<char> = blob.chars().collect();
                let flip = if t[last_ct] == '0' { 'f' } else { '0' };
                t[last_ct] = flip;
                let tampered: String = t.into_iter().collect();
                assert!(unseal(b"pw-correct", &tampered).is_err(), "tamper {algo:?}/{kdf:?}");
            }
        }
    }
}
