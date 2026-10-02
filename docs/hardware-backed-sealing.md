# Hardware-backed at-rest sealing

How talkrypt protects a long-term secret (the ML-DSA-87 **identity seed**) at
rest with a device's secure element, on every platform, through one shared
format. This is recommendation **R-8** of [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md)
(see §3b) and finding **F-15**.

> For the full menu of custody backends (external HSM/PKCS#11, SEALSQ PQ chip,
> macOS Secure-Enclave reach options, the permissive-security hardening plan) and
> their trust/PQ/attribution trade-offs, see [`custody-options.md`](custody-options.md).

## What it does — and the honest limit

A secure element wraps a random **KEK** with a non-exportable, user-presence-
gated key; that KEK (optionally combined with a passphrase) encrypts the stored
seed. An attacker who copies the sealed file off the device cannot decrypt it —
not off-device, not without the device's secure element and whatever
biometric/PIN gate the OS enforces.

It protects the key **at rest, not in use.** Today's secure elements
(StrongBox, the Solana Seeker's SE, Secure Enclave, TPM) are *classical-only* and
**cannot hold or sign with** the post-quantum ML-DSA-87 key, so the seed is still
unwrapped into `mlock`'d RAM to sign. This does not defend a live-RAM attacker on
a compromised device (see SECURITY-AUDIT §3b). Hardware-backed *signing* is
blocked on PQC-capable silicon, not on talkrypt.

## One seam, every platform

The sealed-envelope codec and the wrap/unwrap trait live **once** in
`talkrypt-core` (`crates/core/src/seal.rs`):

- `KeyWrapper` — `wrap(kek) -> wrapped` / `unwrap(wrapped) -> kek`. The core
  never sees the secure element's key.
- `seal(plaintext, SealOptions { passphrase, wrapper }) -> blob` and
  `unseal(blob, passphrase, wrapper) -> plaintext`.
- `tier_of(blob) -> CustodyTier` to show "hardware-backed" vs "software-sealed".

Each host plugs its platform backend into that one seam:

| Host | Backend | Entry point | QROM-safe wrap? |
| --- | --- | --- | --- |
| Android | Keystore / **StrongBox** | FFI `HardwareKeyWrapper` callback | no (classical) → passphrase |
| iOS | **Secure Enclave** | FFI `HardwareKeyWrapper` callback | no (classical) → passphrase |
| Desktop (Linux) | **TPM 2.0** | helper `HardwareBacked` tier → same core codec | no (classical) → passphrase |
| Desktop (macOS) | **Secure Enclave** (ECIES) or **Keychain-AES** | helper `macos_hw` (`macos-se` feature) | SE no / Keychain-AES **yes** |
| Desktop (Win) | **TPM via CNG** (NCrypt RSA-OAEP) | helper `windows_cng` (`windows-tpm` feature) | no (classical) → passphrase |
| Any | **SEALSQ / WISeKey QS7001** (PQ secure element) | helper `pqse::PqSeWrapper` (`sealsq` feature) | **yes** (ML-KEM-1024) |
| Any | Custom HSM / PKCS#11 / YubiKey / smartcard | `KeyStore::with_wrapper(dir, Arc<dyn KeyWrapper>)` | per wrapper's `qrom_safe()` |

### QROM / L5 rule (PQ-at-rest inside a non-PQ HSM)

A classical secure element wraps the KEK with RSA/ECC, so the **wrapped-KEK stored
at rest is quantum-recoverable**. The core therefore **refuses a hardware-only
seal** for a wrapper that does not attest `KeyWrapper::qrom_safe()` unless the
caller sets `allow_weak_hardware_only`; the intended path is to add a passphrase,
whose Argon2id-256 key is mixed into the KEK so the AES-256-GCM contents stay
post-quantum-safe even if the classical wrap is later broken. That is how
**"PQ security inside a non-PQ HSM"** is achieved. A wrapper that *does* attest
`qrom_safe()` — a symmetric ≥256-bit wrap (Keychain-AES), or an **ML-KEM** wrap
(SEALSQ) — unlocks a passphrase-less hardware-only L5 seal. The helper's
`hw_seal` honors this automatically: `allow_weak_hardware_only` is set only when
`!wrapper.qrom_safe()`.

## KEK model (unified)

```text
seal:   KEK_rand  <- CSPRNG (32 bytes)          [hardware only]
        wrapped   <- wrapper.wrap(KEK_rand)      [hardware only, host/SE]
        pw_key    <- Argon2id(passphrase, salt)  [passphrase only]
        K_final   <- KMAC256/HKDF(flags ‖ [KEK_rand] ‖ [pw_key])
        ct        <- AES-256-GCM(K_final, nonce, seed; AAD = header)
```

At least one factor is required. With **both** a passphrase and a wrapper it is
two-factor (device **and** passphrase); with only one it degrades to that factor.
The `flags` byte and the full header are bound as AEAD AAD, so stripping a factor
or tampering with any field fails the open.

### Wire format (`TKS1`)

```text
magic[4]="TKS1" ‖ version(u8)=1 ‖ tier(u8) ‖ flags(u8)
  ‖ salt(len-prefixed,16)     if flags.PASSPHRASE (0b01)
  ‖ wrapped_kek(len-prefixed) if flags.HARDWARE   (0b10)
  ‖ nonce(len-prefixed,12)
  ‖ ciphertext(len-prefixed)   = AES-256-GCM(seed)‖tag
```

## Mobile FFI

Seal/reload the account seed without it ever leaving Rust as plaintext:

```text
// uniffi-generated surface (Kotlin/Swift names mirror these)
interface HardwareKeyWrapper { wrap(kek): ByteArray; unwrap(wrapped): ByteArray }
class Account {
    fun seal(passphrase: String?, wrapper: HardwareKeyWrapper?): ByteArray
    companion object {
        fun fromSealed(blob: ByteArray, passphrase: String?, wrapper: HardwareKeyWrapper?): Account
    }
}
fun sealedTier(blob: ByteArray): CustodyTier   // SOFTWARE_SEALED | OS_KEYSTORE | HARDWARE_BACKED
fun sealSecret(secret: ByteArray, passphrase: String?, wrapper: HardwareKeyWrapper?): ByteArray
fun unsealSecret(blob: ByteArray, passphrase: String?, wrapper: HardwareKeyWrapper?): ByteArray
```

### Android — StrongBox (Kotlin sketch)

A non-exportable AES-GCM key in the AES keystore, hardware-backed via StrongBox
when available, gated on user authentication. `wrap`/`unwrap` are `Cipher`
encrypt/decrypt; prepend the GCM IV to the blob.

```kotlin
class StrongBoxWrapper(private val ctx: Context) : HardwareKeyWrapper {
    private val alias = "talkrypt.seed.kek"
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setIsStrongBoxBacked(true)            // hardware secure element
            .setUserAuthenticationRequired(true)   // biometric / device credential
            .build())
        return kg.generateKey()
    }
    override fun wrap(kek: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        return c.iv + c.doFinal(kek)               // iv(12) ‖ ct‖tag
    }
    override fun unwrap(wrapped: ByteArray): ByteArray {
        val iv = wrapped.copyOfRange(0, 12); val ct = wrapped.copyOfRange(12, wrapped.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
            .apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)) }
        return c.doFinal(ct)
    }
}
// Seal once, persist the blob; reload on launch.
val blob = account.seal(passphrase = null, wrapper = StrongBoxWrapper(ctx))
val reloaded = Account.fromSealed(blob, passphrase = null, wrapper = StrongBoxWrapper(ctx))
```

Fall back to `setIsStrongBoxBacked(false)` (TEE) on devices without StrongBox;
report the achieved tier with `custodyReport(...)`.

### iOS — Secure Enclave (Swift sketch)

The Secure Enclave holds a non-exportable P-256 key; derive a symmetric wrapping
key via ECDH against an ephemeral public key stored alongside the blob (or use
`SecKeyCreateEncryptedData` with an EC key). Gate with `.userPresence` /
`LAContext`. `wrap`/`unwrap` mirror the Android shape.

## Desktop helper

The helper's `HardwareBacked` tier (`crates/helper/src/store.rs`) routes through
the **same** `talkrypt_core::seal`/`unseal`, wrapping the KEK with a TPM 2.0 on
Linux (`--features tpm`; the `crate::tpm` seal/unseal of the 32-byte KEK,
validated against swtpm in [`linux-tpm-test.sh`](linux-tpm-test.sh)). A build
with no secure-element backend rejects the tier with a clear "rebuild with
--features tpm" error rather than silently downgrading.

### PQ secure element — SEALSQ / WISeKey (`sealsq` feature)

Unlike every classical secure element, a **post-quantum secure element** (SEALSQ
QS7001, VaultIC, or any chip that decapsulates **ML-KEM-1024** on-die) makes the
*hardware wrap itself* post-quantum: the KEK is encapsulated to the chip's ML-KEM
public key, so the wrapped-KEK at rest is not quantum-recoverable. `pqse::PqSeWrapper`
attests `qrom_safe() = true`, so it enables a **hardware-only, passphrase-less
L5/QROM** seal — the one hardware path that is PQ at rest end to end, overcoming
the "PQC not in secure elements" limit for the chips that actually do PQC. The
crypto is the audited `talkrypt-crypto` ML-KEM-1024; a concrete chip driver
implements the two-call `PqSecureElement` transport seam (`encapsulation_key` +
`decapsulate`) and is injected via `KeyStore::with_wrapper`. `MockPqSecureElement`
(an in-software ML-KEM key) makes the wrap/unwrap path fully testable without
silicon. It still does not custody the ML-DSA-87 *signing* key — no shipping
secure element signs ML-DSA — so this is at-rest KEK custody, not in-use signing.

### macOS — Secure Enclave and Keychain-AES (`macos-se` feature)

`crates/helper/src/macos_hw.rs` offers two macOS backends, plugged via
`KeyStore::with_wrapper`:

- **`KeychainAesWrapper` (tested here).** A random AES-256 wrapping key custodied
  in the login Keychain; the KEK is wrapped with AES-256-GCM. Symmetric ≥256-bit
  ⇒ `qrom_safe() = true` (passphrase-optional QROM seal). The wrapping key is
  *OS-keystore-grade* — readable by this process, protected by the Keychain (whose
  own class keys are SE-protected on Apple-silicon Macs) — **not** a Secure-Enclave
  non-exportable key. Needs no entitlement.
- **`SecureEnclaveWrapper` (compile-checked; provisioning-gated to run).** A
  non-exportable P-256 key minted in the Secure Enclave; the KEK is wrapped with
  ECIES (`SecKeyCreate{Encrypted,Decrypted}Data`). Classical ⇒ `qrom_safe() = false`,
  so the seam requires a passphrase (PQ-at-rest as above).

**Running the Secure Enclave path is gated by Apple provisioning, empirically
confirmed on an Apple M5:**

- Minting an SE key (even a non-permanent one) registers a data-protection-keychain
  reference, which requires the **restricted** `keychain-access-groups` entitlement.
- Signed **without** the entitlement (ad-hoc, or a self-signed ECDSA P-384/SHA-384
  identity): `SecKeyCreateRandomKey` returns `OSStatus -34018 errSecMissingEntitlement`
  — but note the **Enclave is actually reached** (a live `<SecKeyRef:('com.apple.setoken')>`
  is produced; the key is created, only its keychain registration fails).
- Signed **with** the entitlement on a self-signed identity: `amfid` **SIGKILLs**
  the process on launch, because a restricted entitlement is honored only when
  authorized by an **Apple-issued provisioning profile** (a paid Developer ID, or
  a free personal-team profile from Xcode signed into an Apple ID).

There is **no PQ option at the platform layer**: `codesign`/`amfid` verify only
RSA/ECDSA code-signing certs — not XMSS/LMS (RFC 8391 / SP 800-208) or ML-DSA — so
a PQ-signed code-signing cert cannot be verified by macOS regardless of hardware
hash acceleration. talkrypt does PQ signing for *its own* release artifacts
(`crates/relsign`, ML-DSA); the OS code-signing layer is a separate, classical,
Apple-controlled trust anchor. To run the SE test for real, build + sign with a
provisioned Apple Development identity and `crates/helper/macos-se.entitlements`:

```sh
cargo test -p talkrypt-helper --features macos-se --no-run   # note the lib test binary path
codesign --force --sign "Apple Development: <you>" \
  --entitlements crates/helper/macos-se.entitlements <lib-test-binary>
<lib-test-binary> --ignored secure_enclave_hardware_ecies_roundtrip --nocapture
```

The SE test is `#[ignore]` so a plain `cargo test` reports it **ignored** (never a
skip masquerading as a pass); under `--ignored` it exercises real hardware and
fails loudly (with the `CFError`) if the Enclave is unreachable. `KeyStore` never
auto-selects the SE wrapper, so an unprovisioned build falls back cleanly to
`KeychainAesWrapper` / software sealing rather than erroring.

## Tests

- `crates/core/src/seal.rs` — envelope round-trips (software / hardware /
  hybrid), wrong-device, wrong-passphrase, tamper, factor-stripping, no-plaintext
  leak, format/version checks (9 tests).
- `crates/ffi/src/lib.rs` — `Account::seal`/`from_sealed` and the free functions
  over a Rust mock of the `HardwareKeyWrapper` callback, incl. two-factor and
  wrong-device (3 tests).
- `crates/helper/src/store.rs` — the `HardwareBacked` tier produces and reloads
  the shared envelope via a mock secure element, errors cleanly with no backend,
  and (with `--features sealsq`) round-trips a seed through an injected PQ chip at
  the hardware-only QROM tier.
- `crates/helper/src/pqse.rs` (`sealsq`) — PQ secure-element wrap/unwrap:
  round-trip, a different chip cannot unwrap (ML-KEM implicit reject), tamper,
  bad header, encapsulation-key length guard, and a hardware-only QROM seal
  through the core (8 tests).
- `crates/helper/src/macos_hw.rs` (`macos-se`) — `KeychainAesWrapper` round-trip
  + tamper + hardware-only QROM seal (2 tests, run here); the real
  `SecureEnclaveWrapper` ECIES round-trip is `#[ignore]` (runs only on a
  provisioned signed build — see the macOS section above).

## On-device verification (Android emulator)

Verified end to end on the Android emulator, whose `AndroidKeyStore` stands in for
a real StrongBox/TEE secure element (software-backed keystore; the `KeystoreWrapper`
code path is identical). A persistent chat's store was inspected on disk and across
a restart:

- **Custody tier is the OS keystore.** The app header shows `🔒 OS_KEYSTORE`,
  i.e. `ChatStore` wrapped the seal KEK with a non-exportable `AndroidKeyStore` AES
  key (`KeystoreWrapper`), not a passphrase-only tier.
- **The persisted blob is genuine ciphertext.** `files/chats/<id>.tkc` begins with
  the `TKS1` sealed-envelope magic followed by high-entropy AES-256-GCM ciphertext;
  `strings` over the file finds **only** the `TKS1` magic — no channel names, no
  message text, no metadata in the clear.
- **It unseals across a restart.** After force-stopping and relaunching, the sealed
  chat reloads into the chat list (title/metadata restored) with no unseal error —
  proving the keystore-wrapped KEK persists and the decrypt path works on-device.

The one gap versus a real device is StrongBox hardware custody of the wrapping key
(the emulator's keystore is software-backed); the seal/unseal logic, envelope
format, and no-plaintext-at-rest guarantee are the same.
