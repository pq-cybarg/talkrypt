# Hardware-backed at-rest sealing

How talkrypt protects a long-term secret (the ML-DSA-87 **identity seed**) at
rest with a device's secure element, on every platform, through one shared
format. This is recommendation **R-8** of [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md)
(see §3b) and finding **F-15**.

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

| Host | Backend | Entry point |
| --- | --- | --- |
| Android | Keystore / **StrongBox** | FFI `HardwareKeyWrapper` callback |
| iOS | **Secure Enclave** | FFI `HardwareKeyWrapper` callback |
| Desktop (Linux) | **TPM 2.0** | helper `HardwareBacked` tier → same core codec |
| Desktop (macOS/Win) | OS keystore (no SE PQ) | software-sealed, or host-provided wrapper |

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

## Tests

- `crates/core/src/seal.rs` — envelope round-trips (software / hardware /
  hybrid), wrong-device, wrong-passphrase, tamper, factor-stripping, no-plaintext
  leak, format/version checks (9 tests).
- `crates/ffi/src/lib.rs` — `Account::seal`/`from_sealed` and the free functions
  over a Rust mock of the `HardwareKeyWrapper` callback, incl. two-factor and
  wrong-device (3 tests).
- `crates/helper/src/store.rs` — the `HardwareBacked` tier produces and reloads
  the shared envelope via a mock secure element, and errors cleanly with no
  backend (2 tests).
