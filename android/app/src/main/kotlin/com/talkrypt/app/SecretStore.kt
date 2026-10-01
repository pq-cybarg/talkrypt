package com.talkrypt.app

import android.content.Context
import android.util.Base64
import uniffi.talkrypt_ffi.sealSecret
import uniffi.talkrypt_ffi.unsealSecret

/**
 * Encrypted-at-rest storage for small secret strings (the device identity seed,
 * the NYM wallet mnemonic, segment keys) in the "talkrypt" SharedPreferences.
 *
 * Sealing goes through the project's ONE portable seam — the Rust core's
 * `sealSecret`/`unsealSecret` (the `TKS1` envelope: a random KEK wrapped by the
 * host HSM, `KMAC/HKDF`-derived key, AES-256-GCM with the header bound as AEAD
 * AAD, and a reported `CustodyTier`) with the Android [KeystoreWrapper] as the HSM
 * plug (StrongBox first, TEE fallback). This is the SAME mechanism [ChatStore]
 * uses, so at-rest sealing is one audited, cross-platform codepath (Android
 * Keystore here; Secure Enclave / TPM / OS keystore on iOS / Linux / desktop) —
 * see `docs/hardware-backed-sealing.md`. There is NO bespoke cipher or envelope
 * here; the crypto lives in the core.
 *
 * Legacy plaintext values (and the pre-seam hand-rolled blobs) are migrated —
 * sealed via the core seam, then the plaintext removed — on first read. Fail-
 * closed: if sealing is unavailable, [put] throws rather than storing plaintext;
 * callers surface that via [lastError].
 */
object SecretStore {
    private const val PREFIX = "sec_" // prefs key holding the sealed (TKS1) blob, base64

    /** Last seal/unseal failure (message), or null. Surfaced in Settings so the
     *  "sealed at rest" card never claims more than what actually happened. */
    @Volatile
    var lastError: String? = null
        private set

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences("talkrypt", Context.MODE_PRIVATE)

    // The HSM plug for the core seal seam: prefer a StrongBox-backed key, fall back
    // to TEE if the secure element can't mint it (probe by actually wrapping once).
    private val wrapper by lazy {
        runCatching { KeystoreWrapper(true).also { it.wrap(ByteArray(32)) } }.getOrNull()
            ?: KeystoreWrapper(false)
    }

    /** Seal [value] under [key] via the core seam; null/empty clears. Always removes
     *  any legacy plaintext copy of [key]. Throws if the core refuses to seal. */
    @Synchronized
    fun put(ctx: Context, key: String, value: String?) {
        val e = prefs(ctx).edit().remove(key) // never leave a plaintext copy
        if (value.isNullOrEmpty()) {
            e.remove(PREFIX + key)
        } else {
            try {
                val sealed = sealSecret(value.toByteArray(Charsets.UTF_8), null, wrapper)
                e.putString(PREFIX + key, Base64.encodeToString(sealed, Base64.NO_WRAP))
            } catch (ex: Exception) {
                lastError = ex.message ?: ex.javaClass.simpleName
                throw ex
            }
        }
        e.apply()
    }

    /** True if a sealed (or legacy plaintext) value exists for [key], even if it
     *  cannot currently be unsealed — lets callers avoid clobbering a blob that a
     *  future fix or the right Keystore state could still recover. */
    @Synchronized
    fun has(ctx: Context, key: String): Boolean =
        prefs(ctx).contains(PREFIX + key) || prefs(ctx).contains(key)

    /** Unseal [key] via the core seam, or null if absent/undecryptable. A legacy
     *  plaintext value is returned as-is and migrated to sealed storage (kept
     *  plaintext only if sealing fails, so a broken Keystore never loses the secret). */
    @Synchronized
    fun get(ctx: Context, key: String): String? {
        prefs(ctx).getString(key, null)?.let { plain ->
            runCatching { put(ctx, key, plain) } // migrate legacy plaintext → sealed
            return plain.ifEmpty { null }
        }
        val b64 = prefs(ctx).getString(PREFIX + key, null) ?: return null
        return runCatching {
            String(unsealSecret(Base64.decode(b64, Base64.NO_WRAP), null, wrapper), Charsets.UTF_8)
        }.onFailure { lastError = it.message ?: it.javaClass.simpleName }.getOrNull()
    }
}
