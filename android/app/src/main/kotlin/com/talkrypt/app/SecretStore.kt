package com.talkrypt.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypted-at-rest storage for small secret strings (identity seeds, the NYM
 * wallet mnemonic) inside the "talkrypt" SharedPreferences. Values are sealed
 * with a non-exportable AES-256-GCM key in the Android Keystore (StrongBox when
 * the device has one), so a copied prefs file yields only ciphertext. Legacy
 * plaintext values are migrated (sealed, then removed) on first read.
 *
 * Fail-closed: if the Keystore is unusable, [put] throws rather than falling
 * back to plaintext — callers decide how to surface that. No AndroidX.
 */
object SecretStore {
    private const val ALIAS = "tk-secrets"
    private const val PREFIX = "sec_" // prefs key prefix for sealed values
    private const val GCM_IV_LEN = 12 // bytes; GCM tag is 128-bit

    /** Last seal/unseal failure (message), or null. Surfaced in Settings so the
     *  "sealed at rest" card never claims more than what actually happened. */
    @Volatile
    var lastError: String? = null
        private set

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences("talkrypt", Context.MODE_PRIVATE)

    /** The sealing key — generated once, StrongBox first, TEE/software fallback. */
    private fun sealKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        return try {
            kg.init(spec(strongBox = true)); kg.generateKey()
        } catch (_: Exception) { // StrongBoxUnavailable & friends
            kg.init(spec(strongBox = false)); kg.generateKey()
        }
    }

    /** Seal [value] under [key]; null/empty clears. Always removes any legacy
     *  plaintext copy of [key]. Throws if the Keystore refuses to seal. */
    @Synchronized
    fun put(ctx: Context, key: String, value: String?) {
        val e = prefs(ctx).edit().remove(key) // never leave a plaintext copy
        if (value.isNullOrEmpty()) {
            e.remove(PREFIX + key)
        } else {
            try {
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.ENCRYPT_MODE, sealKey())
                val sealed = c.iv + c.doFinal(value.toByteArray(Charsets.UTF_8))
                e.putString(PREFIX + key, Base64.encodeToString(sealed, Base64.NO_WRAP))
            } catch (ex: Exception) {
                lastError = ex.message ?: ex.javaClass.simpleName
                throw ex
            }
        }
        e.apply()
    }

    /** True if a sealed (or legacy plaintext) value exists for [key], even if it
     *  cannot currently be unsealed — lets callers avoid clobbering a blob that
     *  a future fix or the right Keystore state could still recover. */
    @Synchronized
    fun has(ctx: Context, key: String): Boolean =
        prefs(ctx).contains(PREFIX + key) || prefs(ctx).contains(key)

    /** Unseal [key], or null if absent/undecryptable. A legacy plaintext value
     *  is returned as-is and migrated to sealed storage (kept plaintext only if
     *  sealing fails, so a broken Keystore never loses the secret). */
    @Synchronized
    fun get(ctx: Context, key: String): String? {
        prefs(ctx).getString(key, null)?.let { plain ->
            runCatching { put(ctx, key, plain) }
            return plain.ifEmpty { null }
        }
        val b64 = prefs(ctx).getString(PREFIX + key, null) ?: return null
        return runCatching {
            val raw = Base64.decode(b64, Base64.NO_WRAP)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(
                Cipher.DECRYPT_MODE, sealKey(),
                GCMParameterSpec(128, raw, 0, GCM_IV_LEN),
            )
            String(c.doFinal(raw, GCM_IV_LEN, raw.size - GCM_IV_LEN), Charsets.UTF_8)
        }.onFailure { lastError = it.message ?: it.javaClass.simpleName }.getOrNull()
    }
}
