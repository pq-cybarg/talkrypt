package com.talkrypt.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.talkrypt_ffi.HardwareKeyWrapper
import uniffi.talkrypt_ffi.sealSecret
import uniffi.talkrypt_ffi.unsealSecret

/** Wraps the seal KEK with a non-exportable Android Keystore AES key (StrongBox
 *  when available), so chat history is hardware-gated at rest. Implements the
 *  same HardwareKeyWrapper contract as docs/hardware-backed-sealing.md. */
class KeystoreWrapper(private val strongBox: Boolean) : HardwareKeyWrapper {
    private val alias = if (strongBox) "talkrypt.history.kek.sb" else "talkrypt.history.kek"
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(): SecretKey {
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        kg.init(spec)
        return kg.generateKey()
    }

    override fun wrap(kek: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        return c.iv + c.doFinal(kek)            // iv(12) ‖ ciphertext‖tag
    }

    override fun unwrap(wrapped: ByteArray): ByteArray {
        val iv = wrapped.copyOfRange(0, 12)
        val ct = wrapped.copyOfRange(12, wrapped.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
            .apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)) }
        return c.doFinal(ct)
    }
}

/** Sealed at-rest store for chat metadata + history, under `filesDir/chats/`. */
class ChatStore(ctx: Context) {
    private val dir = File(ctx.filesDir, "chats").apply { mkdirs() }
    private val index = File(dir, "index")

    // Prefer a StrongBox-backed wrapper; fall back to TEE if the secure element
    // can't mint the key (probe by actually wrapping once).
    private val wrapper: HardwareKeyWrapper =
        runCatching { KeystoreWrapper(true).also { it.wrap(ByteArray(32)) } }.getOrNull()
            ?: KeystoreWrapper(false)

    private fun blobFile(id: String) = File(dir, "$id.tkc")

    /** Persist one kept chat (meta + history). Ephemeral chats must not call this. */
    fun save(meta: ChatMeta, history: List<ChatMsg>) {
        // meta.encode()/msg.encode() never contain a raw '\n' (the codec escapes
        // newlines), so a single '\n' cleanly separates meta from the history blob.
        val plain = (meta.encode() + "\n" + ChatMsg.encodeList(history)).toByteArray(Charsets.UTF_8)
        val sealed = sealSecret(plain, null, wrapper)
        blobFile(meta.id).writeBytes(sealed)
        writeIndex((readIndex() + meta.id).distinct())
    }

    /** Load one chat's (meta, history), or null if missing/corrupt. */
    fun load(id: String): Pair<ChatMeta, List<ChatMsg>>? = runCatching {
        val text = unsealSecret(blobFile(id).readBytes(), null, wrapper).toString(Charsets.UTF_8)
        val nl = text.indexOf('\n')
        ChatMeta.decode(text.substring(0, nl)) to ChatMsg.decodeList(text.substring(nl + 1))
    }.getOrNull()

    /** All kept chat ids whose blob still exists. */
    fun ids(): List<String> = readIndex().filter { blobFile(it).exists() }

    fun delete(id: String) {
        blobFile(id).delete()
        writeIndex(readIndex() - id)
    }

    private fun readIndex(): List<String> =
        if (index.exists()) index.readText().split("\n").filter { it.isNotBlank() } else emptyList()

    private fun writeIndex(ids: List<String>) = index.writeText(ids.joinToString("\n"))
}
