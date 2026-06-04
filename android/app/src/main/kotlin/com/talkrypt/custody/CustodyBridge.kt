/*
 * talkrypt — Android key-custody bridge.
 *
 * Detects the strongest custody tier this device actually provides and reports
 * it into talkrypt's PQ + custody-tier parity model (#305) via the shared FFI
 * (`custodyReport`). The device probes at runtime and reports honestly — a phone
 * without a secure element reports OsKeystore (TEE/software), never overclaiming.
 *
 * NOT certified / NOT audited — see the project README.
 */
package com.talkrypt.custody

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import uniffi.talkrypt_ffi.CustodyTier
import uniffi.talkrypt_ffi.custodyReport

object CustodyBridge {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val PROBE_ALIAS = "talkrypt.custody.probe"

    /** Detect the strongest custody tier available on this device. */
    fun detectTier(): CustodyTier {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generateProbeKey(strongBox = true)
                return CustodyTier.HARDWARE_BACKED
            } catch (_: StrongBoxUnavailableException) {
                // no StrongBox — fall through to a non-StrongBox probe
            } catch (_: Exception) {
                // fall through
            }
        }
        return try {
            val key = generateProbeKey(strongBox = false)
            if (isInsideSecureHardware(key)) CustodyTier.HARDWARE_BACKED
            else CustodyTier.OS_KEYSTORE
        } catch (_: Exception) {
            CustodyTier.SOFTWARE_SEALED
        } finally {
            deleteProbeKey()
        }
    }

    /** Detect the tier and return the encoded parity report (for #305). */
    fun parityReport(): ByteArray = custodyReport(detectTier())

    private fun generateProbeKey(strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            PROBE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(builder.build())
        return kg.generateKey()
    }

    private fun isInsideSecureHardware(key: SecretKey): Boolean {
        val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }
    }

    private fun deleteProbeKey() {
        runCatching {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(PROBE_ALIAS)
        }
    }
}
