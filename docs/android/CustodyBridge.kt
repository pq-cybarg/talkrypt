/*
 * talkrypt — Android key-custody bridge (SCAFFOLD).
 *
 * Detects the strongest custody tier this device actually provides and reports
 * it into talkrypt's PQ + custody-tier parity model (#305) via the shared FFI
 * (`custodyReport`). The device must NOT assume StrongBox: it probes at runtime
 * and reports honestly, so a phone without a secure element reports OsKeystore
 * (TEE/software Keystore) rather than overclaiming HardwareBacked.
 *
 * This is a scaffold: it targets the Android Keystore APIs and the uniffi-
 * generated `uniffi.talkrypt` bindings, and is compiled by the Android app
 * module (Gradle + NDK), NOT by cargo. The Rust side it calls
 * (talkrypt_ffi::custody_report / CustodyTier) is cross-compile-verified for
 * aarch64-linux-android.
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
import javax.crypto.SecretKeyFactory

// The uniffi-generated binding (see docs/PLATFORMS.md for bindgen):
import uniffi.talkrypt.CustodyTier
import uniffi.talkrypt.custodyReport

object CustodyBridge {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val PROBE_ALIAS = "talkrypt.custody.probe"

    /**
     * Detect the strongest custody tier available on this device.
     *
     * - StrongBox-backed key creation succeeds            -> HardwareBacked
     * - Key is inside secure hardware (TEE), not StrongBox -> HardwareBacked
     * - Key exists only in the software Keystore           -> OsKeystore
     * - Keystore unavailable / probe failed                -> SoftwareSealed
     */
    fun detectTier(): CustodyTier {
        // Try StrongBox first (Android 9 / API 28+, dedicated secure element).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generateProbeKey(strongBox = true)
                return CustodyTier.HARDWARE_BACKED
            } catch (_: StrongBoxUnavailableException) {
                // fall through to a non-StrongBox probe
            } catch (_: Exception) {
                // fall through
            }
        }
        return try {
            val key = generateProbeKey(strongBox = false)
            if (isInsideSecureHardware(key)) CustodyTier.HARDWARE_BACKED
            else CustodyTier.OS_KEYSTORE
        } catch (_: Exception) {
            // No usable Keystore — fall back to the app's software-sealed tier.
            CustodyTier.SOFTWARE_SEALED
        } finally {
            deleteProbeKey()
        }
    }

    /** Detect the tier and return the encoded parity report for #305. */
    fun parityReport(): ByteArray = custodyReport(detectTier())

    private fun generateProbeKey(strongBox: Boolean): javax.crypto.SecretKey {
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

    private fun isInsideSecureHardware(key: javax.crypto.SecretKey): Boolean {
        val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // API 31+: SECURITY_LEVEL_TRUSTED_ENVIRONMENT or _STRONGBOX are HW.
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
