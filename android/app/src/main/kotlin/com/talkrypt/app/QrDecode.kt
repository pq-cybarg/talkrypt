package com.talkrypt.app

import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * Pure, Android-free QR decode over a luminance (grayscale) frame. Kept separate
 * from [QrScanActivity] so the decode contract is unit-testable on the JVM with
 * no camera or emulator — the activity just supplies camera frames to it.
 *
 * `data` is a tightly-packed `width * height` array of 8-bit luminance samples
 * (the Y plane of a YUV camera frame, stride already removed). Returns the
 * decoded QR text, or null if no QR is found in the frame.
 *
 * No Google Play Services, no ML Kit, no network — ZXing core decoding only.
 */
object QrDecode {
    private val reader = QRCodeReader()
    private val hints = mapOf<DecodeHintType, Any>(DecodeHintType.TRY_HARDER to true)

    @Synchronized
    fun decodeLuminance(data: ByteArray, width: Int, height: Int): String? {
        return try {
            val source = PlanarYUVLuminanceSource(data, width, height, 0, 0, width, height, false)
            val bitmap = BinaryBitmap(HybridBinarizer(source))
            reader.decode(bitmap, hints).text
        } catch (_: Exception) {
            // NotFound / Checksum / Format — no readable QR in this frame.
            null
        } finally {
            reader.reset()
        }
    }
}
