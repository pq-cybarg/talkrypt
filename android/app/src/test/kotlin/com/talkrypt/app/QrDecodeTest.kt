package com.talkrypt.app

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Proves the in-app scanner's decode contract end-to-end on the JVM, with no
 * camera or emulator: encode a talkrypt invite as a QR (ZXing writer), render it
 * to a luminance buffer exactly like a camera Y plane, and decode it through the
 * same [QrDecode.decodeLuminance] the live camera frames flow through.
 */
class QrDecodeTest {

    /** Encode `text` to a tight width*height luminance buffer (0x00 dark, 0xFF light). */
    private fun qrLuminance(text: String, size: Int, quietModules: Int = 4): Triple<ByteArray, Int, Int> {
        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to quietModules,
        )
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
        val w = matrix.width
        val h = matrix.height
        val data = ByteArray(w * h)
        for (y in 0 until h) {
            for (x in 0 until w) {
                // ZXing module set => dark; PlanarYUVLuminanceSource treats low
                // luminance as dark, so dark = 0x00, light = 0xFF.
                data[y * w + x] = if (matrix.get(x, y)) 0x00 else 0xFF.toByte()
            }
        }
        return Triple(data, w, h)
    }

    @Test
    fun decodes_a_talkrypt_invite_qr() {
        val invite = "talkrypt://aaaaaaiaaaaaaaboorvs4zdsfzwwy23fnuytamrufnygczbomfsxgmrvgztwg3joonugcmzngm4d"
        val (data, w, h) = qrLuminance(invite, 512)
        assertEquals(invite, QrDecode.decodeLuminance(data, w, h))
    }

    @Test
    fun decodes_a_short_uri() {
        val text = "talkrypt://abc123"
        val (data, w, h) = qrLuminance(text, 256)
        assertEquals(text, QrDecode.decodeLuminance(data, w, h))
    }

    @Test
    fun returns_null_for_a_blank_frame() {
        // An all-light frame has no QR — the scanner must keep scanning, not crash.
        val w = 320
        val h = 240
        val blank = ByteArray(w * h) { 0xFF.toByte() }
        assertNull(QrDecode.decodeLuminance(blank, w, h))
    }
}
