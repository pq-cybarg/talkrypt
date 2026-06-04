package com.talkrypt.app

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import com.talkrypt.custody.CustodyBridge

/**
 * Minimal probe activity: detects this device's custody tier via the Android
 * Keystore, builds the shared parity report through the talkrypt FFI, and
 * shows + logs the result. Read it with:
 *   adb logcat -s talkrypt
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val sbFeature =
            packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val tier = CustodyBridge.detectTier()
        val report = CustodyBridge.parityReport()
        val reportHex = report.joinToString("") { "%02x".format(it) }

        val text = buildString {
            appendLine("talkrypt custody probe")
            appendLine("device: ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
            appendLine("StrongBox feature: $sbFeature")
            appendLine("detected tier: $tier")
            appendLine("PQ identity: yes (ML-DSA-87)")
            appendLine("parity report (${report.size} B): $reportHex")
        }
        Log.i("talkrypt", text.replace("\n", " | "))

        setContentView(TextView(this).apply {
            setPadding(40, 80, 40, 40)
            textSize = 16f
            this.text = text
        })
    }
}
