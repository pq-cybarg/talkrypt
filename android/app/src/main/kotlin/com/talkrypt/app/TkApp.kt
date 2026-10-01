package com.talkrypt.app

import android.app.Application

/**
 * Application entry point. Its `onCreate` runs before ANY app component (the
 * always-on ChatService's boot reconnect, or MainActivity), so it's the right
 * place to initialize nym-sdk's TLS verifier once — before anything can host or
 * join over the Nym mixnet. No-op (caught) on builds without the `nym` feature.
 */
class TkApp : Application() {
    override fun onCreate() {
        super.onCreate()
        runCatching { NymNative.initTlsVerifier(this) }
        // Prewarm the expensive singletons (Keystore unseal + ML-DSA account
        // reconstruction, StrongBox custody probe) off the main thread, so the
        // first screen that needs them doesn't pay the cost during layout.
        Thread {
            runCatching { ChatNet.account(this) }
            runCatching { com.talkrypt.custody.CustodyBridge.detectTier() }
        }.start()
    }
}
