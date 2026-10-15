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
            // Run the prewarm at background priority so the one-shot PQ-keygen
            // burst (ML-DSA-87 reconstruct + Argon2id KEK + POST self-tests) can't
            // starve system services during the fragile launch window. talkrypt is
            // idle-clean at steady state (~0.1% CPU); this only smooths the startup
            // spike so a thin/software-GPU host stays responsive while we warm up.
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
            runCatching { ChatNet.account(this) }
            runCatching { com.talkrypt.custody.CustodyBridge.detectTier() }
        }.start()
    }
}
