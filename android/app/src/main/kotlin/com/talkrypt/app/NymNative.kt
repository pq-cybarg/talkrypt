package com.talkrypt.app

/**
 * Native init for nym-sdk's TLS stack. nym's HTTP client (reqwest) verifies
 * certificates through `rustls-platform-verifier`, which on Android MUST be
 * initialized with the app's JNI context before the first HTTPS call — otherwise
 * it aborts ("Expect rustls-platform-verifier to be initialized"). The Rust side
 * exports `Java_com_talkrypt_app_NymNative_initTlsVerifier` (crates/ffi).
 *
 * Only present when the .so was built with the `nym` feature; on other builds the
 * call throws UnsatisfiedLinkError, which the caller ignores (non-nym builds
 * never touch nym TLS). Called once from [TkApp.onCreate].
 */
object NymNative {
    init { System.loadLibrary("talkrypt_ffi") }

    /** Wire rustls-platform-verifier to the Android cert store via the JVM. */
    external fun initTlsVerifier(context: android.content.Context)
}
