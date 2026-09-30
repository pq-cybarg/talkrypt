package com.talkrypt.app

import uniffi.talkrypt_ffi.LocalBeaconBackend

/**
 * SUB-SPEC A / #68: a radio backend for the pre-session CQ beacon — the FFI
 * [LocalBeaconBackend] (advertise/stop the opaque sealed blob) plus the app-side
 * scan pump and an emulator spoof hook. Implemented by [BleBeaconBackend] (BLE) and
 * [WifiBeaconBackend] (Wi-Fi / NSD).
 */
interface RadioBeacon : LocalBeaconBackend {
    /** Scan for nearby beacons; push each opaque blob (with a coarse source handle)
     *  to [onBlob] — wire it to `FfiBeacon.deliverBeacon(blob, source)`. */
    fun startScanning(onBlob: (ByteArray, String) -> Unit, onError: (String) -> Unit = {})

    /** The most recent blob core asked us to advertise (for the emulator spoof
     *  self-test — feed it back through `deliverBeacon`). */
    fun lastAdvertised(): ByteArray?
}

/**
 * Compose several radios into one backend — the Kotlin peer of the Rust
 * `MultiBeacon`. `advertise`/`stop` fan out to every child, `startScanning` starts
 * all of them, and `lastAdvertised` returns the first child's blob (they all carry
 * the same one). A dead/absent radio is best-effort and never breaks the others.
 */
class MultiLocalBeacon(private val children: List<RadioBeacon>) : RadioBeacon {
    override fun advertise(blob: ByteArray) = children.forEach { runCatching { it.advertise(blob) } }.let {}
    override fun stop() = children.forEach { runCatching { it.stop() } }.let {}
    override fun startScanning(onBlob: (ByteArray, String) -> Unit, onError: (String) -> Unit) =
        children.forEach { runCatching { it.startScanning(onBlob, onError) } }.let {}
    override fun lastAdvertised(): ByteArray? = children.firstNotNullOfOrNull { it.lastAdvertised() }
}
