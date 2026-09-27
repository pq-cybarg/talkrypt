package com.talkrypt.app

import uniffi.talkrypt_ffi.MeshNodeBackend

/**
 * A LoRa-mesh radio backend the app can start/stop and feed received packets from.
 * Extends the FFI [MeshNodeBackend] (which talkrypt core drives for `mtu`/`send`)
 * with the app-side lifecycle both concrete backends share
 * ([MeshtasticBleBackend], [MeshcoreBleBackend]) — so MainActivity can hold either
 * behind one type and wire `onPacket` to `FfiMeshNode.deliverPacket`.
 */
interface MeshRadioBackend : MeshNodeBackend {
    /** Connect to the node and deliver inbound talkrypt payloads via [onPacket]
     *  (channel, opaque payload, coarse sender). Call once, after
     *  `client.startMeshMessaging(backend, channel)` returns the handle. */
    fun startReceiving(onPacket: (UByte, ByteArray, UInt?) -> Unit)

    /** Disconnect and release the radio. */
    fun stop()
}
