package com.talkrypt.app

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Handler
import android.os.Looper
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import uniffi.talkrypt_ffi.MeshNodeBackend
import uniffi.talkrypt_ffi.meshtasticEncodeToradio
import uniffi.talkrypt_ffi.meshtasticParseFromradio

/**
 * A Meshtastic LoRa node reached over **BLE**, as an FFI [MeshNodeBackend] so talkrypt
 * can carry chat messages over the mesh (see `Core::start_mesh_messaging`). The phone
 * talks to the node (T-Deck, tracker, …) over Meshtastic's GATT service; talkrypt's
 * own frames ride inside a `PRIVATE_APP` payload.
 *
 * The Meshtastic **protobuf is built/parsed by the verified Rust codec** exposed over
 * the FFI (`meshtasticEncodeToradio` / `meshtasticParseFromradio`) — this class is a
 * dumb BLE pipe and never touches protobuf or talkrypt keys/plaintext (the
 * non-negotiable backend invariant: opaque, already-sealed bytes only).
 *
 * Over BLE each write to TORADIO is one raw protobuf `ToRadio` (GATT frames it — no
 * `0x94 0xC3` Stream API framing, which is serial-only); FROMRADIO is a queue drained
 * by repeated reads, and FROMNUM notifies when new packets are waiting.
 *
 * **On-device only:** the Android emulator has no real Bluetooth, so this is validated
 * on hardware (a phone + a Meshtastic node), like [BleBeaconBackend]. Compile + wiring
 * are covered by the JVM unit-test gate.
 */
class MeshtasticBleBackend(
    private val context: Context,
    private val device: BluetoothDevice,
) : MeshNodeBackend {
    private val main = Handler(Looper.getMainLooper())
    private var gatt: BluetoothGatt? = null
    private var toRadio: BluetoothGattCharacteristic? = null
    private var fromRadio: BluetoothGattCharacteristic? = null
    private var onPacket: ((UByte, ByteArray, UInt?) -> Unit)? = null

    // BLE allows one outstanding GATT operation; serialize writes + reads through a queue.
    private val ops = ConcurrentLinkedQueue<() -> Unit>()
    @Volatile private var busy = false

    // MARK: MeshNodeBackend (called by talkrypt core)

    /** Conservative usable `Data.payload` per Meshtastic packet (region/preset dependent). */
    override fun mtu(): UInt = 200u

    @SuppressLint("MissingPermission")
    override fun send(channel: UByte, payload: ByteArray) {
        val ch = toRadio ?: return // not connected yet; core retries on the next frame
        // The Rust codec wraps the opaque fragment as a PRIVATE_APP ToRadio protobuf.
        val pb = meshtasticEncodeToradio(channel, payload)
        enqueue {
            val g = gatt ?: return@enqueue finishOp()
            try {
                @Suppress("DEPRECATION")
                run {
                    ch.value = pb
                    ch.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                    g.writeCharacteristic(ch)
                }
            } catch (e: SecurityException) {
                finishOp()
            }
        }
    }

    // MARK: connection lifecycle (called by the app; wire onPacket -> FfiMeshNode.deliverPacket)

    /**
     * Connect to the node and start delivering inbound Meshtastic `PRIVATE_APP` payloads
     * via [onPacket] (wire it to `FfiMeshNode.deliverPacket`). Call once, after
     * `client.startMeshMessaging(backend, channel)` returns the handle.
     */
    @SuppressLint("MissingPermission")
    fun startReceiving(onPacket: (UByte, ByteArray, UInt?) -> Unit) {
        this.onPacket = onPacket
        try {
            gatt = device.connectGatt(context, false, callback)
        } catch (e: SecurityException) {
        }
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        try {
            gatt?.disconnect()
            gatt?.close()
        } catch (e: SecurityException) {
        }
        gatt = null
        toRadio = null
        fromRadio = null
        onPacket = null
        ops.clear()
        busy = false
    }

    // MARK: GATT op queue (one outstanding operation at a time)

    private fun enqueue(op: () -> Unit) {
        ops.add(op)
        main.post { pump() }
    }

    private fun pump() {
        if (busy) return
        val op = ops.poll() ?: return
        busy = true
        op()
    }

    private fun finishOp() {
        busy = false
        main.post { pump() }
    }

    /** Enqueue a FROMRADIO read; the callback drains further reads until empty. */
    @SuppressLint("MissingPermission")
    private fun readFromRadio() {
        val ch = fromRadio ?: return
        enqueue {
            val g = gatt ?: return@enqueue finishOp()
            try {
                @Suppress("DEPRECATION")
                g.readCharacteristic(ch)
            } catch (e: SecurityException) {
                finishOp()
            }
        }
    }

    private val callback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            try {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> g.requestMtu(512)
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        busy = false
                        ops.clear()
                    }
                }
            } catch (e: SecurityException) {
            }
        }

        @SuppressLint("MissingPermission")
        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
            try {
                g.discoverServices()
            } catch (e: SecurityException) {
            }
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            val svc = g.getService(SERVICE) ?: return
            toRadio = svc.getCharacteristic(TORADIO)
            fromRadio = svc.getCharacteristic(FROMRADIO)
            val fromNum = svc.getCharacteristic(FROMNUM)
            // Subscribe to FROMNUM so the node tells us when packets are waiting.
            if (fromNum != null) {
                try {
                    g.setCharacteristicNotification(fromNum, true)
                    val cccd = fromNum.getDescriptor(CCCD)
                    if (cccd != null) {
                        @Suppress("DEPRECATION")
                        run {
                            cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                            g.writeDescriptor(cccd)
                        }
                    }
                } catch (e: SecurityException) {
                }
            }
            // Drain anything already queued on the node.
            readFromRadio()
        }

        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION") // 3-arg forms work API 28-35
        override fun onCharacteristicWrite(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            finishOp()
        }

        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
        override fun onCharacteristicRead(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            if (characteristic.uuid == FROMRADIO) {
                val bytes = characteristic.value ?: ByteArray(0)
                finishOp()
                if (bytes.isNotEmpty()) {
                    // Opaque protobuf → verified Rust codec extracts a PRIVATE_APP payload.
                    runCatching { meshtasticParseFromradio(bytes) }.getOrNull()?.let { rx ->
                        main.post { onPacket?.invoke(rx.channel, rx.payload, rx.from) }
                    }
                    readFromRadio() // keep draining until empty
                }
            } else {
                finishOp()
            }
        }

        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
        override fun onCharacteristicChanged(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
        ) {
            // FROMNUM notification: new packet(s) waiting — drain FROMRADIO.
            if (characteristic.uuid == FROMNUM) readFromRadio()
        }
    }

    companion object {
        /** Meshtastic BLE GATT UUIDs (verified against meshtastic.org client-api docs). */
        val SERVICE: UUID = UUID.fromString("6ba1b218-15a8-461f-9fa8-5dcae273eafd")
        val TORADIO: UUID = UUID.fromString("f75c76d2-129e-4dad-a1dd-7866124401e7")
        val FROMRADIO: UUID = UUID.fromString("2c55e69e-4993-11ed-b878-0242ac120002")
        val FROMNUM: UUID = UUID.fromString("ed9da18c-a800-4f66-a670-aa7547e34453")

        /** Standard Client Characteristic Configuration Descriptor (enables notifications). */
        val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
}
