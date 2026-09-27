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
import uniffi.talkrypt_ffi.meshcoreEncodeAppStart
import uniffi.talkrypt_ffi.meshcoreEncodeChannelText
import uniffi.talkrypt_ffi.meshcoreParseChannelRecv

/**
 * A Meshcore LoRa node reached over **BLE**, as an FFI [MeshNodeBackend] so talkrypt
 * can carry chat messages over the mesh (`Core::start_mesh_messaging`). Meshcore's
 * BLE companion uses the **Nordic UART Service** (RX = app→node write, TX = node→app
 * notify); over BLE each notification is exactly one companion frame (no serial length
 * prefix). talkrypt's own frames ride inside a channel message, base64-wrapped for
 * Meshcore's UTF-8 text field.
 *
 * The Meshcore **companion frames are built/parsed by the verified Rust codec** over
 * the FFI (`meshcoreEncodeChannelText` / `meshcoreParseChannelRecv` / `meshcoreEncodeAppStart`) —
 * this class is a dumb BLE pipe and never touches the protocol or talkrypt
 * keys/plaintext (opaque, already-sealed bytes only).
 *
 * On connect it sends `CMD_APP_START` to identify the app to the node (required before
 * the node accepts commands). Meshcore's BLE companion mandates **bonding + a static
 * PIN** (default 123456); Android drives the pairing dialog on first connect.
 *
 * **On-device only:** the Android emulator has no real Bluetooth, so this is validated
 * on hardware (a phone + a Meshcore node), like [MeshtasticBleBackend]. Compile + wiring
 * are covered by the JVM unit-test gate.
 */
class MeshcoreBleBackend(
    private val context: Context,
    private val device: BluetoothDevice,
) : MeshRadioBackend {
    private val main = Handler(Looper.getMainLooper())
    private var gatt: BluetoothGatt? = null
    private var rx: BluetoothGattCharacteristic? = null // app -> node (write)
    private var onPacket: ((UByte, ByteArray, UInt?) -> Unit)? = null

    private val ops = ConcurrentLinkedQueue<() -> Unit>()
    @Volatile private var busy = false

    // MARK: MeshNodeBackend (called by talkrypt core)

    /** Fragment budget per packet: Meshcore channel text ~160 UTF-8 chars, base64 4/3
     *  inflation → a 120-byte fragment fits. */
    override fun mtu(): UInt = 120u

    override fun send(channel: UByte, payload: ByteArray) {
        // The Rust codec base64-wraps the opaque fragment into a channel-text command.
        writeToRx(meshcoreEncodeChannelText(channel, payload))
    }

    // MARK: connection lifecycle (called by the app; wire onPacket -> FfiMeshNode.deliverPacket)

    /** Connect, identify via CMD_APP_START, and deliver inbound channel messages via
     *  [onPacket] (wire it to `FfiMeshNode.deliverPacket`). Call once, after
     *  `client.startMeshMessaging(backend, channel)` returns the handle. */
    @SuppressLint("MissingPermission")
    override fun startReceiving(onPacket: (UByte, ByteArray, UInt?) -> Unit) {
        this.onPacket = onPacket
        try {
            gatt = device.connectGatt(context, false, callback)
        } catch (e: SecurityException) {
        }
    }

    @SuppressLint("MissingPermission")
    override fun stop() {
        try {
            gatt?.disconnect()
            gatt?.close()
        } catch (e: SecurityException) {
        }
        gatt = null
        rx = null
        onPacket = null
        ops.clear()
        busy = false
    }

    // MARK: GATT write queue (one outstanding op)

    private fun writeToRx(payload: ByteArray) {
        val ch = rx ?: return // not connected yet; core retries next frame
        enqueue {
            val g = gatt ?: return@enqueue finishOp()
            try {
                @Suppress("DEPRECATION")
                run {
                    ch.value = payload
                    ch.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                    g.writeCharacteristic(ch)
                }
            } catch (e: SecurityException) {
                finishOp()
            }
        }
    }

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
            rx = svc.getCharacteristic(RX)
            val tx = svc.getCharacteristic(TX)
            if (tx != null) {
                try {
                    g.setCharacteristicNotification(tx, true)
                    val cccd = tx.getDescriptor(CCCD)
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
            // Identify our app to the node so it accepts subsequent commands.
            writeToRx(meshcoreEncodeAppStart("talkrypt"))
        }

        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
        override fun onCharacteristicWrite(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            finishOp()
        }

        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
        override fun onCharacteristicChanged(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
        ) {
            // Over BLE each TX notification is one whole companion frame [code][data].
            if (characteristic.uuid == TX) {
                val frame = characteristic.value ?: return
                // Opaque frame → verified Rust codec extracts + base64-decodes a channel payload.
                runCatching { meshcoreParseChannelRecv(frame) }.getOrNull()?.let { rx ->
                    main.post { onPacket?.invoke(rx.channel, rx.payload, null) }
                }
            }
        }
    }

    companion object {
        /** Meshcore BLE companion = Nordic UART Service (verified: meshcore-dev docs). */
        val SERVICE: UUID = UUID.fromString("6e400001-b5a3-f393-e0a9-e50e24dcca9e")
        val RX: UUID = UUID.fromString("6e400002-b5a3-f393-e0a9-e50e24dcca9e") // central writes here
        val TX: UUID = UUID.fromString("6e400003-b5a3-f393-e0a9-e50e24dcca9e") // central notified here

        /** Standard Client Characteristic Configuration Descriptor (enables notifications). */
        val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
}
