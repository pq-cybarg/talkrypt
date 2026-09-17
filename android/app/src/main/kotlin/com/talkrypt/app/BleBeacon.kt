package com.talkrypt.app

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import java.io.ByteArrayOutputStream
import java.util.Collections

/**
 * SUB-SPEC A / #68: a Bluetooth LE radio backend for the pre-session CQ **beacon**.
 *
 * This is the Kotlin implementation of the FFI [`LocalBeaconBackend`] seam. talkrypt
 * core hands it an OPAQUE, already-PQ+AES-sealed beacon blob (never keys or
 * plaintext — the non-negotiable backend invariant) via [advertise]; the backend is
 * a dumb pipe that moves those bytes over the radio.
 *
 * **Advertise:** open a GATT server exposing the blob on a readable characteristic
 * (blob/offset reads, so a beacon larger than one MTU is delivered in full) and
 * BLE-advertise a DISTINCT beacon service UUID (separate from the invite-discovery
 * service). This mirrors [BleNearby], which does the same for `talkrypt://` invites.
 *
 * **Scan:** [startScanning] scans for that beacon service, GATT-reads each peer's
 * blob, and pushes it up via the `onBlob` callback — which the caller wires to
 * `FfiBeacon.deliverBeacon(blob, source)` so core can open it (an invite-holder
 * recovers the CQ; anyone else learns only "a device is beaconing").
 *
 * **Emulator note:** Android emulators do not reliably support BLE peripheral
 * advertising, so [lastAdvertised] exposes the most recent blob core asked us to
 * broadcast — a test can feed it straight back through `deliverBeacon` to exercise
 * the full core round-trip (advertise -> open -> `Event::BeaconSeen`) with the radio
 * spoofed. On real hardware the scan path above delivers it over the air instead.
 */
class BleBeaconBackend(private val context: Context) : RadioBeacon {
    private val main = Handler(Looper.getMainLooper())
    private val mgr = context.getSystemService(BluetoothManager::class.java)

    private var gattServer: BluetoothGattServer? = null
    private var advertiseCallback: AdvertiseCallback? = null
    private var scanCallback: ScanCallback? = null
    private val clients = Collections.synchronizedList(mutableListOf<BluetoothGatt>())
    private val seen = Collections.synchronizedSet(mutableSetOf<String>())

    // The current opaque beacon blob core asked us to broadcast (guarded; read by the
    // GATT server + exposed via lastAdvertised for the emulator spoof path).
    @Volatile private var blob: ByteArray = ByteArray(0)

    /** The most recent blob passed to [advertise] (for the emulator spoof self-test). */
    override fun lastAdvertised(): ByteArray? = blob.takeIf { it.isNotEmpty() }

    @SuppressLint("MissingPermission")
    override fun advertise(blob: ByteArray) {
        this.blob = blob
        val adapter = mgr?.adapter ?: return
        try {
            // (Re)open the GATT server serving the blob to connecting scanners.
            gattServer?.close()
            val server = mgr.openGattServer(context, gattServerCallback) ?: return
            val service = BluetoothGattService(
                NearbyDiscovery.BEACON_SERVICE_UUID,
                BluetoothGattService.SERVICE_TYPE_PRIMARY,
            )
            service.addCharacteristic(
                BluetoothGattCharacteristic(
                    NearbyDiscovery.BEACON_CHAR_UUID,
                    BluetoothGattCharacteristic.PROPERTY_READ,
                    BluetoothGattCharacteristic.PERMISSION_READ,
                ),
            )
            server.addService(service)
            gattServer = server

            val advertiser = adapter.bluetoothLeAdvertiser ?: return
            val settings = AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setConnectable(true)
                .setTimeout(0)
                .build()
            val data = AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceUuid(ParcelUuid(NearbyDiscovery.BEACON_SERVICE_UUID))
                .build()
            // Replace any prior advertisement so the newest CQ blob is the one served.
            advertiseCallback?.let { runCatching { adapter.bluetoothLeAdvertiser?.stopAdvertising(it) } }
            val cb = object : AdvertiseCallback() {}
            advertiseCallback = cb
            advertiser.startAdvertising(settings, data, cb)
        } catch (e: SecurityException) {
            // Permission not granted — caller requests BLUETOOTH_ADVERTISE beforehand.
        }
    }

    @SuppressLint("MissingPermission")
    override fun stop() {
        val adapter = mgr?.adapter
        try {
            advertiseCallback?.let { adapter?.bluetoothLeAdvertiser?.stopAdvertising(it) }
            scanCallback?.let { adapter?.bluetoothLeScanner?.stopScan(it) }
            synchronized(clients) {
                clients.forEach { runCatching { it.close() } }
                clients.clear()
            }
            gattServer?.close()
        } catch (e: SecurityException) {
        }
        advertiseCallback = null
        scanCallback = null
        gattServer = null
        seen.clear()
        blob = ByteArray(0)
    }

    /**
     * Scan for nearby beacons; for each new device, GATT-read its opaque blob and
     * hand it to [onBlob] with a coarse `source` handle (the MAC/adv address — for
     * dedup/signal only, never an identity). Wire `onBlob` to
     * `FfiBeacon.deliverBeacon(blob, source)`.
     */
    @SuppressLint("MissingPermission")
    override fun startScanning(onBlob: (ByteArray, String) -> Unit, onError: (String) -> Unit) {
        val adapter = mgr?.adapter
        if (adapter == null || !adapter.isEnabled) {
            onError("Bluetooth is off"); return
        }
        val scanner = adapter.bluetoothLeScanner ?: run { onError("No BLE scanner"); return }
        val filters = listOf(
            ScanFilter.Builder().setServiceUuid(ParcelUuid(NearbyDiscovery.BEACON_SERVICE_UUID)).build(),
        )
        val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult?) {
                val device = result?.device ?: return
                if (seen.add(device.address)) connectAndRead(device, onBlob)
            }
            override fun onScanFailed(errorCode: Int) {
                main.post { onError("BLE scan failed ($errorCode)") }
            }
        }
        scanCallback = cb
        try {
            scanner.startScan(filters, settings, cb)
        } catch (e: SecurityException) {
            onError("Bluetooth scan permission denied")
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        @SuppressLint("MissingPermission")
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice?,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic?,
        ) {
            val server = gattServer ?: return
            try {
                if (characteristic?.uuid == NearbyDiscovery.BEACON_CHAR_UUID) {
                    val v = blob
                    val slice = if (offset >= v.size) ByteArray(0) else v.copyOfRange(offset, v.size)
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
                } else {
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                }
            } catch (e: SecurityException) {
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun connectAndRead(device: BluetoothDevice, onBlob: (ByteArray, String) -> Unit) {
        try {
            device.connectGatt(context, false, gattClient(device.address, onBlob))
        } catch (e: SecurityException) {
        }
    }

    // Accumulates the (possibly multi-read) characteristic value; a single read of an
    // extended-MTU connection returns the whole blob, but we also support blob reads.
    private fun gattClient(address: String, onBlob: (ByteArray, String) -> Unit) =
        object : BluetoothGattCallback() {
            private val acc = ByteArrayOutputStream()

            @SuppressLint("MissingPermission")
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                try {
                    when (newState) {
                        BluetoothProfile.STATE_CONNECTED -> {
                            clients.add(gatt); gatt.requestMtu(517)
                        }
                        BluetoothProfile.STATE_DISCONNECTED -> {
                            clients.remove(gatt); gatt.close()
                        }
                    }
                } catch (e: SecurityException) {
                }
            }

            @SuppressLint("MissingPermission")
            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                try { gatt.discoverServices() } catch (e: SecurityException) {}
            }

            @SuppressLint("MissingPermission")
            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                try {
                    val ch = gatt.getService(NearbyDiscovery.BEACON_SERVICE_UUID)
                        ?.getCharacteristic(NearbyDiscovery.BEACON_CHAR_UUID)
                    if (ch != null) gatt.readCharacteristic(ch) else gatt.disconnect()
                } catch (e: SecurityException) {
                }
            }

            @SuppressLint("MissingPermission")
            @Suppress("OVERRIDE_DEPRECATION") // the 3-arg form works across API 28-35
            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    val bytes = characteristic.value ?: ByteArray(0)
                    if (bytes.isNotEmpty()) {
                        acc.write(bytes)
                        // Opaque bytes; hand up for core to open. `source` is coarse only.
                        val out = acc.toByteArray()
                        main.post { onBlob(out, address) }
                    }
                }
                try { gatt.disconnect() } catch (e: SecurityException) {}
            }
        }
}
