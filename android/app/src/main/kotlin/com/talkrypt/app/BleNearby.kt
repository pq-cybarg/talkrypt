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
import java.util.Collections

/**
 * Bluetooth LE nearby discovery.
 *
 * **Host (advertising):** opens a GATT server with a single readable
 * characteristic holding the `talkrypt://` invite, and BLE-advertises the
 * talkrypt service UUID so scanners know a host is present. Reads are served
 * with offset support (ATT read-blob), so invites larger than one MTU are
 * delivered in full.
 *
 * **Scanner:** scans for that service UUID; on the first sighting of a device it
 * connects via GATT, raises the MTU, reads the invite characteristic, and hands
 * the invite to `onFound` — then disconnects. The chat that follows still goes
 * over the normal encrypted transport.
 *
 * Permission calls are `@SuppressLint("MissingPermission")`: the caller
 * (MainActivity) requests BLUETOOTH_ADVERTISE/SCAN/CONNECT (API 31+) or
 * BLUETOOTH(_ADMIN)+location (pre-31) before invoking these. If a permission is
 * missing, the framework throws SecurityException, which we report via onError.
 */
class BleNearby(private val context: Context) : NearbyDiscovery {
    private val main = Handler(Looper.getMainLooper())
    private val mgr = context.getSystemService(BluetoothManager::class.java)

    private var gattServer: BluetoothGattServer? = null
    private var inviteBytes: ByteArray = ByteArray(0)
    private var advertiseCallback: AdvertiseCallback? = null
    private var scanCallback: ScanCallback? = null
    private val clients = Collections.synchronizedList(mutableListOf<BluetoothGatt>())
    private val seen = Collections.synchronizedSet(mutableSetOf<String>())

    @SuppressLint("MissingPermission")
    override fun startAdvertising(inviteUri: String) {
        val adapter = mgr?.adapter ?: return
        inviteBytes = inviteUri.toByteArray()
        try {
            // GATT server that serves the invite when a scanner connects + reads.
            val server = mgr.openGattServer(context, gattServerCallback)
            val service = BluetoothGattService(
                NearbyDiscovery.SERVICE_UUID,
                BluetoothGattService.SERVICE_TYPE_PRIMARY,
            )
            val ch = BluetoothGattCharacteristic(
                NearbyDiscovery.INVITE_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ,
            )
            service.addCharacteristic(ch)
            server.addService(service)
            gattServer = server

            // Advertise presence (the service UUID; the invite is fetched via GATT).
            val advertiser = adapter.bluetoothLeAdvertiser ?: return
            val settings = AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setConnectable(true)
                .setTimeout(0)
                .build()
            val data = AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceUuid(ParcelUuid(NearbyDiscovery.SERVICE_UUID))
                .build()
            val cb = object : AdvertiseCallback() {}
            advertiseCallback = cb
            advertiser.startAdvertising(settings, data, cb)
        } catch (e: SecurityException) {
            // Permission not granted — caller should have requested it.
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
                if (characteristic?.uuid == NearbyDiscovery.INVITE_CHAR_UUID) {
                    // Serve the requested slice (supports long/blob reads).
                    val value = inviteBytes
                    val slice = if (offset >= value.size) {
                        ByteArray(0)
                    } else {
                        value.copyOfRange(offset, value.size)
                    }
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
                } else {
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                }
            } catch (e: SecurityException) {
                // ignore
            }
        }
    }

    @SuppressLint("MissingPermission")
    override fun startScanning(onFound: (NearbyDiscovery.Peer) -> Unit, onError: (String) -> Unit) {
        val adapter = mgr?.adapter
        if (adapter == null || !adapter.isEnabled) {
            onError("Bluetooth is off")
            return
        }
        val scanner = adapter.bluetoothLeScanner ?: run {
            onError("No BLE scanner")
            return
        }
        val filters = listOf(
            ScanFilter.Builder()
                .setServiceUuid(ParcelUuid(NearbyDiscovery.SERVICE_UUID))
                .build(),
        )
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult?) {
                val device = result?.device ?: return
                // Connect once per device to read the invite characteristic.
                if (seen.add(device.address)) {
                    connectAndRead(device, onFound)
                }
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

    @SuppressLint("MissingPermission")
    private fun connectAndRead(device: BluetoothDevice, onFound: (NearbyDiscovery.Peer) -> Unit) {
        try {
            device.connectGatt(context, false, gattClient(onFound))
        } catch (e: SecurityException) {
            // ignore; permission handled by caller
        }
    }

    @Suppress("DEPRECATION") // the 3-arg onCharacteristicRead works across API 28-35
    private fun gattClient(onFound: (NearbyDiscovery.Peer) -> Unit) =
        object : BluetoothGattCallback() {
            @SuppressLint("MissingPermission")
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                try {
                    when (newState) {
                        BluetoothProfile.STATE_CONNECTED -> {
                            clients.add(gatt)
                            gatt.requestMtu(517)
                        }
                        BluetoothProfile.STATE_DISCONNECTED -> {
                            clients.remove(gatt)
                            gatt.close()
                        }
                    }
                } catch (e: SecurityException) {
                }
            }

            @SuppressLint("MissingPermission")
            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                try {
                    gatt.discoverServices()
                } catch (e: SecurityException) {
                }
            }

            @SuppressLint("MissingPermission")
            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                try {
                    val ch = gatt.getService(NearbyDiscovery.SERVICE_UUID)
                        ?.getCharacteristic(NearbyDiscovery.INVITE_CHAR_UUID)
                    if (ch != null) gatt.readCharacteristic(ch) else gatt.disconnect()
                } catch (e: SecurityException) {
                }
            }

            @SuppressLint("MissingPermission")
            @Suppress("OVERRIDE_DEPRECATION") // the 3-arg form works on all of API 28-35
            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    val invite = String(characteristic.value ?: ByteArray(0))
                    if (invite.startsWith("talkrypt://")) {
                        val name = try {
                            gatt.device.name ?: gatt.device.address
                        } catch (e: SecurityException) {
                            gatt.device.address
                        }
                        main.post { onFound(NearbyDiscovery.Peer(name, invite)) }
                    }
                }
                try {
                    gatt.disconnect()
                } catch (e: SecurityException) {
                }
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
    }
}
