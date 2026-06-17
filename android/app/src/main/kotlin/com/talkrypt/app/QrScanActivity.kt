package com.talkrypt.app

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.ImageReader
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.util.Size
import android.view.Gravity
import android.view.Surface
import android.view.TextureView
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.TextView
import java.util.concurrent.atomic.AtomicBoolean

/**
 * In-app QR scanner. A back-camera preview (Camera2) whose frames are decoded
 * on-device by ZXing's [QRCodeReader] — no Google Play Services, no ML Kit, no
 * network, no AndroidX. On a successful scan the raw QR text is returned to the
 * caller via [Activity.setResult] under [EXTRA_RESULT]; the caller decides what
 * to do with it (e.g. route a `talkrypt://` invite into the join flow).
 *
 * Built without XML, matching the rest of the app's code-defined UI.
 */
class QrScanActivity : Activity() {

    companion object {
        const val EXTRA_RESULT = "qr_text"
        private const val REQ_CAMERA = 0x4351 // "CQ"
        // A modest analysis resolution: big enough to read a dense invite QR,
        // small enough that per-frame decode stays real-time.
        private val TARGET = Size(1280, 720)
    }

    private lateinit var textureView: TextureView
    private lateinit var hint: TextView
    private var cameraDevice: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var imageReader: ImageReader? = null
    private var bgThread: HandlerThread? = null
    private var bgHandler: Handler? = null
    private var cameraId: String? = null
    private var previewSize: Size = TARGET
    // Guards against re-entrant decode + double-finishing once we have a hit.
    private val decoding = AtomicBoolean(false)
    private val done = AtomicBoolean(false)
    // Single-flight guards: the camera can be opened from several callbacks
    // (resume, surface-ready, permission-granted). Without these the device gets
    // opened twice and the second open disconnects the first, crashing the
    // first's onOpened in startPreview (CAMERA_DISCONNECTED).
    @Volatile private var opening = false
    @Volatile private var paused = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        textureView = TextureView(this)
        root.addView(
            textureView,
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT),
        )
        hint = TextView(this).apply {
            text = "Point at a talkrypt QR"
            setTextColor(Color.WHITE)
            textSize = 16f
            setPadding(0, 0, 0, dp(48))
        }
        root.addView(
            hint,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL,
            ),
        )
        val cancel = TextView(this).apply {
            text = "✕"
            setTextColor(Color.WHITE)
            textSize = 22f
            setPadding(dp(20), dp(20), dp(20), dp(20))
            setOnClickListener { cancel() }
        }
        root.addView(
            cancel,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP or Gravity.END,
            ),
        )
        setContentView(root)

        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.CAMERA), REQ_CAMERA)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_CAMERA) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                maybeOpenCamera()
            } else {
                hint.text = "Camera permission needed to scan"
            }
        }
    }

    override fun onResume() {
        super.onResume()
        paused = false
        bgThread = HandlerThread("qr-cam").also { it.start() }
        bgHandler = Handler(bgThread!!.looper)
        // Register the surface listener once; every open path funnels through the
        // single-flight maybeOpenCamera(), so duplicate triggers are harmless.
        textureView.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(s: SurfaceTexture, w: Int, h: Int) { maybeOpenCamera() }
            override fun onSurfaceTextureSizeChanged(s: SurfaceTexture, w: Int, h: Int) {}
            override fun onSurfaceTextureDestroyed(s: SurfaceTexture) = true
            override fun onSurfaceTextureUpdated(s: SurfaceTexture) {}
        }
        maybeOpenCamera()
    }

    override fun onPause() {
        paused = true
        closeCamera()
        bgThread?.quitSafely()
        bgThread = null
        bgHandler = null
        super.onPause()
    }

    /** Idempotent, single-flight camera open. Safe to call from any callback. */
    private fun maybeOpenCamera() {
        if (paused || opening || cameraDevice != null) return
        if (!textureView.isAvailable) return
        if (bgHandler == null) return
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return
        val mgr = getSystemService(Context.CAMERA_SERVICE) as CameraManager
        try {
            val id = pickBackCamera(mgr) ?: run { hint.text = "No camera found"; return }
            cameraId = id
            val chars = mgr.getCameraCharacteristics(id)
            val map = chars.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
            previewSize = chooseSize(map?.getOutputSizes(ImageReader::class.java))
            imageReader = ImageReader.newInstance(previewSize.width, previewSize.height, android.graphics.ImageFormat.YUV_420_888, 2).apply {
                setOnImageAvailableListener({ r -> onFrame(r) }, bgHandler)
            }
            opening = true
            mgr.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    opening = false
                    // If we paused/finished while opening, don't touch the camera.
                    if (paused || isFinishing) { device.close(); cameraDevice = null; return }
                    cameraDevice = device
                    startPreview()
                }
                override fun onDisconnected(device: CameraDevice) { opening = false; device.close(); cameraDevice = null }
                override fun onError(device: CameraDevice, error: Int) { opening = false; device.close(); cameraDevice = null; runOnUiThread { hint.text = "Camera error $error" } }
            }, bgHandler)
        } catch (e: Exception) {
            opening = false
            runOnUiThread { hint.text = "Camera unavailable: ${e.message}" }
        }
    }

    private fun startPreview() {
        val device = cameraDevice ?: return
        val texture = textureView.surfaceTexture ?: return
        try {
            texture.setDefaultBufferSize(previewSize.width, previewSize.height)
            val previewSurface = Surface(texture)
            val readerSurface = imageReader!!.surface
            val req = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                addTarget(previewSurface)
                addTarget(readerSurface)
                set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
            }
            @Suppress("DEPRECATION")
            device.createCaptureSession(listOf(previewSurface, readerSurface), object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(s: CameraCaptureSession) {
                    if (cameraDevice == null || paused) return
                    session = s
                    runCatching { s.setRepeatingRequest(req.build(), null, bgHandler) }
                }
                override fun onConfigureFailed(s: CameraCaptureSession) { runOnUiThread { hint.text = "Camera config failed" } }
            }, bgHandler)
        } catch (e: Exception) {
            // Device disconnected/closed between open and preview — bail quietly
            // instead of crashing (the CAMERA_DISCONNECTED case).
            runOnUiThread { hint.text = "Camera unavailable: ${e.message}" }
        }
    }

    private fun onFrame(rdr: ImageReader) {
        val image = rdr.acquireLatestImage() ?: return
        // Only one decode in flight; if we're busy or already done, drop the frame.
        if (done.get() || !decoding.compareAndSet(false, true)) {
            image.close()
            return
        }
        try {
            val w = image.width
            val h = image.height
            val plane = image.planes[0] // Y (luminance) plane is all ZXing needs
            val buffer = plane.buffer
            val rowStride = plane.rowStride
            // Copy the Y plane into a tight width*height buffer, dropping any
            // per-row stride padding the camera HAL may insert.
            val data = ByteArray(w * h)
            if (rowStride == w) {
                buffer.get(data, 0, w * h)
            } else {
                val row = ByteArray(rowStride)
                for (y in 0 until h) {
                    buffer.get(row, 0, minOf(rowStride, buffer.remaining()))
                    System.arraycopy(row, 0, data, y * w, w)
                }
            }
            image.close()
            val text = QrDecode.decodeLuminance(data, w, h)
            if (text != null) succeed(text)
        } catch (_: Exception) {
            runCatching { image.close() }
        } finally {
            decoding.set(false)
        }
    }

    private fun succeed(text: String) {
        if (!done.compareAndSet(false, true)) return
        runOnUiThread {
            setResult(RESULT_OK, Intent().putExtra(EXTRA_RESULT, text))
            finish()
        }
    }

    private fun cancel() {
        setResult(RESULT_CANCELED)
        finish()
    }

    private fun closeCamera() {
        opening = false
        runCatching { session?.close() }; session = null
        runCatching { cameraDevice?.close() }; cameraDevice = null
        runCatching { imageReader?.close() }; imageReader = null
    }

    private fun pickBackCamera(mgr: CameraManager): String? {
        var firstFacing: String? = null
        for (id in mgr.cameraIdList) {
            val facing = mgr.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING)
            if (firstFacing == null) firstFacing = id
            if (facing == CameraCharacteristics.LENS_FACING_BACK) return id
        }
        return firstFacing // fall back to whatever exists (e.g. emulator's front cam)
    }

    /** Largest output size not exceeding TARGET, to bound per-frame decode cost. */
    private fun chooseSize(sizes: Array<Size>?): Size {
        if (sizes == null || sizes.isEmpty()) return TARGET
        val fit = sizes.filter { it.width <= TARGET.width && it.height <= TARGET.height }
            .maxByOrNull { it.width.toLong() * it.height }
        return fit ?: sizes.minByOrNull { it.width.toLong() * it.height } ?: TARGET
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
}
