package io.passwordmanager.password_manager

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.UUID

class SensitiveClipboard(context: Context) {
    private val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    private val handler = Handler(Looper.getMainLooper())
    private var owner: String? = null
    private var deadline = 0L
    private val cleanup = Runnable { expire() }

    fun handle(call: MethodCall, result: MethodChannel.Result) {
        try {
            when (call.method) {
                "copy" -> {
                    val text = call.arguments as? String ?: error("Invalid value")
                    require(text.length in 1..65536)
                    val label = "ByteLocker:" + UUID.randomUUID().toString()
                    val clip = ClipData.newPlainText(label, text)
                    clip.description.extras = PersistableBundle().apply {
                        putBoolean("android.content.extra.IS_SENSITIVE", true)
                    }
                    manager.setPrimaryClip(clip)
                    owner = label
                    deadline = SystemClock.elapsedRealtime() + 60_000L
                    handler.removeCallbacks(cleanup)
                    handler.postDelayed(cleanup, 60_000L)
                    result.success(null)
                }
                "clear" -> { clear(); result.success(null) }
                else -> result.notImplemented()
            }
        } catch (_: Exception) { result.error("UNAVAILABLE", "Appunti non disponibili", null) }
    }

    fun expire() { if (owner != null && SystemClock.elapsedRealtime() >= deadline) clear() }
    fun clear() {
        deadline = 0L
        val label = owner ?: return
        try {
            // Android may deny access while backgrounded. Retain the marker
            // for another attempt on resume; never read unrelated text.
            val description = manager.primaryClipDescription ?: return
            if (description.label?.toString() == label) manager.clearPrimaryClip()
            owner = null
            handler.removeCallbacks(cleanup)
        } catch (_: Exception) { /* Retry on resume when the OS grants access. */ }
    }
    fun close() { clear(); handler.removeCallbacks(cleanup) }
}
