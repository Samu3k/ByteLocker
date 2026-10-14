package io.passwordmanager.password_manager

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject
import java.net.InetAddress
import java.net.URL
import java.io.ByteArrayOutputStream
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

class NativePasskeys(private val activity: Activity) {
    private data class Operation(val id: String, val create: Boolean, val options: JSONObject,
        val origin: String, val hash: ByteArray?, val started: Long = SystemClock.elapsedRealtime()) {
        var verified = false
        var material: JSONObject? = null
        var response: String? = null
    }
    private val worker = Executors.newSingleThreadExecutor()
    private var pending = CompletableFuture.completedFuture<Operation?>(null)

    fun receive(intent: Intent) {
        if (activity !is PasskeyActivity || Build.VERSION.SDK_INT < 34) return
        val future = CompletableFuture<Operation?>()
        pending = future
        worker.execute {
            try {
                val create = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
                val get = if (create == null) PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) else null
                val raw: String; val isCreate: Boolean; val hash: ByteArray?; val app: CallingAppInfo
                if (create != null && create.callingRequest is CreatePublicKeyCredentialRequest) {
                    val request = create.callingRequest as CreatePublicKeyCredentialRequest
                    raw = request.requestJson; hash = request.clientDataHash; app = create.callingAppInfo; isCreate = true
                } else if (get != null) {
                    val request = get.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().single()
                    raw = request.requestJson; hash = request.clientDataHash; app = get.callingAppInfo; isCreate = false
                } else { error("Unsupported provider request") }
                val options = PasskeyEngine.options(raw, isCreate)
                val origin = validateCaller(app, PasskeyEngine.rp(options, isCreate), hash)
                future.complete(Operation(UUID.randomUUID().toString(), isCreate, options, origin, hash))
            } catch (error: Exception) { future.completeExceptionally(error) }
        }
    }

    private fun validateCaller(app: CallingAppInfo, rp: String, hash: ByteArray?): String {
        val allowlist = activity.assets.open("privileged_apps.json").bufferedReader().use { it.readText() }
        val browserOrigin = app.getOrigin(allowlist)
        if (browserOrigin != null) {
            // Related-origin requests are not enabled by this initial profile.
            return PasskeyEngine.browserOrigin(browserOrigin, rp, hash)
        }
        require(hash == null)
        val signers = app.signingInfo.apkContentsSigners
        require(signers.size == 1)
        val digest = PasskeyEngine.hash(signers[0].toByteArray())
        val fingerprint = digest.joinToString(":") { "%02X".format(it) }
        val addresses = InetAddress.getAllByName(rp)
        require(addresses.isNotEmpty() && addresses.none { it.isAnyLocalAddress || it.isLoopbackAddress || it.isLinkLocalAddress || it.isSiteLocalAddress || it.isMulticastAddress })
        val connection = URL("https://$rp/.well-known/assetlinks.json").openConnection() as HttpsURLConnection
        connection.instanceFollowRedirects = false
        connection.connectTimeout = 5000; connection.readTimeout = 5000
        connection.setRequestProperty("Accept", "application/json")
        try {
            val deadline = SystemClock.elapsedRealtime() + 10000
            require(connection.responseCode == 200 && connection.contentLengthLong <= 262144)
            val bytes = connection.inputStream.use { stream ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val remaining = deadline - SystemClock.elapsedRealtime(); require(remaining > 0)
                    connection.readTimeout = minOf(5000, remaining.toInt())
                    val read = stream.read(buffer)
                    if (read < 0) break
                    require(output.size() + read <= 262144)
                    output.write(buffer, 0, read)
                }
                output.toByteArray()
            }
            require(bytes.size <= 262144)
            require(PasskeyEngine.assetLinks(bytes.toString(Charsets.UTF_8), app.packageName, fingerprint))
        } finally { connection.disconnect() }
        return "android:apk-key-hash:${PasskeyEngine.encode(digest)}"
    }

    private fun active(id: String): Operation {
        val operation = pending.getNow(null) ?: error("Missing request")
        require(operation.id == id && SystemClock.elapsedRealtime() - operation.started <= 300000)
        return operation
    }
    fun handle(call: MethodCall, result: MethodChannel.Result) {
        if (call.method == "pending") {
            pending.whenComplete { operation, error -> activity.runOnUiThread {
                if (error != null) result.error("UNSUPPORTED", "Richiesta passkey non supportata o chiamante non verificato", null)
                else if (operation == null) result.success(null)
                else result.success(mapOf("request_id" to operation.id, "operation" to if (operation.create) "create" else "get",
                    "rp_id" to PasskeyEngine.rp(operation.options, operation.create),
                    "user_name" to if (operation.create) operation.options.getJSONObject("user").getString("name") else "",
                    "display_name" to if (operation.create) operation.options.getJSONObject("user").getString("displayName") else "",
                    "allowed_ids" to PasskeyEngine.ids(operation.options, if (operation.create) "excludeCredentials" else "allowCredentials")))
            } }
            return
        }
        try {
            if (call.method == "cancel") {
                pending = CompletableFuture.completedFuture(null)
                result.success(null); activity.setResult(Activity.RESULT_CANCELED); if (activity is PasskeyActivity) activity.finish()
                return
            }
            val id = call.argument<String>("request_id")!!
            val operation = active(id)
            when (call.method) {
                "verified" -> { require(activity.hasWindowFocus() && !activity.isFinishing); operation.verified = true; result.success(null) }
                "create" -> {
                    require(operation.create && operation.verified && activity.hasWindowFocus())
                    val existing = call.argument<List<String>>("existing_ids")!!
                    require(existing.size <= 10000 && PasskeyEngine.ids(operation.options, "excludeCredentials").none { it in existing })
                    if (operation.material == null) {
                        val created = PasskeyEngine.create(operation.options, operation.origin, operation.hash)
                        operation.material = created.first; operation.response = created.second
                    }
                    result.success(operation.material.toString())
                }
                "sign" -> {
                    require(!operation.create && operation.verified && activity.hasWindowFocus())
                    val material = call.argument<String>("material")!!
                    require(material.length <= 4096)
                    operation.response = PasskeyEngine.assertion(operation.options, operation.origin, operation.hash, JSONObject(material))
                    result.success(null)
                }
                "complete" -> {
                    require(operation.verified && activity.hasWindowFocus())
                    val response = operation.response ?: error("Missing response")
                    val intent = Intent()
                    if (operation.create) PendingIntentHandler.setCreateCredentialResponse(intent, CreatePublicKeyCredentialResponse(response))
                    else PendingIntentHandler.setGetCredentialResponse(intent, GetCredentialResponse(PublicKeyCredential(response)))
                    pending = CompletableFuture.completedFuture(null)
                    result.success(null); activity.setResult(Activity.RESULT_OK, intent); activity.finish()
                }
                else -> result.notImplemented()
            }
        } catch (_: Exception) { result.error("PASSKEY_FAILED", "Operazione passkey non completata", null) }
    }
    fun lock() { runCatching { pending.getNow(null)?.verified = false } }
    fun close() { lock(); worker.shutdownNow(); pending = CompletableFuture.completedFuture(null) }
}
