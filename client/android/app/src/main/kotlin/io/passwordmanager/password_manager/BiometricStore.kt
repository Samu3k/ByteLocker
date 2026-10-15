package io.passwordmanager.password_manager

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/** The system prompt authorizes the exact AES-GCM operation, not a UI boolean. */
class BiometricStore(private val activity: Activity) {
    private val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private var cancellation: CancellationSignal? = null
    private val prefs = activity.getSharedPreferences("bytelocker_client", Activity.MODE_PRIVATE)
    private fun linkedFile() = AtomicFile(File(activity.noBackupFilesDir, "linked-account.json"))

    private fun linkedAccount(): JSONObject? {
        val target = linkedFile()
        if (!target.baseFile.exists()) return null
        require(target.baseFile.length() in 1..4096)
        return JSONObject(target.readFully().toString(Charsets.UTF_8))
    }

    private fun saveLinkedAccount(arguments: Any?) {
        val value = arguments as Map<*, *>
        val fields = listOf("origin", "server_id", "email", "account_id", "vault_id")
        require(value.size == 6 && value["schema"] == 1 && fields.all { value[it] is String && (value[it] as String).length in 1..512 })
        val json = JSONObject().put("schema", 1)
        fields.forEach { json.put(it, value[it]) }
        val bytes = json.toString().toByteArray(Charsets.UTF_8)
        require(bytes.size <= 4096)
        val target = linkedFile()
        val stream = target.startWrite()
        try { stream.write(bytes); target.finishWrite(stream) }
        catch (error: Exception) { target.failWrite(stream); throw error }
    }
    private fun slot(value: String): String {
        require(value.length in 1..1024)
        return MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
    private fun file(id: String): AtomicFile {
        val directory = File(activity.noBackupFilesDir, "biometric").apply { mkdirs() }
        return AtomicFile(File(directory, "$id.json"))
    }
    private fun read(id: String): JSONObject? {
        val file = file(id)
        if (!file.baseFile.exists()) return null
        require(file.baseFile.length() <= 8192)
        return JSONObject(file.readFully().toString(Charsets.UTF_8))
    }
    private fun delete(id: String) {
        val old = runCatching { read(id)?.getString("alias") }.getOrNull()
        file(id).delete()
        if (old != null && old.startsWith("bytelocker.bio.$id.")) keys.deleteEntry(old)
    }
    private fun available(): Boolean = Build.VERSION.SDK_INT >= 30 &&
        activity.getSystemService(BiometricManager::class.java).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    fun handle(call: MethodCall, result: MethodChannel.Result) {
        try {
            when (call.method) {
                "linkedAccount" -> {
                    val value = linkedAccount()
                    result.success(value?.let { json -> json.keys().asSequence().associateWith { json.get(it) } })
                }
                "saveLinkedAccount" -> { saveLinkedAccount(call.arguments); result.success(null) }
                "status" -> result.success(mapOf("theme" to prefs.getString("theme", "dark"), "language" to prefs.getString("language", "it"), "biometrics" to available(), "passkeys" to (Build.VERSION.SDK_INT >= 34)))
                "language" -> {
                    val language = call.arguments as String
                    require(language in listOf("it", "en", "system"))
                    check(prefs.edit().putString("language", language).commit())
                    result.success(null)
                }
                "theme" -> {
                    val theme = call.arguments as String
                    require(theme in listOf("dark", "light", "system"))
                    check(prefs.edit().putString("theme", theme).commit())
                    result.success(null)
                }
                "enrolled" -> result.success(read(slot(call.arguments as String)) != null)
                "remove" -> { check(cancellation == null); delete(slot(call.arguments as String)); result.success(null) }
                "enroll" -> {
                    check(available() && cancellation == null)
                    val id = slot(call.argument<String>("slot")!!)
                    val payload = call.argument<ByteArray>("payload")!!.copyOf()
                    require(payload.size in 1..4096)
                    enroll(id, payload, result)
                }
                "unlock" -> {
                    check(available() && cancellation == null)
                    unlock(slot(call.arguments as String), result)
                }
                else -> result.notImplemented()
            }
        } catch (_: Exception) { result.error("UNAVAILABLE", "Operazione protetta non disponibile", null) }
    }

    private fun enroll(id: String, payload: ByteArray, result: MethodChannel.Result) {
        val alias = "bytelocker.bio.$id.${UUID.randomUUID()}"
        try {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true).build())
            val key = generator.generateKey()
            val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
            @Suppress("DEPRECATION")
            check(info.isInsideSecureHardware)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
            prompt(cipher, result, onFailure = { payload.fill(0); keys.deleteEntry(alias) }) { authenticated ->
                try {
                    // Auth-per-use keys authorize update/finish only after the prompt.
                    authenticated.updateAAD(aad(id))
                    val encrypted = authenticated.doFinal(payload)
                    val json = JSONObject().put("alias", alias).put("iv", encode(authenticated.iv)).put("data", encode(encrypted))
                    val old = runCatching { read(id)?.getString("alias") }.getOrNull()
                    val target = file(id)
                    val stream = target.startWrite()
                    try { stream.write(json.toString().toByteArray(Charsets.UTF_8)); target.finishWrite(stream) }
                    catch (error: Exception) { target.failWrite(stream); throw error }
                    if (old != null && old.startsWith("bytelocker.bio.$id.")) runCatching { keys.deleteEntry(old) }
                    null
                } catch (error: Exception) { keys.deleteEntry(alias); throw error }
                finally { payload.fill(0) }
            }
        } catch (error: Exception) { payload.fill(0); keys.deleteEntry(alias); throw error }
    }

    private fun unlock(id: String, result: MethodChannel.Result) {
        val stored = read(id) ?: error("Missing enrollment")
        val alias = stored.getString("alias")
        require(alias.startsWith("bytelocker.bio.$id."))
        val cipher: Cipher
        val encrypted = decode(stored.getString("data"))
        try {
            val iv = decode(stored.getString("iv")); require(iv.size == 12 && encrypted.size in 17..4112)
            val key = keys.getKey(alias, null) as SecretKey
            cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }
        } catch (error: Exception) { delete(id); throw error }
        prompt(cipher, result) { authenticated -> authenticated.updateAAD(aad(id)); authenticated.doFinal(encrypted) }
    }

    private fun prompt(cipher: Cipher, result: MethodChannel.Result, onFailure: () -> Unit = {}, action: (Cipher) -> Any?) {
        val signal = CancellationSignal()
        cancellation = signal
        var completed = false
        try {
        val selectedLanguage = prefs.getString("language", "it")
        val english = selectedLanguage == "en" || (selectedLanguage == "system" && java.util.Locale.getDefault().language == "en")
        val prompt = BiometricPrompt.Builder(activity).setTitle(if (english) "Unlock ByteLocker" else "Sblocca ByteLocker")
            .setSubtitle(if (english) "Authorize secure access on this device" else "Autorizza l’accesso protetto su questo dispositivo")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton(if (english) "Cancel" else "Annulla", activity.mainExecutor) { _, _ -> signal.cancel() }.build()
        prompt.authenticate(BiometricPrompt.CryptoObject(cipher), signal, activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    if (completed) return
                    completed = true
                    cancellation = null; runCatching { onFailure() }; result.error("CANCELLED", "Autenticazione non completata", null)
                }
                override fun onAuthenticationSucceeded(auth: BiometricPrompt.AuthenticationResult) {
                    if (completed) return
                    completed = true
                    cancellation = null
                    try {
                        val value = action(auth.cryptoObject!!.cipher!!)
                        try { result.success(value) } finally { if (value is ByteArray) value.fill(0) }
                    } catch (_: Exception) { runCatching { onFailure() }; result.error("INVALIDATED", "Accesso protetto non disponibile", null) }
                }
            })
        } catch (_: Exception) {
            if (!completed) {
                completed = true
                cancellation = null
                runCatching { onFailure() }
                result.error("UNAVAILABLE", "Dialogo biometrico non disponibile", null)
            }
        }
    }
    fun cancel() { cancellation?.cancel() }
    private fun aad(id: String) = "ByteLocker/biometric/v1/$id".toByteArray(Charsets.UTF_8)
    private fun encode(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun decode(value: String) = Base64.decode(value, Base64.NO_WRAP)
}
