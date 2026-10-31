package io.passwordmanager.password_manager

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import android.os.Bundle
import android.content.Intent
import android.os.Build
import android.view.WindowManager
import androidx.credentials.CredentialManager

open class MainActivity : FlutterActivity() {
    private lateinit var biometrics: BiometricStore
    private lateinit var passkeys: NativePasskeys
    private lateinit var clipboard: SensitiveClipboard
    private lateinit var clientFiles: ClientFiles
    override fun configureFlutterEngine(engine: FlutterEngine) {
        super.configureFlutterEngine(engine)
        biometrics = BiometricStore(this)
        passkeys = NativePasskeys(this)
        clipboard = SensitiveClipboard(this)
        clientFiles = ClientFiles(this)
        MethodChannel(engine.dartExecutor.binaryMessenger, "bytelocker/files").setMethodCallHandler(clientFiles::handle)
        MethodChannel(engine.dartExecutor.binaryMessenger, "bytelocker/clipboard").setMethodCallHandler(clipboard::handle)
        MethodChannel(engine.dartExecutor.binaryMessenger, "bytelocker/security").setMethodCallHandler { call, result ->
            if (call.method == "providerSettings") {
                try {
                    check(Build.VERSION.SDK_INT >= 34)
                    CredentialManager.create(this).createSettingsPendingIntent().send()
                    result.success(null)
                } catch (_: Exception) { result.error("UNAVAILABLE", "Impostazioni non disponibili", null) }
            } else biometrics.handle(call, result)
        }
        MethodChannel(engine.dartExecutor.binaryMessenger, "bytelocker/passkeys").setMethodCallHandler(passkeys::handle)
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        passkeys.receive(intent)
    }
    override fun onStop() { biometrics.cancel(); passkeys.lock(); super.onStop() }
    override fun onResume() { super.onResume(); if (::clipboard.isInitialized) clipboard.expire() }
    override fun onActivityResult(requestCode:Int,resultCode:Int,data:Intent?) {
        if(::clientFiles.isInitialized && clientFiles.receive(requestCode,resultCode,data))return
        super.onActivityResult(requestCode,resultCode,data)
    }
    override fun onDestroy() { biometrics.cancel(); passkeys.close(); if (::clipboard.isInitialized) clipboard.close(); if(::clientFiles.isInitialized)clientFiles.close(); super.onDestroy() }
}
