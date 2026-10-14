package io.passwordmanager.password_manager

import android.app.PendingIntent
import android.content.Intent
import android.net.Uri
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.*
import java.util.UUID

/** No plaintext credential index: selection continues inside the unlocked vault. */
class ByteLockerProvider : CredentialProviderService() {
    private fun pending(): PendingIntent {
        val id = UUID.randomUUID().toString()
        val intent = Intent(this, PasskeyActivity::class.java).setData(Uri.parse("bytelocker://provider/$id"))
        return PendingIntent.getActivity(this, id.hashCode(), intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }
    override fun onBeginCreateCredentialRequest(request: BeginCreateCredentialRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>) {
        if (cancellationSignal.isCanceled) return
        if (request !is BeginCreatePublicKeyCredentialRequest) { callback.onError(CreateCredentialUnknownException()); return }
        callback.onResult(BeginCreateCredentialResponse(listOf(CreateEntry("Vault ByteLocker", pending()))))
    }
    override fun onBeginGetCredentialRequest(request: BeginGetCredentialRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>) {
        if (cancellationSignal.isCanceled) return
        val entries = request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>().take(20).map {
            PublicKeyCredentialEntry(context = this, username = "Vault ByteLocker", pendingIntent = pending(),
                beginGetPublicKeyCredentialOption = it, displayName = "Sblocca e scegli una passkey")
        }
        if (entries.isEmpty()) callback.onError(GetCredentialUnknownException())
        else callback.onResult(BeginGetCredentialResponse(entries))
    }
    override fun onClearCredentialStateRequest(request: ProviderClearCredentialStateRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>) {
        callback.onResult(null)
    }
}

/** Only the system-held explicit PendingIntent can launch this internal activity. */
class PasskeyActivity : MainActivity()
