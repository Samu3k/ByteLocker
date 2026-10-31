package io.passwordmanager.password_manager

import android.app.Activity
import android.content.Intent
import android.net.Uri
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/** Storage Access Framework: no broad storage permission or secret temp file. */
class ClientFiles(private val activity:Activity) {
    private var pending:MethodChannel.Result? = null
    private var destination:Uri? = null
    private var imported:Uri? = null
    companion object { private const val EXPORT = 0xB170; private const val IMPORT = 0xB171 }
    fun handle(call:MethodCall,result:MethodChannel.Result) {
        try { when(call.method) {
            "installUpdate" -> {
                val file=java.io.File(call.arguments as String)
                require(file.canonicalPath.startsWith(activity.cacheDir.canonicalPath+java.io.File.separator)&&file.isFile&&file.length() in 1..(128L*1024*1024))
                val flags=if(android.os.Build.VERSION.SDK_INT>=28)android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES else android.content.pm.PackageManager.GET_SIGNATURES
                val incoming=activity.packageManager.getPackageArchiveInfo(file.path,flags) ?: error("Invalid package")
                val current=activity.packageManager.getPackageInfo(activity.packageName,flags)
                require(incoming.packageName==activity.packageName)
                val incomingVersion=if(android.os.Build.VERSION.SDK_INT>=28)incoming.longVersionCode else incoming.versionCode.toLong()
                val currentVersion=if(android.os.Build.VERSION.SDK_INT>=28)current.longVersionCode else current.versionCode.toLong()
                require(incomingVersion>currentVersion)
                val newSigners=if(android.os.Build.VERSION.SDK_INT>=28)incoming.signingInfo!!.apkContentsSigners else incoming.signatures!!
                val oldSigners=if(android.os.Build.VERSION.SDK_INT>=28)current.signingInfo!!.apkContentsSigners else current.signatures!!
                require(newSigners.size==1&&oldSigners.size==1&&newSigners[0]==oldSigners[0])
                if(android.os.Build.VERSION.SDK_INT>=26&&!activity.packageManager.canRequestPackageInstalls()){
                    activity.startActivity(Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,Uri.parse("package:"+activity.packageName)))
                    result.error("INSTALL_PERMISSION","Allow app updates in Android settings, then try again",null)
                }else{
                    val directory=java.io.File(activity.cacheDir,"updates").apply{mkdirs()}
                    val target=java.io.File(directory,"ByteLocker-update.apk")
                    file.copyTo(target,overwrite=true)
                    val uri=androidx.core.content.FileProvider.getUriForFile(activity,activity.packageName+".updates",target)
                    activity.startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri,"application/vnd.android.package-archive").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
                    result.success(null)
                }
            }
            "chooseCsvImport" -> {
                check(pending==null);imported=null;pending=result
                try { activity.startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE);type="*/*";putExtra(Intent.EXTRA_MIME_TYPES,arrayOf("text/csv","text/plain","application/csv","text/comma-separated-values"))
                },IMPORT) }catch(error:Exception){pending=null;throw error}
            }
            "readCsvImport" -> {
                val selected=imported ?: error("No file")
                check(call.arguments==selected.toString());imported=null
                val output=java.io.ByteArrayOutputStream()
                activity.contentResolver.openInputStream(selected)!!.use { input ->
                    val buffer=ByteArray(32768)
                    try { while(true){val count=input.read(buffer);if(count<0)break;check(output.size()+count<=10*1024*1024);output.write(buffer,0,count)} }
                    finally {buffer.fill(0)}
                }
                val bytes=output.toByteArray()
                try {result.success(bytes)}finally {bytes.fill(0);output.reset()}
            }
            "chooseCsvExport" -> {
                check(pending == null)
                destination = null
                pending = result
                try { activity.startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE); type="text/csv"; putExtra(Intent.EXTRA_TITLE,"ByteLocker-export.csv")
                },EXPORT) } catch(error:Exception) { pending=null;throw error }
            }
            "writeCsvExport" -> {
                val selected = destination ?: error("No destination")
                check(call.argument<String>("destination")==selected.toString())
                val bytes=call.argument<ByteArray>("bytes") ?: error("No data")
                require(bytes.size in 1..(10*1024*1024))
                destination=null
                try { activity.contentResolver.openOutputStream(selected,"wt")!!.use { it.write(bytes); it.flush() }; result.success(null) }
                finally { bytes.fill(0) }
            }
            else -> result.notImplemented()
        }}catch(_:Exception){result.error("FILE_UNAVAILABLE","File operation unavailable",null)}
    }
    fun receive(requestCode:Int,resultCode:Int,data:Intent?):Boolean {
        if(requestCode!=EXPORT&&requestCode!=IMPORT)return false
        val result=pending;pending=null
        if(requestCode==IMPORT){imported=if(resultCode==Activity.RESULT_OK)data?.data else null;result?.success(imported?.toString());return true}
        destination=if(resultCode==Activity.RESULT_OK)data?.data else null
        result?.success(destination?.toString());return true
    }
    fun close(){pending?.error("CANCELLED","File operation cancelled",null);pending=null;destination=null;imported=null}
}
