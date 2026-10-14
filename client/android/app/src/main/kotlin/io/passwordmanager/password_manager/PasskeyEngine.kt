package io.passwordmanager.password_manager

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.AlgorithmParameters
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.net.URI

/** ES256 synced credentials: zero counter, backup eligible/backed up, none attestation. */
object PasskeyEngine {
    fun browserOrigin(origin: String, rp: String, hash: ByteArray?): String {
        require(hash != null && hash.size == 32)
        val uri = URI(origin)
        require(uri.scheme == "https" && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null &&
            (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") && (uri.port == -1 || uri.port == 443) &&
            uri.host != null && (uri.host == rp || uri.host.endsWith(".$rp")))
        return origin
    }
    fun assetLinks(raw: String, packageName: String, fingerprint: String): Boolean {
        val links = JSONArray(raw); require(links.length() <= 256)
        return (0 until links.length()).any { index ->
            val entry = links.getJSONObject(index)
            val relations = entry.optJSONArray("relation") ?: return@any false
            val target = entry.optJSONObject("target") ?: return@any false
            val fingerprints = target.optJSONArray("sha256_cert_fingerprints") ?: return@any false
            target.optString("namespace") == "android_app" && target.optString("package_name") == packageName &&
                (0 until relations.length()).any { relations.optString(it) == "delegate_permission/common.get_login_creds" } &&
                (0 until fingerprints.length()).any { fingerprints.optString(it).equals(fingerprint, ignoreCase = true) }
        }
    }
    fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun decode(value: String, max: Int = 1024): ByteArray {
        require(value.isNotEmpty() && value.length <= (max + 2) / 3 * 4 && value.matches(Regex("[A-Za-z0-9_-]+")))
        val bytes = Base64.getUrlDecoder().decode(value)
        require(bytes.size <= max && encode(bytes) == value)
        return bytes
    }
    fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    fun rp(options: JSONObject, create: Boolean): String {
        val rp = if (create) options.getJSONObject("rp").getString("id") else options.getString("rpId")
        require(rp.length <= 253 && rp.contains('.') && !rp.contains("..") &&
            rp.split('.').all { it.length in 1..63 && it.matches(Regex("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) } &&
            !rp.matches(Regex("[0-9.]+")))
        return rp
    }
    fun options(raw: String, create: Boolean): JSONObject {
        require(raw.toByteArray(Charsets.UTF_8).size <= 65536)
        val json = JSONObject(raw)
        rp(json, create)
        require(decode(json.getString("challenge")).size >= 16)
        val extensions = json.optJSONObject("extensions") ?: JSONObject()
        require(extensions.keys().asSequence().all { create && it == "credProps" && extensions.get(it) == true })
        if (create) {
            val user = json.getJSONObject("user")
            decode(user.getString("id"), 64)
            require(user.getString("name").toByteArray(Charsets.UTF_8).size in 1..256)
            require(user.getString("displayName").toByteArray(Charsets.UTF_8).size in 1..256)
            val algorithms = json.getJSONArray("pubKeyCredParams")
            require(algorithms.length() in 1..100 && (0 until algorithms.length()).any {
                val algorithm = algorithms.getJSONObject(it)
                algorithm.optString("type") == "public-key" && algorithm.optInt("alg") == -7
            })
            require(json.optString("attestation", "none") == "none")
            val selection = json.optJSONObject("authenticatorSelection")
            require(selection?.optString("authenticatorAttachment", "platform") != "cross-platform")
            ids(json, "excludeCredentials")
        } else { ids(json, "allowCredentials") }
        return json
    }
    fun ids(options: JSONObject, field: String): List<String> {
        val array = options.optJSONArray(field) ?: return emptyList()
        require(array.length() <= 100)
        return (0 until array.length()).map {
            val item = array.getJSONObject(it)
            require(item.getString("type") == "public-key")
            item.getString("id").also { id -> decode(id) }
        }
    }
    private fun client(options: JSONObject, origin: String, create: Boolean, clientHash: ByteArray?): Pair<ByteArray, ByteArray> {
        if (clientHash != null) { require(clientHash.size == 32); return "{}".toByteArray() to clientHash.copyOf() }
        val data = JSONObject().put("type", if (create) "webauthn.create" else "webauthn.get")
            .put("challenge", options.getString("challenge")).put("origin", origin).put("crossOrigin", false)
            .toString().toByteArray(Charsets.UTF_8)
        return data to hash(data)
    }
    private fun auth(rp: String, flags: Int) = hash(rp.toByteArray(Charsets.UTF_8)) + byteArrayOf(flags.toByte(), 0, 0, 0, 0)
    private fun coordinate(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        val unsigned = if (bytes.size == 33 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, 33) else bytes
        require(unsigned.size <= 32)
        return ByteArray(32 - unsigned.size) + unsigned
    }
    fun create(options: JSONObject, origin: String, clientHash: ByteArray?): Pair<JSONObject, String> {
        val rp = rp(options, true)
        val user = options.getJSONObject("user")
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        val keys = generator.generateKeyPair()
        val public = keys.public as ECPublicKey
        val id = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val cose = cbor(linkedMapOf(1 to 2, 3 to -7, -1 to 1, -2 to coordinate(public.w.affineX), -3 to coordinate(public.w.affineY)))
        val auth = auth(rp, 0x5d) + ByteArray(16) + byteArrayOf(0, 32) + id + cose
        val attestation = cbor(linkedMapOf("fmt" to "none", "attStmt" to emptyMap<Any, Any>(), "authData" to auth))
        val client = client(options, origin, true, clientHash)
        val material = JSONObject().put("algorithm", -7).put("rp_id", rp)
            .put("user_id", user.getString("id")).put("user_name", user.getString("name"))
            .put("display_name", user.getString("displayName")).put("credential_id", encode(id))
            .put("private_key", encode(keys.private.encoded)).put("public_key", encode(keys.public.encoded))
        val extensions = JSONObject()
        if (options.optJSONObject("extensions")?.optBoolean("credProps") == true) extensions.put("credProps", JSONObject().put("rk", true))
        val response = credential(encode(id)).put("clientExtensionResults", extensions).put("response", JSONObject()
            .put("clientDataJSON", encode(client.first)).put("attestationObject", encode(attestation))
            .put("transports", JSONArray(listOf("internal"))).put("publicKeyAlgorithm", -7)
            .put("publicKey", encode(keys.public.encoded)).put("authenticatorData", encode(auth)))
        return material to response.toString()
    }
    fun assertion(options: JSONObject, origin: String, clientHash: ByteArray?, material: JSONObject): String {
        val rp = rp(options, false)
        require(material.getInt("algorithm") == -7 && material.getString("rp_id") == rp)
        val id = material.getString("credential_id"); require(decode(id).size == 32)
        val allowed = ids(options, "allowCredentials"); require(allowed.isEmpty() || id in allowed)
        val userId = material.getString("user_id"); decode(userId, 64)
        val bytes = decode(material.getString("private_key"), 512)
        try {
            val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(bytes)) as ECPrivateKey
            val public = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(decode(material.getString("public_key"), 256))) as ECPublicKey
            val expected = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
            require(key.params.curve == expected.curve && key.params.generator == expected.generator && key.params.order == expected.order && key.params.cofactor == expected.cofactor &&
                public.params.curve == expected.curve && public.params.generator == expected.generator && public.params.order == expected.order && public.params.cofactor == expected.cofactor &&
                key.s.signum() > 0 && key.s < expected.order)
            val data = auth(rp, 0x1d)
            val client = client(options, origin, false, clientHash)
            val signed = data + client.second
            val signature = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(signed); sign() }
            check(Signature.getInstance("SHA256withECDSA").run { initVerify(public); update(signed); verify(signature) })
            return credential(id).put("clientExtensionResults", JSONObject()).put("response", JSONObject()
                .put("clientDataJSON", encode(client.first)).put("authenticatorData", encode(data))
                .put("signature", encode(signature)).put("userHandle", userId)).toString()
        } finally { bytes.fill(0) }
    }
    private fun credential(id: String) = JSONObject().put("id", id).put("rawId", id).put("type", "public-key").put("authenticatorAttachment", "platform")
    private fun head(major: Int, size: Int): ByteArray {
        require(size >= 0 && size <= 65535)
        return if (size < 24) byteArrayOf(((major shl 5) or size).toByte())
        else if (size <= 255) byteArrayOf(((major shl 5) or 24).toByte(), size.toByte())
        else byteArrayOf(((major shl 5) or 25).toByte(), (size shr 8).toByte(), size.toByte())
    }
    internal fun cbor(value: Any): ByteArray = when (value) {
        is Int -> if (value >= 0) head(0, value) else head(1, -1 - value)
        is ByteArray -> head(2, value.size) + value
        is String -> value.toByteArray(Charsets.UTF_8).let { head(3, it.size) + it }
        is Map<*, *> -> head(5, value.size) + value.entries.fold(ByteArray(0)) { bytes, entry -> bytes + cbor(entry.key!!) + cbor(entry.value!!) }
        else -> error("Unsupported CBOR value")
    }
}
