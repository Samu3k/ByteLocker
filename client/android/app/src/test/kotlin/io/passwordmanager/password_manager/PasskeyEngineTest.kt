package io.passwordmanager.password_manager

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class PasskeyEngineTest {
    private fun create() = JSONObject().put("rp", JSONObject().put("id", "example.com").put("name", "Example"))
        .put("challenge", PasskeyEngine.encode(ByteArray(32) { it.toByte() }))
        .put("user", JSONObject().put("id", PasskeyEngine.encode(byteArrayOf(1, 2, 3))).put("name", "alice").put("displayName", "Alice"))
        .put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
    private fun get(id: String? = null) = JSONObject().put("rpId", "example.com")
        .put("challenge", PasskeyEngine.encode(ByteArray(32) { (it + 1).toByte() })).apply {
            if (id != null) put("allowCredentials", JSONArray().put(JSONObject().put("type", "public-key").put("id", id)))
        }
    @Test fun registrationAndAssertionAreVerifiableWithIndependentJcaVerifier() {
        val options = PasskeyEngine.options(create().toString(), true)
        val (material, raw) = PasskeyEngine.create(options, "https://example.com", null)
        val response = JSONObject(raw)
        assertEquals("public-key", response.getString("type"))
        assertEquals(material.getString("credential_id"), response.getString("id"))
        val auth = PasskeyEngine.decode(response.getJSONObject("response").getString("authenticatorData"))
        assertArrayEquals(PasskeyEngine.hash("example.com".toByteArray()), auth.copyOfRange(0, 32))
        assertEquals(0x5d, auth[32].toInt() and 255)
        assertArrayEquals(ByteArray(4), auth.copyOfRange(33, 37))
        assertArrayEquals(ByteArray(16), auth.copyOfRange(37, 53))
        assertEquals(32, auth[54].toInt())
        assertArrayEquals(PasskeyEngine.decode(response.getString("id")), auth.copyOfRange(55, 87))
        assertEquals(0xa5, auth[87].toInt() and 255) // five-entry COSE EC2 map
        val assertion = JSONObject(PasskeyEngine.assertion(get(response.getString("id")), "https://example.com", null, material)).getJSONObject("response")
        val data = PasskeyEngine.decode(assertion.getString("authenticatorData"))
        val client = PasskeyEngine.decode(assertion.getString("clientDataJSON"))
        assertEquals("webauthn.get", JSONObject(client.toString(Charsets.UTF_8)).getString("type"))
        assertEquals(0x1d, data[32].toInt() and 255)
        val public = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(PasskeyEngine.decode(material.getString("public_key"))))
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(public); verifier.update(data + PasskeyEngine.hash(client))
        assertTrue(verifier.verify(PasskeyEngine.decode(assertion.getString("signature"))))
        val (_, second) = PasskeyEngine.create(options, "https://example.com", null)
        assertNotEquals(response.getString("id"), JSONObject(second).getString("id"))
    }
    @Test fun browserClientDataHashIsSignedAndNeverRecomputed() {
        val (material, _) = PasskeyEngine.create(create(), "https://example.com", ByteArray(32) { 7 })
        val clientHash = ByteArray(32) { 9 }
        val assertion = JSONObject(PasskeyEngine.assertion(get(), "https://example.com", clientHash, material)).getJSONObject("response")
        assertEquals("{}", PasskeyEngine.decode(assertion.getString("clientDataJSON")).toString(Charsets.UTF_8))
        val public = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(PasskeyEngine.decode(material.getString("public_key"))))
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(public); verifier.update(PasskeyEngine.decode(assertion.getString("authenticatorData")) + clientHash)
        assertTrue(verifier.verify(PasskeyEngine.decode(assertion.getString("signature"))))
    }
    @Test fun rejectsWrongRpIdsCredentialsKeysAndUnsupportedFeatures() {
        val (material, _) = PasskeyEngine.create(create(), "https://example.com", null)
        fun reject(action: () -> Unit) { try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { } }
        reject { PasskeyEngine.assertion(get().put("rpId", "other.example"), "https://other.example", null, material) }
        reject { PasskeyEngine.assertion(get(PasskeyEngine.encode(ByteArray(32))), "https://example.com", null, material) }
        reject { PasskeyEngine.options(create().put("attestation", "direct").toString(), true) }
        reject { PasskeyEngine.options(create().put("extensions", JSONObject().put("prf", JSONObject())).toString(), true) }
        reject { PasskeyEngine.options(get().put("challenge", "short").toString(), false) }
        reject { PasskeyEngine.options(get().put("rpId", "127.0.0.1").toString(), false) }
        reject { PasskeyEngine.options(get().put("rpId", "example.com.evil/").toString(), false) }
        reject { PasskeyEngine.decode("AA=") }
        reject { PasskeyEngine.decode("AB") }
    }
    @Test fun browserOriginsRejectDomainSpoofsAndInsecureOrAmbiguousUrls() {
        val hash = ByteArray(32)
        assertEquals("https://login.example.com", PasskeyEngine.browserOrigin("https://login.example.com", "example.com", hash))
        for (origin in listOf("https://example.com.evil.test", "https://fakeexample.com", "http://example.com", "https://example.com@evil.test", "https://example.com/path", "https://example.com?x=1", "https://example.com#fragment", "https://example.com:8443")) {
            try { PasskeyEngine.browserOrigin(origin, "example.com", hash); fail("Expected rejected origin") } catch (_: IllegalArgumentException) { }
        }
        try { PasskeyEngine.browserOrigin("https://example.com", "example.com", null); fail("Expected missing hash rejection") } catch (_: IllegalArgumentException) { }
    }
    @Test fun nativeAssetLinksBindPackageCertificateAndCredentialRelation() {
        val raw = """[{"relation":["delegate_permission/common.get_login_creds"],"target":{"namespace":"android_app","package_name":"example.app","sha256_cert_fingerprints":["AA:BB"]}}]"""
        assertTrue(PasskeyEngine.assetLinks(raw, "example.app", "AA:BB"))
        assertFalse(PasskeyEngine.assetLinks(raw, "attacker.app", "AA:BB"))
        assertFalse(PasskeyEngine.assetLinks(raw, "example.app", "CC:DD"))
        assertFalse(PasskeyEngine.assetLinks(raw.replace("common.get_login_creds", "common.handle_all_urls"), "example.app", "AA:BB"))
    }
}
