// Plan-17 Android WG client scaffold.
//
// Mirrors the iOS WGClient.swift: load PairingBundle (from a file in
// the app's private storage, written by the pairing screen), construct
// JSON-RPC `seck.analyze`, send over WireGuard (BoringTun JNI), return
// the report.
package net.seck.share

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.util.UUID
import kotlin.concurrent.thread

object WGClient {

    data class PairingBundle(
        val hostPublicHex: String,
        val pskHex: String,
        val hostEndpoint: String,
        val fingerprintSha3_256: String,
    )

    private fun loadBundle(ctx: Context): PairingBundle? {
        val f = File(ctx.filesDir, "pairing.json")
        if (!f.exists()) return null
        val o = JSONObject(f.readText())
        return PairingBundle(
            hostPublicHex = o.getString("host_public_hex"),
            pskHex = o.getString("psk_hex"),
            hostEndpoint = o.getString("host_endpoint"),
            fingerprintSha3_256 = o.getString("fingerprint_sha3_256"),
        )
    }

    fun analyze(
        ctx: Context,
        filename: String,
        contents: ByteArray,
        callback: (String) -> Unit,
    ) {
        val bundle = loadBundle(ctx)
        if (bundle == null) {
            callback("Not paired — run `seck pair` on your desktop, then scan the QR.")
            return
        }
        thread {
            val frame = JSONObject().apply {
                put("jsonrpc", "2.0")
                put("id", UUID.randomUUID().toString())
                put("method", "seck.analyze")
                put("params", JSONObject().apply {
                    put("filename", filename)
                    put("content_base64", Base64.encodeToString(contents, Base64.NO_WRAP))
                })
            }
            val body = frame.toString().toByteArray(Charsets.UTF_8)
            // BoringTun JNI tunnel goes here in the executor build.
            callback("Encoded ${body.size} bytes; would send to ${bundle.hostEndpoint}.")
        }
    }
}
