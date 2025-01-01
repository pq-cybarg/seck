// Plan-17 Android share-target Activity.
//
// Receives ACTION_SEND / ACTION_SEND_MULTIPLE, reads the URI's bytes
// in-memory (size-capped to keep this simple), forwards to WGClient.
package net.seck.share

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val tv = TextView(this).apply { textSize = 16f; setPadding(32, 32, 32, 32) }
        setContentView(tv)

        when (intent?.action) {
            Intent.ACTION_SEND -> handle(intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java), tv)
            Intent.ACTION_SEND_MULTIPLE -> {
                val uris = intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                uris?.forEach { handle(it, tv) }
            }
            else -> tv.text = "seck: unsupported intent ${intent?.action}"
        }
    }

    private fun handle(uri: Uri?, tv: TextView) {
        if (uri == null) { tv.text = "no URI in share intent"; return }
        val data = contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: run { tv.text = "could not read $uri"; return }
        WGClient.analyze(this, uri.lastPathSegment ?: "input", data) { result ->
            runOnUiThread { tv.text = result }
        }
    }
}
