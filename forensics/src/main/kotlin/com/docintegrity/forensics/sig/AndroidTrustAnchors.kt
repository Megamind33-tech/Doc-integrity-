package com.docintegrity.forensics.sig

import com.docintegrity.forensics.engine.TrustSet
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * Trust roots from the device's own certificate store (system roots plus any the user installed).
 * Roots used for PDF signing in many regions (Adobe AATL, EU trusted lists) are NOT part of this store, so a legitimate
 * signature may report an unknown root. The report always names the trust set that was used.
 */
object AndroidTrustAnchors {
    fun load(): TrustSet = try {
        val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        val certs = ArrayList<X509Certificate>()
        for (alias in ks.aliases()) (ks.getCertificate(alias) as? X509Certificate)?.let { certs.add(it) }
        TrustSet(certs, "this device's certificate store (${certs.size} roots)")
    } catch (e: Exception) {
        TrustSet(emptyList(), "none: the device certificate store could not be read")
    }
}
