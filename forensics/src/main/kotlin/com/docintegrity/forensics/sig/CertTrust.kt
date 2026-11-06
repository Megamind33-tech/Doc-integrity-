package com.docintegrity.forensics.sig

import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPResp
import org.bouncycastle.cert.ocsp.RevokedStatus
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.ByteArrayInputStream
import java.security.cert.CertPathBuilder
import java.security.cert.CertStore
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CRL
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.util.Date

enum class TrustStatus(val label: String) {
    TRUSTED("Chains to a trusted root"),
    UNKNOWN_ROOT("Chain ends in a root not in the trusted set"),
    SELF_SIGNED("Self-signed certificate"),
    CHAIN_INCOMPLETE("Chain could not be completed"),
    EXPIRED_AT_SIGNING("Certificate not valid at the signing time"),
    NOT_EVALUATED("Not evaluated (no trust anchors)"),
}

class TrustResult(val status: TrustStatus, val detail: String, val chain: List<String>)

enum class RevocationStatus(val label: String) { NOT_REVOKED("Not revoked per embedded evidence"), REVOKED("Revoked per embedded evidence"), UNKNOWN("Status unknown") }
class RevocationResult(val status: RevocationStatus, val detail: String, val revokedAt: Date? = null)

/**
 * Certificate-path and revocation checks. Trust is only ever relative to the supplied anchors; the report states
 * which set was used. Revocation is evaluated only from evidence EMBEDDED in the file (CMS revocation-info attribute
 * and the DSS dictionary): the app has no network permission and never performs online lookups.
 */
object CertTrust {
    val bc = BouncyCastleProvider()

    fun toX509(h: X509CertificateHolder): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(h.encoded)) as X509Certificate

    fun subjectCn(c: X509Certificate): String = rdn(c.subjectX500Principal.name, "CN") ?: c.subjectX500Principal.name
    fun issuerCn(c: X509Certificate): String = rdn(c.issuerX500Principal.name, "CN") ?: c.issuerX500Principal.name

    private fun rdn(dn: String, key: String): String? =
        Regex("(?:^|,)\\s*$key=((?:\\\\.|[^,])+)", RegexOption.IGNORE_CASE).find(dn)?.groupValues?.get(1)?.replace("\\,", ",")

    fun isSelfSigned(c: X509Certificate): Boolean {
        if (c.subjectX500Principal != c.issuerX500Principal) return false
        return try { c.verify(c.publicKey); true } catch (e: Exception) { false }
    }

    /**
     * Validates the signer certificate at [at] (the claimed or timestamped signing time; null = now) against [anchors],
     * building the path from [embedded] certificates. Revocation checking is off here (see [revocation]).
     */
    fun trust(signer: X509Certificate, embedded: List<X509Certificate>, anchors: List<X509Certificate>, at: Date?): TrustResult {
        val when_ = at ?: Date()
        try { signer.checkValidity(when_) } catch (e: java.security.cert.CertificateExpiredException) {
            return TrustResult(TrustStatus.EXPIRED_AT_SIGNING, "certificate expired on ${signer.notAfter}; signing time ${when_}", listOf(subjectCn(signer)))
        } catch (e: java.security.cert.CertificateNotYetValidException) {
            return TrustResult(TrustStatus.EXPIRED_AT_SIGNING, "certificate not valid before ${signer.notBefore}; signing time ${when_}", listOf(subjectCn(signer)))
        }
        if (anchors.isEmpty()) {
            return if (isSelfSigned(signer)) TrustResult(TrustStatus.SELF_SIGNED, "the signer certificate is its own issuer", listOf(subjectCn(signer)))
            else TrustResult(TrustStatus.NOT_EVALUATED, "no trust anchors were supplied", listOf(subjectCn(signer)))
        }
        // anchor listed explicitly as the signer itself
        fun attempt(a: List<X509Certificate>): java.security.cert.PKIXCertPathBuilderResult? = try {
            val params = PKIXBuilderParameters(a.map { TrustAnchor(it, null) }.toSet(), X509CertSelector().apply { certificate = signer })
            params.isRevocationEnabled = false
            params.date = when_
            params.addCertStore(CertStore.getInstance("Collection", CollectionCertStoreParameters(embedded + signer)))
            CertPathBuilder.getInstance("PKIX").build(params) as java.security.cert.PKIXCertPathBuilderResult
        } catch (e: Exception) { null }

        attempt(anchors)?.let { r ->
            val names = r.certPath.certificates.map { subjectCn(it as X509Certificate) } + subjectCn(r.trustAnchor.trustedCert)
            return TrustResult(TrustStatus.TRUSTED, "valid path to “${subjectCn(r.trustAnchor.trustedCert)}” at $when_", names)
        }
        if (isSelfSigned(signer)) return TrustResult(TrustStatus.SELF_SIGNED, "the signer certificate is its own issuer and is not among the trusted roots", listOf(subjectCn(signer)))
        // is the embedded chain at least internally consistent up to a root-like certificate?
        val pool = embedded + signer
        val roots = pool.filter { isSelfSigned(it) }
        if (roots.isNotEmpty() && attempt(roots) != null) {
            return TrustResult(TrustStatus.UNKNOWN_ROOT, "chain is consistent but ends in “${subjectCn(roots[0])}”, which is not among the trusted roots", listOf(subjectCn(signer), subjectCn(roots[0])))
        }
        return TrustResult(TrustStatus.CHAIN_INCOMPLETE, "no valid path from the signer certificate to a root could be built from the certificates in the file", listOf(subjectCn(signer)))
    }

    // ---- revocation (embedded evidence only) ----------------------------------------------------------------------

    fun revocation(signer: X509Certificate, issuerCandidates: List<X509Certificate>, crls: List<ByteArray>, ocsps: List<ByteArray>, signingTime: Date?): RevocationResult {
        val notes = ArrayList<String>()
        var verdict: RevocationResult? = null
        val cf = CertificateFactory.getInstance("X.509")
        for (b in crls) {
            val crl = try { cf.generateCRL(ByteArrayInputStream(b)) as X509CRL } catch (e: Exception) { notes.add("unparseable CRL"); continue }
            if (crl.issuerX500Principal != signer.issuerX500Principal) continue
            val issuer = issuerCandidates.firstOrNull { it.subjectX500Principal == crl.issuerX500Principal && sigOk(crl, it) }
            if (issuer == null) { notes.add("embedded CRL signature could not be verified against any available issuer"); continue }
            val entry = crl.getRevokedCertificate(signer)
            if (entry != null) return RevocationResult(RevocationStatus.REVOKED, "embedded CRL (issued ${crl.thisUpdate}) lists serial ${signer.serialNumber.toString(16)} as revoked on ${entry.revocationDate}", entry.revocationDate)
            val fresh = signingTime == null || (!signingTime.before(crl.thisUpdate) && (crl.nextUpdate == null || !signingTime.after(crl.nextUpdate)))
            verdict = RevocationResult(RevocationStatus.NOT_REVOKED, "embedded CRL issued ${crl.thisUpdate} (valid verified signature) does not list the certificate" + if (!fresh) "; note: the CRL was not current at the signing time" else "")
        }
        for (b in ocsps) {
            try {
                val resp = OCSPResp(b)
                if (resp.status != 0) continue
                val basic = resp.responseObject as BasicOCSPResp
                val issuer = issuerCandidates.firstOrNull { it.subjectX500Principal == signer.issuerX500Principal } ?: continue
                val calc = JcaDigestCalculatorProviderBuilder().setProvider(bc).build()
                val cid = CertificateID(calc.get(CertificateID.HASH_SHA1), org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(issuer), signer.serialNumber)
                val single = basic.responses.firstOrNull { it.certID.equals(cid) } ?: continue
                val responderCerts = basic.certs.map { toX509(it) } + issuerCandidates
                val okSig = responderCerts.any { rc -> try { basic.isSignatureValid(JcaContentVerifierProviderBuilder().setProvider(bc).build(rc)) } catch (e: Exception) { false } }
                if (!okSig) { notes.add("embedded OCSP response signature could not be verified"); continue }
                val st = single.certStatus
                if (st is RevokedStatus) return RevocationResult(RevocationStatus.REVOKED, "embedded OCSP response (produced ${basic.producedAt}) reports the certificate revoked on ${st.revocationTime}", st.revocationTime)
                if (st == null) verdict = RevocationResult(RevocationStatus.NOT_REVOKED, "embedded OCSP response (produced ${basic.producedAt}) reports the certificate good")
            } catch (e: Exception) { notes.add("unparseable OCSP response") }
        }
        return verdict ?: RevocationResult(RevocationStatus.UNKNOWN, "no usable embedded revocation evidence" + (if (notes.isNotEmpty()) " (${notes.distinct().joinToString("; ")})" else "") + "; online lookup is never performed (the app has no network access)")
    }

    private fun sigOk(crl: X509CRL, issuer: X509Certificate) = try { crl.verify(issuer.publicKey); true } catch (e: Exception) { false }

    /** Parses the adbe-revocationInfoArchival signed attribute value into (CRL DER list, OCSP response DER list). */
    fun parseRevocationArchival(attr: ASN1Primitive): Pair<List<ByteArray>, List<ByteArray>> {
        val crls = ArrayList<ByteArray>(); val ocsps = ArrayList<ByteArray>()
        try {
            val seq = ASN1Sequence.getInstance(attr)
            for (e in seq) {
                val t = ASN1TaggedObject.getInstance(e)
                val inner = ASN1Sequence.getInstance(t.baseObject.toASN1Primitive())
                when (t.tagNo) {
                    0 -> inner.forEach { crls.add(it.toASN1Primitive().encoded) }
                    1 -> inner.forEach { ocsps.add(it.toASN1Primitive().encoded) }
                }
            }
        } catch (e: Exception) { /* leave what we have */ }
        return crls to ocsps
    }

}
