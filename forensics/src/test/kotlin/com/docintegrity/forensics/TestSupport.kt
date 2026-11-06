package com.docintegrity.forensics

import com.docintegrity.forensics.compare.PageRenderer
import com.docintegrity.forensics.image.GrayImage
import java.io.File

/** Renders pages with poppler's pdftoppm (test environment only). */
class PdftoppmRenderer : PageRenderer {
    override fun render(pdfBytes: ByteArray, page: Int, widthPx: Int): GrayImage? {
        val dir = java.nio.file.Files.createTempDirectory("render").toFile()
        try {
            val pdf = File(dir, "in.pdf").also { it.writeBytes(pdfBytes) }
            val p = ProcessBuilder("pdftoppm", "-gray", "-f", "${page + 1}", "-l", "${page + 1}", "-scale-to-x", "$widthPx", "-scale-to-y", "-1", pdf.path, File(dir, "out").path)
                .redirectErrorStream(true).start()
            p.inputStream.readBytes(); p.waitFor()
            val out = dir.listFiles()!!.firstOrNull { it.name.startsWith("out") } ?: return null
            return readPgm(out.readBytes())
        } finally { dir.deleteRecursively() }
    }

    private fun readPgm(b: ByteArray): GrayImage {
        var p = 0
        fun token(): String { while (b[p].toInt().toChar().isWhitespace()) p++; val s = p; while (!b[p].toInt().toChar().isWhitespace()) p++; return String(b, s, p - s) }
        require(token() == "P5")
        val w = token().toInt(); val h = token().toInt(); token(); p++
        return GrayImage(w, h, b.copyOfRange(p, p + w * h))
    }

    companion object {
        val available: Boolean by lazy { try { ProcessBuilder("pdftoppm", "-v").redirectErrorStream(true).start().also { it.inputStream.readBytes() }.waitFor(); true } catch (e: Exception) { false } }
    }
}

object TestTrust {
    private fun load(name: String): java.security.cert.X509Certificate =
        java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(java.io.ByteArrayInputStream(Fixtures.bytes(name))) as java.security.cert.X509Certificate

    /** The throw-away CA used by tools/fixtures/generate_signed.py. Never a real trust store. */
    val testRoots: com.docintegrity.forensics.engine.TrustSet by lazy {
        com.docintegrity.forensics.engine.TrustSet(listOf(load("test_root_ca.pem")), "test root CA (fixture generator)")
    }
}

/** Builds throw-away certificates / CRLs / OCSP responses with BouncyCastle for trust and revocation unit tests. */
object CertFactory {
    class Entity(val cert: java.security.cert.X509Certificate, val key: java.security.KeyPair)

    private val bc = org.bouncycastle.jce.provider.BouncyCastleProvider()
    private fun kp(): java.security.KeyPair = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private fun name(cn: String) = org.bouncycastle.asn1.x500.X500Name("CN=$cn, O=Test")

    fun issue(cn: String, issuer: Entity?, ca: Boolean, from: java.util.Date = java.util.Date(System.currentTimeMillis() - 86_400_000L * 30), to: java.util.Date = java.util.Date(System.currentTimeMillis() + 86_400_000L * 365)): Entity {
        val k = kp()
        val issuerName = issuer?.cert?.let { org.bouncycastle.asn1.x500.X500Name.getInstance(it.subjectX500Principal.encoded) } ?: name(cn)
        val b = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(issuerName, java.math.BigInteger.valueOf(System.nanoTime()), from, to, name(cn), k.public)
        b.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, org.bouncycastle.asn1.x509.BasicConstraints(ca))
        val signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build((issuer?.key ?: k).private)
        val cert = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(bc).getCertificate(b.build(signer))
        return Entity(cert, k)
    }

    fun selfSignedRoot(cn: String) = issue(cn, null, true)

    /** A CRL issued by [issuer] listing [revoked] (serial, revocation date). */
    fun crl(issuer: Entity, revoked: List<Pair<java.math.BigInteger, java.util.Date>>, thisUpdate: java.util.Date = java.util.Date(System.currentTimeMillis() - 3_600_000L), nextUpdate: java.util.Date = java.util.Date(System.currentTimeMillis() + 86_400_000L * 7)): ByteArray {
        val b = org.bouncycastle.cert.X509v2CRLBuilder(org.bouncycastle.asn1.x500.X500Name.getInstance(issuer.cert.subjectX500Principal.encoded), thisUpdate)
        b.setNextUpdate(nextUpdate)
        for ((sn, d) in revoked) b.addCRLEntry(sn, d, 1)
        return b.build(org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(issuer.key.private)).encoded
    }

    /** A signed OCSP response by [issuer] about [subject]; [revokedAt] == null means status good. */
    fun ocsp(issuer: Entity, subject: Entity, revokedAt: java.util.Date?): ByteArray {
        val calc = org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().setProvider(bc).build()
        val id = org.bouncycastle.cert.ocsp.CertificateID(calc.get(org.bouncycastle.cert.ocsp.CertificateID.HASH_SHA1), org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(issuer.cert), subject.cert.serialNumber)
        val b = org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder(org.bouncycastle.cert.ocsp.RespID(org.bouncycastle.asn1.x500.X500Name.getInstance(issuer.cert.subjectX500Principal.encoded)))
        b.addResponse(id, if (revokedAt == null) org.bouncycastle.cert.ocsp.CertificateStatus.GOOD else org.bouncycastle.cert.ocsp.RevokedStatus(revokedAt, 1))
        val basic = b.build(org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(issuer.key.private), arrayOf(org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(issuer.cert)), java.util.Date())
        return org.bouncycastle.cert.ocsp.OCSPRespBuilder().build(org.bouncycastle.cert.ocsp.OCSPRespBuilder.SUCCESSFUL, basic).encoded
    }
}
