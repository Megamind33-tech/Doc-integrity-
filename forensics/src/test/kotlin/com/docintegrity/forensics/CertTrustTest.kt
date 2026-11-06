package com.docintegrity.forensics

import com.docintegrity.forensics.sig.CertTrust
import com.docintegrity.forensics.sig.RevocationStatus
import com.docintegrity.forensics.sig.TrustStatus
import org.junit.Assert.*
import org.junit.Test
import java.util.Date

class CertTrustTest {
    private val day = 86_400_000L
    private val root = CertFactory.selfSignedRoot("Root A")
    private val inter = CertFactory.issue("Intermediate", root, true)
    private val leaf = CertFactory.issue("Leaf Signer", inter, false)

    @Test fun chainToTrustedRootViaEmbeddedIntermediateIsTrusted() {
        val r = CertTrust.trust(leaf.cert, listOf(inter.cert), listOf(root.cert), Date())
        assertEquals(TrustStatus.TRUSTED, r.status)
        assertEquals(listOf("Leaf Signer", "Intermediate", "Root A"), r.chain)
    }

    @Test fun missingIntermediateMeansChainIncompleteNotInvalid() {
        assertEquals(TrustStatus.CHAIN_INCOMPLETE, CertTrust.trust(leaf.cert, emptyList(), listOf(root.cert), Date()).status)
    }

    @Test fun rootNotInTrustSetIsUnknownRoot() {
        val other = CertFactory.selfSignedRoot("Root B")
        val r = CertTrust.trust(leaf.cert, listOf(inter.cert, root.cert), listOf(other.cert), Date())
        assertEquals(TrustStatus.UNKNOWN_ROOT, r.status)
        assertTrue(r.detail.contains("Root A"))
    }

    @Test fun noAnchorsIsNotEvaluatedAndSelfSignedIsRecognised() {
        assertEquals(TrustStatus.NOT_EVALUATED, CertTrust.trust(leaf.cert, listOf(inter.cert), emptyList(), Date()).status)
        assertEquals(TrustStatus.SELF_SIGNED, CertTrust.trust(root.cert, emptyList(), emptyList(), Date()).status)
    }

    @Test fun validityIsJudgedAtTheSigningTimeNotToday() {
        val old = CertFactory.issue("Old", root, false, Date(System.currentTimeMillis() - 800 * day), Date(System.currentTimeMillis() - 400 * day))
        // signed 600 days ago: valid then (expired today)
        assertEquals(TrustStatus.TRUSTED, CertTrust.trust(old.cert, emptyList(), listOf(root.cert), Date(System.currentTimeMillis() - 600 * day)).status)
        assertEquals(TrustStatus.EXPIRED_AT_SIGNING, CertTrust.trust(old.cert, emptyList(), listOf(root.cert), Date()).status)
    }

    // ---- revocation: only embedded evidence is used -----------------------------------------------------------------

    @Test fun embeddedCrlListingTheCertificateMeansRevoked() {
        val rev = Date(System.currentTimeMillis() - 2 * day)
        val crl = CertFactory.crl(inter, listOf(leaf.cert.serialNumber to rev))
        val r = CertTrust.revocation(leaf.cert, listOf(inter.cert), listOf(crl), emptyList(), Date())
        assertEquals(RevocationStatus.REVOKED, r.status)
        assertEquals(rev.time / 1000, r.revokedAt!!.time / 1000)
    }

    @Test fun embeddedCrlNotListingTheCertificateMeansNotRevokedPerThatEvidence() {
        val crl = CertFactory.crl(inter, emptyList())
        val r = CertTrust.revocation(leaf.cert, listOf(inter.cert), listOf(crl), emptyList(), Date())
        assertEquals(RevocationStatus.NOT_REVOKED, r.status)
        assertTrue(r.detail.contains("embedded CRL"))
    }

    @Test fun crlSignedByTheWrongKeyIsNotTrusted() {
        val impostor = CertFactory.issue("Intermediate", root, true)   // same name, different key
        val crl = CertFactory.crl(impostor, listOf(leaf.cert.serialNumber to Date()))
        val r = CertTrust.revocation(leaf.cert, listOf(inter.cert), listOf(crl), emptyList(), Date())
        assertEquals("an unverifiable CRL must not be believed", RevocationStatus.UNKNOWN, r.status)
    }

    @Test fun ocspGoodAndRevokedAreRecognised() {
        val good = CertTrust.revocation(leaf.cert, listOf(inter.cert), emptyList(), listOf(CertFactory.ocsp(inter, leaf, null)), Date())
        assertEquals(RevocationStatus.NOT_REVOKED, good.status)
        val bad = CertTrust.revocation(leaf.cert, listOf(inter.cert), emptyList(), listOf(CertFactory.ocsp(inter, leaf, Date(System.currentTimeMillis() - day))), Date())
        assertEquals(RevocationStatus.REVOKED, bad.status)
    }

    @Test fun noEvidenceMeansUnknownAndStatesOnlineLookupIsNeverDone() {
        val r = CertTrust.revocation(leaf.cert, listOf(inter.cert), emptyList(), emptyList(), Date())
        assertEquals(RevocationStatus.UNKNOWN, r.status)
        assertTrue(r.detail.contains("online lookup is never performed"))
    }
}
