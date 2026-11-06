package com.docintegrity.forensics

import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.pdf.analysis.RevisionAnalyzer
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.sig.*
import com.docintegrity.forensics.util.Hashing
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

/**
 * Signature verification against files signed by pyHanko (an independent implementation). The expected outcome of
 * every fixture was first established with pyHanko's own validator (tools/fixtures/verify_signed_with_pyhanko.py).
 */
class SignatureTest {
    private val now = Instant.parse("2026-11-06T20:00:00Z")

    private fun analyse(name: String, trust: com.docintegrity.forensics.engine.TrustSet = TestTrust.testRoots): SignatureResultSet {
        val f = PdfFile.open(Fixtures.bytes(name))!!
        return SignatureAnalyzer.analyze(f, RevisionAnalyzer.analyze(f).revisions, trust.anchors, trust.description, now)
    }
    private fun SignatureResultSet.f(id: String) = findings.firstOrNull { it.id == id }

    @Test fun validUntouchedSignatureIsValidTrustedAndStillNotCertification() {
        val r = analyse("H0_signed_valid.pdf")
        val s = r.signatures.single()
        assertEquals(CryptoStatus.VALID, s.crypto)
        assertEquals(TrustStatus.TRUSTED, s.trustAtSigning!!.status)
        assertEquals("Grace Banda", s.signerCn)
        assertEquals("SHA-256", s.digestAlg)
        assertEquals(0, s.laterRevisions); assertEquals(emptyList<String>(), s.byteRangeProblems)
        val f = r.f("SIG_VALID_UNMODIFIED")!!
        assertEquals(EvidenceClass.INFO, f.evidence)
        assertTrue("states validity is not truth", f.unknown.contains("says nothing about whether the signed information is TRUE"))
        assertTrue("states claimed signing time", f.unknown.contains("signer's own claim"))
        assertTrue(r.findings.none { it.evidence == EvidenceClass.ESTABLISHED || it.evidence == EvidenceClass.INDICATOR })
    }

    @Test fun trustIsNeverClaimedWithoutRoots() {
        val s = analyse("H0_signed_valid.pdf", com.docintegrity.forensics.engine.TrustSet.NONE)
        assertEquals(CryptoStatus.VALID, s.signatures.single().crypto)
        assertEquals(TrustStatus.NOT_EVALUATED, s.signatures.single().trustAtSigning!!.status)
        assertEquals(EvidenceClass.LIMITATION, s.f("SIG_TRUST")!!.evidence)
    }

    @Test fun selfSignedIsValidButIdentityUnproven() {
        val r = analyse("H4_signed_self_signed.pdf", com.docintegrity.forensics.engine.TrustSet.NONE)
        assertEquals(CryptoStatus.VALID, r.signatures.single().crypto)
        assertEquals(TrustStatus.SELF_SIGNED, r.signatures.single().trustAtSigning!!.status)
        assertTrue(r.f("SIG_TRUST")!!.establishes.contains("not who holds it"))
    }

    @Test fun unknownRootIsNotCalledInvalid() {
        // the test CA is simply not in the device's trust set
        val r = analyse("H0_signed_valid.pdf", com.docintegrity.forensics.engine.TrustSet(listOf(TestTrust.testRoots.anchors[0].let { selfSignedOther() }), "an unrelated root"))
        assertEquals(CryptoStatus.VALID, r.signatures.single().crypto)
        assertEquals(TrustStatus.UNKNOWN_ROOT, r.signatures.single().trustAtSigning!!.status)
        assertTrue(r.f("SIG_TRUST")!!.unknown.contains("AATL"))
    }

    private fun selfSignedOther(): java.security.cert.X509Certificate = CertFactory.selfSignedRoot("Unrelated Root").cert

    @Test fun byteFlippedInsideSignedRangeIsConfirmedChange() {
        val r = analyse("H1_signed_bytes_flipped.pdf")
        val s = r.signatures.single()
        assertEquals(CryptoStatus.DIGEST_MISMATCH, s.crypto)
        val f = r.f("SIG_DIGEST_MISMATCH")!!
        assertEquals(EvidenceClass.ESTABLISHED, f.evidence)
        assertTrue("does not equate mismatch with fraud", f.unknown.contains("Accidental corruption"))
    }

    @Test fun contentChangedAfterSigningIsConfirmedAndSignedVersionIsRecoverable() {
        val r = analyse("H2_signed_then_edited.pdf")
        val s = r.signatures.single()
        assertEquals(CryptoStatus.VALID, s.crypto)
        assertEquals(1, s.laterRevisions)
        assertTrue(s.laterChanges.any { it.cls == PostSignChange.VISIBLE_CONTENT })
        val f = r.f("SIG_CHANGED_AFTER_SIGNING")!!
        assertEquals(EvidenceClass.ESTABLISHED, f.evidence)
        // the signed version, reconstructed from the edited file, is byte-identical to the file as it was when signed
        val file = PdfFile.open(Fixtures.bytes("H2_signed_then_edited.pdf"))!!
        assertEquals(Hashing.sha256(Fixtures.bytes("H0_signed_valid.pdf")), Hashing.sha256(file.prefix(s.signedRevision)))
    }

    @Test fun legitimateCoSigningIsNotFlagged() {
        val r = analyse("H3_signed_then_cosigned.pdf")
        assertEquals(2, r.signatures.size)
        assertTrue(r.signatures.all { it.crypto == CryptoStatus.VALID })
        assertTrue("signature + form-field additions are permitted", r.signatures[0].laterChanges.none { it.cls == PostSignChange.VISIBLE_CONTENT || it.cls == PostSignChange.OTHER })
        assertTrue(r.findings.none { it.evidence == EvidenceClass.ESTABLISHED || it.evidence == EvidenceClass.INDICATOR })
        assertNotNull(r.f("SIG_LATER_BENIGN"))
    }

    @Test fun timestampIsVerifiedAndAuthenticatesTheSigningTime() {
        val s = analyse("H5_signed_timestamped.pdf").signatures.single()
        assertEquals(CryptoStatus.VALID, s.crypto)
        assertNotNull(s.verifiedTimestamp)
        assertTrue(s.timestampNote!!.contains("verified"))
    }

    @Test fun annotationAfterCertificationViolatesDocMdp() {
        val r = analyse("H6_certified_then_annotated.pdf")
        val s = r.signatures.single()
        assertEquals(1, s.docMdp)
        assertEquals(CryptoStatus.VALID, s.crypto)
        val f = r.f("SIG_CHANGED_AFTER_SIGNING")!!
        assertEquals(EvidenceClass.ESTABLISHED, f.evidence)
        assertTrue(f.detected.contains("allows no changes"))
    }

    @Test fun validSignatureOverFalseContentIsReportedValidAndNotCertified() {
        val r = analyse("H7_signed_false_content.pdf")
        assertEquals(CryptoStatus.VALID, r.signatures.single().crypto)
        assertTrue(r.findings.none { it.evidence == EvidenceClass.ESTABLISHED })
        assertTrue(r.f("SIG_VALID_UNMODIFIED")!!.unknown.contains("a document created with false information and then signed still verifies"))
    }

    @Test fun certificateExpiredAtSigningTimeIsAnIndicatorNotAnInvalidSignature() {
        val r = analyse("H8_signed_cert_expired.pdf")
        val s = r.signatures.single()
        assertEquals("cryptography is intact (pyHanko: intact=True valid=True)", CryptoStatus.VALID, s.crypto)
        assertEquals(TrustStatus.EXPIRED_AT_SIGNING, s.trustAtSigning!!.status)
        val f = r.f("SIG_CERT_NOT_VALID_AT_SIGNING")!!
        assertEquals(EvidenceClass.INDICATOR, f.evidence)
        assertTrue(f.unknown.contains("unauthenticated"))
    }

    @Test fun documentTimestampIsRecognisedAsFurtherValidationDataNotAChange() {
        val r = analyse("H9_signed_then_doc_timestamp.pdf")
        assertEquals(2, r.signatures.size)
        val ts = r.signatures.single { it.timestampOnly }
        assertEquals(CryptoStatus.VALID, ts.crypto)
        assertNotNull(ts.verifiedTimestamp)
        assertTrue(r.signatures.first { !it.timestampOnly }.laterChanges.none { it.cls == PostSignChange.VISIBLE_CONTENT })
        assertTrue(r.findings.none { it.evidence == EvidenceClass.ESTABLISHED || it.evidence == EvidenceClass.INDICATOR })
    }

    @Test fun unsignedFileSaysThereIsNoCryptographicEvidence() {
        val r = analyse("A_original.pdf")
        assertTrue(r.signatures.isEmpty())
        val f = r.f("SIG_NONE")!!
        assertEquals(EvidenceClass.INFO, f.evidence)
        assertTrue(f.unknown.contains("says nothing about authenticity"))
    }

    // ---- ByteRange manipulation ----------------------------------------------------------------------------------------

    private fun editByteRange(name: String, edit: (a: Long, b: Long, c: Long, d: Long) -> LongArray): ByteArray {
        val bytes = Fixtures.bytes(name)
        val s = String(bytes, Charsets.ISO_8859_1)
        val m = Regex("/ByteRange\\s*\\[\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*\\]").find(s)!!
        val v = edit(m.groupValues[1].toLong(), m.groupValues[2].toLong(), m.groupValues[3].toLong(), m.groupValues[4].toLong())
        val repl = "/ByteRange [${v[0]} ${v[1]} ${v[2]} ${v[3]}]".padEnd(m.value.length)
        require(repl.length == m.value.length) { "length changed" }
        return (s.substring(0, m.range.first) + repl + s.substring(m.range.last + 1)).toByteArray(Charsets.ISO_8859_1)
    }

    private fun run(b: ByteArray): SignatureResultSet {
        val f = PdfFile.open(b)!!
        return SignatureAnalyzer.analyze(f, RevisionAnalyzer.analyze(f).revisions, TestTrust.testRoots.anchors, "test", now)
    }

    @Test fun gapThatIsNotExactlyTheSignatureValueIsFlaggedAsHidingPlace() {
        // widen the unsigned gap by one byte on each side: content could be hidden there
        val r = run(editByteRange("H0_signed_valid.pdf") { a, b, c, d -> longArrayOf(a, b - 1, c + 1, d - 1) })
        val s = r.signatures.single()
        assertTrue(s.byteRangeProblems.any { it.contains("not exactly the signature value") })
        assertNull("a manipulated range must never be reported as an intact signature", r.f("SIG_VALID_UNMODIFIED"))
        assertNull(r.f("SIG_VALID_EARLIER_REVISION"))
    }

    @Test fun rangeNotStartingAtZeroIsReported() {
        val r = run(editByteRange("H0_signed_valid.pdf") { a, b, c, d -> longArrayOf(a + 1, b - 1, c, d) })
        assertTrue(r.signatures.single().byteRangeProblems.any { it.contains("does not start at byte 0") })
    }

    @Test fun rangeBeyondTheFileIsReportedAndNothingIsClaimed() {
        val r = run(editByteRange("H0_signed_valid.pdf") { a, b, c, d -> longArrayOf(a, b, c, d + 1) })
        val s = r.signatures.single()
        assertTrue(s.byteRangeProblems.any { it.contains("beyond the file") })
        assertNull(r.f("SIG_VALID_UNMODIFIED"))
    }

    @Test fun signatureBytesThemselvesAreNeverModifiedByAnalysis() {
        val b = Fixtures.bytes("H3_signed_then_cosigned.pdf"); val h = Hashing.sha256(b)
        val f = PdfFile.open(b)!!
        SignatureAnalyzer.analyze(f, RevisionAnalyzer.analyze(f).revisions, TestTrust.testRoots.anchors, "t", now)
        assertEquals(h, Hashing.sha256(b))
    }
}
