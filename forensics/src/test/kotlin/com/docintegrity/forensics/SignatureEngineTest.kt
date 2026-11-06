package com.docintegrity.forensics

import com.docintegrity.forensics.compare.ReferenceFile
import com.docintegrity.forensics.compare.ReferenceInput
import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.image.AndroidImageDecoder
import com.docintegrity.forensics.image.ImageDecoders
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Verdict
import com.docintegrity.forensics.sig.CryptoStatus
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class SignatureEngineTest {
    @Before fun init() { RobolectricSupport.initPdfBox(); ImageDecoders.default = AndroidImageDecoder() }
    private fun run(n: String, ref: ReferenceInput? = null) = ForensicEngine().analyze(Fixtures.bytes(n), n, ref, null, TestTrust.testRoots)

    @Test fun validSignatureAloneNeverMakesTheReportSayGenuine() {
        val r = run("H0_signed_valid.pdf")
        assertEquals(Verdict.NO_INDICATORS_DETECTED, r.verdict.verdict)
        val all = (r.verdict.reasons + r.verdict.verdict.summary + r.findings.map { it.establishes }).joinToString(" ").lowercase()
        // the only permitted mention of "genuine" is the explicit negation
        val stripped = all.replace("not evidence that the document is genuine", "")
        assertFalse(stripped.contains("genuine")); assertFalse(stripped.contains("authentic document")); assertFalse(stripped.contains("verified document"))
        assertTrue(r.verdict.reasons.joinToString(" ").contains("not evidence that the document is genuine"))
        assertEquals(1, r.signatures.size)
    }

    @Test fun cryptographicEvidenceDrivesTheConfirmedChangeCategory() {
        for (n in listOf("H1_signed_bytes_flipped.pdf", "H2_signed_then_edited.pdf", "H6_certified_then_annotated.pdf")) {
            val r = run(n)
            assertEquals("$n", Verdict.CONFIRMED_CHANGE, r.verdict.verdict)
            assertTrue("$n has an established signature finding", r.findings.any { it.area == com.docintegrity.forensics.model.Area.SIGNATURE && it.evidence == EvidenceClass.ESTABLISHED })
        }
    }

    @Test fun legitimateCosignedFileIsNotConfirmedChanged() {
        assertEquals(Verdict.NO_INDICATORS_DETECTED, run("H3_signed_then_cosigned.pdf").verdict.verdict)
        assertEquals(Verdict.NO_INDICATORS_DETECTED, run("H9_signed_then_doc_timestamp.pdf").verdict.verdict)
    }

    @Test fun signedFalseContentIsStillCaughtByComparisonWithTheTrustedOriginal() {
        // H7 = D (amount altered) validly signed. The signature verifies; the content differs from the issuer's original.
        val withoutOriginal = run("H7_signed_false_content.pdf")
        assertEquals(CryptoStatus.VALID, withoutOriginal.signatures.single().crypto)
        assertEquals("signature validity alone cannot expose false content", Verdict.NO_INDICATORS_DETECTED, withoutOriginal.verdict.verdict)
        val withOriginal = run("H7_signed_false_content.pdf", ReferenceInput(file = ReferenceFile("A.pdf", Fixtures.bytes("A_original.pdf"))))
        assertEquals(CryptoStatus.VALID, withOriginal.signatures.single().crypto)
        assertEquals(Verdict.CONFIRMED_CHANGE, withOriginal.verdict.verdict)
        assertTrue(withOriginal.comparison!!.entityDeltas.any { it.type == com.docintegrity.forensics.compare.EntityType.AMOUNT })
    }

    @Test fun reportRecordsWhichTrustSetWasUsed() {
        val r = run("H0_signed_valid.pdf")
        assertEquals("test root CA (fixture generator)", r.trust.description)
        val none = ForensicEngine().analyze(Fixtures.bytes("H0_signed_valid.pdf"), "H0")
        assertEquals(com.docintegrity.forensics.sig.TrustStatus.NOT_EVALUATED, none.signatures.single().trustAtSigning!!.status)
    }
}
