package com.docintegrity.forensics

import com.docintegrity.forensics.compare.*
import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.engine.ForensicReport
import com.docintegrity.forensics.image.AndroidImageDecoder
import com.docintegrity.forensics.image.ImageDecoders
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Side
import com.docintegrity.forensics.model.Verdict
import com.docintegrity.forensics.pdf.content.ContentExtractor
import com.docintegrity.forensics.util.Hashing
import org.junit.Assert.*
import org.junit.Assume
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** Comparison against a trusted original, on files produced by real tools. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class ComparisonFixtureTest {
    @Before fun init() { RobolectricSupport.initPdfBox(); ImageDecoders.default = AndroidImageDecoder() }

    private val renderer: PageRenderer? get() = if (PdftoppmRenderer.available) PdftoppmRenderer() else null
    private fun ref(name: String) = ReferenceInput(file = ReferenceFile(name, Fixtures.bytes(name)))
    private fun run(n: String, r: ReferenceInput?): ForensicReport = ForensicEngine().analyze(Fixtures.bytes(n), n, r, renderer)
    private fun ForensicReport.f(id: String) = findings.firstOrNull { it.id == id }
    private fun ForensicReport.ids() = findings.map { it.id }.toSet()
    private val vs = "A_original.pdf"

    // ---- same bytes ----------------------------------------------------------------------------------------------

    @Test fun identicalFileIsReportedIdenticalAndNotAsCertification() {
        val r = run(vs, ref(vs))
        assertEquals(Tri.YES, r.comparison!!.bytesIdentical)
        assertEquals(Tri.NO, r.comparison!!.meaningChanged)
        val f = r.f("CMP_BYTES_IDENTICAL")!!
        assertEquals(EvidenceClass.INFO, f.evidence)
        assertTrue("states the original may itself be unverified", f.unknown.contains("cannot verify"))
        assertEquals(Verdict.NO_INDICATORS_DETECTED, r.verdict.verdict)
    }

    // ---- bytes vs meaning ------------------------------------------------------------------------------------------

    @Test fun conversionRoundTripChangesBytesButNotMeaning() {
        // Scenario B vs A: PDF -> DOCX -> PDF without edits. Different bytes, fonts and layout; same wording.
        val r = run("B_roundtrip_unchanged.pdf", ref(vs))
        val c = r.comparison!!
        assertEquals(Tri.NO, c.bytesIdentical)
        assertTrue(c.textCompared)
        assertTrue("no text differences: ${c.textHunks.map { it.referenceText + '→' + it.submittedText }}", c.textHunks.isEmpty())
        assertEquals(Tri.NO, c.meaningChanged)
        assertTrue("CMP_BYTES_ONLY" in r.ids())
        assertNotEquals("a re-export must not be called a confirmed change", Verdict.CONFIRMED_CHANGE, r.verdict.verdict)
        assertTrue("embedded photo survives conversion", c.images.any { it.verdict == ImageVerdict.SAME_PICTURE || it.verdict == ImageVerdict.IDENTICAL })
    }

    @Test fun nameChangedThroughWordRoundTripIsConfirmedAgainstTrustedOriginal() {
        val r = run("C_roundtrip_name_altered.pdf", ref(vs))
        assertEquals(Verdict.CONFIRMED_CHANGE, r.verdict.verdict)
        val h = r.comparison!!.textHunks.single { it.category == EntityType.NAME }
        assertEquals("John Mwansa", h.referenceText); assertEquals("Joseph Mwanza", h.submittedText)
        val d = r.comparison!!.entityDeltas.single { it.type == EntityType.NAME }
        assertEquals(DeltaKind.CHANGED, d.kind)
        assertEquals("John Mwansa", d.reference); assertEquals("Joseph Mwanza", d.submitted)
        assertEquals(EvidenceClass.ESTABLISHED, r.f("CMP_TEXT_DIFF")!!.evidence)
        assertTrue(r.f("CMP_TEXT_DIFF")!!.unknown.contains("cannot verify"))
    }

    @Test fun amountChangedThroughWordRoundTripIsConfirmed() {
        val r = run("D_roundtrip_amount_altered.pdf", ref(vs))
        assertEquals(Verdict.CONFIRMED_CHANGE, r.verdict.verdict)
        val d = r.comparison!!.entityDeltas.single { it.type == EntityType.AMOUNT }
        assertTrue(d.reference!!.contains("4,250.00")); assertTrue(d.submitted!!.contains("42,500.00"))
        assertTrue("changed regions are highlighted on both sides", r.f("CMP_TEXT_DIFF")!!.regions.any { it.side == Side.SUBMITTED } && r.f("CMP_TEXT_DIFF")!!.regions.any { it.side == Side.REFERENCE })
    }

    @Test fun everyEditRouteIsConfirmedWithTheSameMeaningChange() {
        // F: incremental edit, Fb: full rewrite, Fw: white-out + retype, I: regenerated. Different forensics, same truth.
        for (n in listOf("F_editor_incremental.pdf", "Fb_editor_full_rewrite.pdf", "Fw_whiteout_retype.pdf", "I_regenerated_no_history.pdf")) {
            val r = run(n, ref(vs))
            assertEquals("$n verdict", Verdict.CONFIRMED_CHANGE, r.verdict.verdict)
            val h = r.comparison!!.textHunks.single { it.category == EntityType.NAME }
            assertEquals("$n", "Joseph Mwanza", h.submittedText)
            assertEquals("$n", "John Mwansa", h.referenceText)
        }
    }

    @Test fun whiteOutCoveredTextDoesNotPolluteTheVisibleTextComparison() {
        val c = ContentExtractor.extract(Fixtures.bytes("Fw_whiteout_retype.pdf"))
        assertFalse("covered 'John' must not be part of visible text", c.text.contains("John"))
        assertTrue(c.text.contains("Joseph Mwanza"))
    }

    @Test fun swappedPhotographIsConfirmed() {
        val r = run("K_photo_swapped.pdf", ref(vs))
        assertTrue(r.comparison!!.images.any { it.verdict == ImageVerdict.DIFFERENT })
        assertEquals(EvidenceClass.ESTABLISHED, r.f("CMP_IMAGE_DIFF")!!.evidence)
        assertEquals(Verdict.CONFIRMED_CHANGE, r.verdict.verdict)
        assertTrue("text is unchanged", r.comparison!!.textHunks.isEmpty())
    }

    // ---- DOCX reference ---------------------------------------------------------------------------------------------

    @Test fun pdfExportedFromTheAuthenticatedDocxMatchesIt() {
        val r = run("E_native_docx_export.pdf", ref("E_source.docx"))
        val c = r.comparison!!
        assertEquals(ReferenceKind.DOCX, c.referenceKind)
        assertTrue(c.textHunks.isEmpty())
        assertEquals(Tri.NO, c.meaningChanged)
        assertNotEquals(Verdict.CONFIRMED_CHANGE, r.verdict.verdict)
    }

    @Test fun alteredPdfIsCaughtAgainstTheDocxOriginal() {
        // a PDF that claims to be the receipt in E_source.docx but says a different name/amount
        val r = run("D_roundtrip_amount_altered.pdf", ref("E_source.docx"))
        assertTrue(r.comparison!!.entityDeltas.any { it.type == EntityType.AMOUNT })
        assertEquals(Verdict.CONFIRMED_CHANGE, r.verdict.verdict)
    }

    // ---- hashes ----------------------------------------------------------------------------------------------------

    @Test fun matchingReferenceHashIsInformationNotProofOfTruth() {
        val a = Fixtures.bytes(vs)
        val r = run(vs, ReferenceInput(hashes = listOf(Hashing.sha256(a).uppercase().chunked(8).joinToString(" "))))
        val f = r.f("CMP_HASH_MATCH")!!
        assertEquals(EvidenceClass.INFO, f.evidence)
        assertTrue(f.unknown.contains("says nothing about whether the information inside is genuine"))
        assertEquals(Tri.YES, r.comparison!!.bytesIdentical)
    }

    @Test fun hashOnlyMismatchIsEstablishedAtByteLevelOnly() {
        val r = run("D_roundtrip_amount_altered.pdf", ReferenceInput(hashes = listOf("sha256:" + Hashing.sha256(Fixtures.bytes(vs)))))
        val f = r.f("CMP_HASH_MISMATCH")!!
        assertEquals(EvidenceClass.ESTABLISHED, f.evidence)
        assertTrue(f.unknown.contains("BYTES differ, not that the meaning does"))
        assertEquals(Verdict.CONFIRMED_CHANGE, r.verdict.verdict)
        assertEquals("meaning is not assessed without the original", Tri.UNKNOWN, r.comparison!!.meaningChanged)
    }

    @Test fun hashMismatchWithOriginalFileIsOnlyInformation() {
        val r = run("B_roundtrip_unchanged.pdf", ReferenceInput(file = ReferenceFile(vs, Fixtures.bytes(vs)), hashes = listOf(Hashing.sha256(Fixtures.bytes(vs)))))
        assertEquals(EvidenceClass.INFO, r.f("CMP_HASH_MISMATCH")!!.evidence)
    }

    @Test fun malformedHashIsReportedNotSilentlyIgnored() {
        val r = run(vs, ReferenceInput(hashes = listOf("not-a-hash")))
        assertEquals(EvidenceClass.LIMITATION, r.f("CMP_HASH_BAD")!!.evidence)
    }

    @Test fun otherHashAlgorithmsAreRecognisedByLength() {
        val h = Hashing.all(Fixtures.bytes(vs))
        for (x in listOf(h.md5, h.sha1, h.sha256, h.sha512)) assertTrue(run(vs, ReferenceInput(hashes = listOf(x))).ids().contains("CMP_HASH_MATCH"))
    }

    // ---- issuer record -------------------------------------------------------------------------------------------

    private val record = mapOf("Receipt number" to "RC-2024-004217", "Name" to "John Mwansa", "Total amount" to "ZMW 4,250.00", "Date of issue" to "12 March 2024")

    @Test fun documentAgreeingWithIssuerRecordMatches() {
        val r = run(vs, ReferenceInput(issuerRecord = record))
        assertTrue(r.comparison!!.issuer.all { it.matched })
        assertEquals(EvidenceClass.INFO, r.f("CMP_ISSUER_MATCH")!!.evidence)
        assertNull(r.f("CMP_ISSUER_MISMATCH"))
    }

    @Test fun alteredAmountAndNameDisagreeWithIssuerRecord() {
        val d = run("D_roundtrip_amount_altered.pdf", ReferenceInput(issuerRecord = record))
        assertEquals(setOf("Total amount"), d.comparison!!.issuer.filter { !it.matched }.map { it.field }.toSet())
        assertEquals(Verdict.CONFIRMED_CHANGE, d.verdict.verdict)
        val c = run("C_roundtrip_name_altered.pdf", ReferenceInput(issuerRecord = record))
        assertEquals(setOf("Name"), c.comparison!!.issuer.filter { !it.matched }.map { it.field }.toSet())
    }

    // ---- scans: only rendered comparison is possible ------------------------------------------------------------------

    @Test fun scanEditedAsImageIsLocalisedByRenderedComparison() {
        Assume.assumeTrue("pdftoppm needed", PdftoppmRenderer.available)
        val a = ContentExtractor.extract(Fixtures.bytes(vs))
        val amount = a.pages[0].words.first { it.text.contains("4,250.00") }.rect
        val s = ReferenceInput(file = ReferenceFile("G0.pdf", Fixtures.bytes("G0_scan_unedited.pdf")))
        for (n in listOf("G_scan_amount_edited.pdf", "Gb_scan_amount_edited_same_quality.pdf")) {
            val r = run(n, s)
            val f = r.f("CMP_VISUAL_DIFF")!!
            assertEquals("pixel-only evidence is an indicator, not established", EvidenceClass.INDICATOR, f.evidence)
            assertTrue("$n: region covers the edited amount", f.regions.filter { it.side == Side.SUBMITTED }.any { reg ->
                val rr = com.docintegrity.forensics.pdf.content.RectD(reg.x, reg.y, reg.x + reg.w, reg.y + reg.h)
                rr.intersectionArea(amount) / amount.area > 0.3
            })
            assertTrue("text limitation is stated", r.f("CMP_TEXT_UNAVAILABLE") != null)
            assertEquals(Verdict.SUSPICIOUS_INDICATORS, r.verdict.verdict)
        }
        assertNull("the unedited scan raises nothing", run("G0_scan_unedited.pdf", s).f("CMP_VISUAL_DIFF"))
    }

    // ---- no reference / bad reference -----------------------------------------------------------------------------------

    @Test fun withoutAReferenceTheToolSaysItDoesNotKnowTheOriginal() {
        val r = run(vs, null)
        val f = r.f("CMP_NO_REFERENCE")!!
        assertEquals(EvidenceClass.LIMITATION, f.evidence)
        assertFalse(f.blocking)
        assertTrue(f.establishes.contains("Nothing about the document's ORIGINAL contents is known"))
        assertNull(r.comparison!!.referenceKind)
        assertEquals(Verdict.NO_INDICATORS_DETECTED, r.verdict.verdict)
    }

    @Test fun unreadableReferenceIsBlockingNotSilentlyOk() {
        val r = run(vs, ReferenceInput(file = ReferenceFile("x.bin", ByteArray(64) { it.toByte() })))
        assertEquals(EvidenceClass.LIMITATION, r.f("CMP_REF_UNREADABLE")!!.evidence)
        assertEquals(Verdict.INCONCLUSIVE, r.verdict.verdict)
    }

    @Test fun referenceBytesAreNeverModified() {
        val ref = Fixtures.bytes(vs); val sub = Fixtures.bytes("D_roundtrip_amount_altered.pdf")
        val h1 = Hashing.sha256(ref); val h2 = Hashing.sha256(sub)
        ForensicEngine().analyze(sub, "D", ReferenceInput(file = ReferenceFile("A", ref)), renderer)
        assertEquals(h1, Hashing.sha256(ref)); assertEquals(h2, Hashing.sha256(sub))
    }
}
