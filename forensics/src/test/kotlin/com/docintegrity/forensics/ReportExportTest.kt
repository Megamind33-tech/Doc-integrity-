package com.docintegrity.forensics

import com.docintegrity.forensics.compare.ReferenceFile
import com.docintegrity.forensics.compare.ReferenceInput
import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.engine.ForensicReport
import com.docintegrity.forensics.image.AndroidImageDecoder
import com.docintegrity.forensics.image.ImageDecoders
import com.docintegrity.forensics.model.Verdict
import com.docintegrity.forensics.pdf.content.ContentExtractor
import com.docintegrity.forensics.report.EvidenceReportPdf
import com.docintegrity.forensics.report.ReportJson
import com.tom_roush.pdfbox.pdmodel.PDDocument
import org.json.JSONObject
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
class ReportExportTest {
    @Before fun init() { RobolectricSupport.initPdfBox(); ImageDecoders.default = AndroidImageDecoder() }

    private fun report(n: String, ref: String? = null): ForensicReport =
        ForensicEngine({ BenchmarkScenarios.FIXED_NOW }).analyze(Fixtures.bytes(n), n, ref?.let { ReferenceInput(file = ReferenceFile(it, Fixtures.bytes(it))) }, if (PdftoppmRenderer.available) PdftoppmRenderer() else null, TestTrust.testRoots)

    private fun textOf(pdf: ByteArray) = ContentExtractor.extract(pdf).let { c -> c.pages.joinToString("\n") { it.text } }
    private fun flat(s: String) = s.replace(Regex("\\s+"), " ")

    @Test fun exportedPdfRestatesCategoryHashAndTheStandingStatement() {
        val r = report("D_roundtrip_amount_altered.pdf", "A_original.pdf")
        val pdf = EvidenceReportPdf.build(r)
        val t = flat(textOf(pdf))
        assertTrue(t.contains("NOT a certificate of authenticity"))
        assertTrue(t.contains("Confirmed change"))
        assertTrue("full SHA-256 of the examined file is printed", t.contains(r.hashes.sha256))
        assertTrue(t.contains(r.tool.rulesetVersion)); assertTrue(t.contains(r.tool.version))
        assertTrue("states bytes vs meaning", t.contains("File bytes") && t.contains("Document meaning"))
        assertTrue("comparison diff is shown", t.contains("4,250.00") && t.contains("42,500.00"))
        assertTrue("no certifying language", !t.lowercase().replace("not a certificate of authenticity", "").contains("certified genuine"))
    }

    @Test fun everyFindingIsPrintedWithAllThreeStatements() {
        val r = report("F_editor_incremental.pdf")
        val t = flat(textOf(EvidenceReportPdf.build(r)))
        for (f in r.findings.filter { it.evidence != com.docintegrity.forensics.model.EvidenceClass.INFO }) {
            assertTrue("finding title present: ${f.title}", t.contains(EvidenceReportPdf.sanitize(f.title).take(40)))
        }
        assertTrue(t.contains("Detected:") && t.contains("Establishes:") && t.contains("Unknown:"))
    }

    @Test fun noReferenceReportStatesTheOriginalIsUnknownAndNoIndicatorsIsNotAuthenticity() {
        val r = report("A_original.pdf")
        assertEquals(Verdict.NO_INDICATORS_DETECTED, r.verdict.verdict)
        val t = flat(textOf(EvidenceReportPdf.build(r)))
        assertTrue(t.contains("original contents of this document are therefore unknown"))
        assertTrue(t.contains("Authenticity is NOT established"))
        assertTrue(t.contains("No probability or confidence score"))
    }

    @Test fun signatureSectionKeepsIntegrityTrustAndTruthApart() {
        val t = flat(textOf(EvidenceReportPdf.build(report("H2_signed_then_edited.pdf"))))
        assertTrue(t.contains("1. Integrity") && t.contains("2. Certificate") && t.contains("3. After signing"))
        assertTrue(t.contains("does not show that the signed information is true"))
    }

    @Test fun jsonIsAttachedAndIdenticalToTheStandaloneExport() {
        val r = report("D_roundtrip_amount_altered.pdf", "A_original.pdf")
        val json = ReportJson.toJson(r)
        val pdf = EvidenceReportPdf.build(r, json)
        PDDocument.load(pdf).use { d ->
            val spec = d.documentCatalog.names.embeddedFiles.names["report.json"]
            assertNotNull("report.json attached", spec)
            val attached = String(spec!!.embeddedFile.toByteArray(), Charsets.UTF_8)
            assertEquals(json, attached)
        }
    }

    @Test fun jsonIsValidDeterministicAndCarriesReproducibilityData() {
        val r = report("H2_signed_then_edited.pdf", "A_original.pdf")
        val a = ReportJson.toJson(r); val b = ReportJson.toJson(r)
        assertEquals(a, b)
        val j = JSONObject(a)
        assertEquals(ReportJson.SCHEMA, j.getString("schema"))
        assertEquals(r.hashes.sha256, j.getJSONObject("file").getString("sha256"))
        assertEquals(r.tool.rulesetVersion, j.getJSONObject("tool").getString("ruleset"))
        assertEquals("CONFIRMED_CHANGE", j.getJSONObject("verdict").getString("category"))
        assertTrue(j.getJSONArray("findings").length() > 3)
        val f0 = j.getJSONArray("findings").getJSONObject(0)
        assertTrue(f0.has("detected") && f0.has("establishes") && f0.has("unknown") && f0.has("evidence_class"))
        assertTrue(j.getJSONObject("verdict").getString("note").contains("No probability or confidence score"))
        assertTrue("never contains document bytes", a.length < 200_000)
        assertEquals(1, j.getJSONArray("signatures").length())
        assertEquals("VALID", j.getJSONArray("signatures").getJSONObject(0).getString("integrity"))
    }

    @Test fun hugeUnbreakableTokensAndManyPagesDoNotBreakLayout() {
        val r = report("H3_signed_then_cosigned.pdf", "A_original.pdf")
        val pdf = EvidenceReportPdf.build(r)
        PDDocument.load(pdf).use { assertTrue(it.numberOfPages >= 2) }
        // every page carries the footer disclaimer
        val c = ContentExtractor.extract(pdf)
        for (p in c.pages) assertTrue("footer on page ${p.index + 1}", flat(p.text).contains("not a certificate of authenticity"))
    }

    @Test fun exportedReportIsItselfAnOrdinaryPdfTheEngineCanExamine() {
        val pdf = EvidenceReportPdf.build(report("A_original.pdf"))
        val again = ForensicEngine({ BenchmarkScenarios.FIXED_NOW }).analyze(pdf, "report.pdf")
        assertTrue(again.isPdf); assertEquals(1, again.revisions.size)
        assertEquals(Verdict.NO_INDICATORS_DETECTED, again.verdict.verdict)
    }

    @Test fun writeSampleReportsForReview() {
        val dir = java.io.File(System.getProperty("user.dir"), "build/reports/samples").apply { mkdirs() }
        java.io.File(dir, "sample-confirmed-change.pdf").writeBytes(EvidenceReportPdf.build(report("D_roundtrip_amount_altered.pdf", "A_original.pdf")))
        java.io.File(dir, "sample-signed-edited.pdf").writeBytes(EvidenceReportPdf.build(report("H2_signed_then_edited.pdf")))
        java.io.File(dir, "sample-no-indicators.pdf").writeBytes(EvidenceReportPdf.build(report("A_original.pdf")))
    }

    @Test fun sanitiseMapsTypographyAndNeverLeavesUnencodableCharacters() {
        val s = EvidenceReportPdf.sanitize("“John” → Joseph … ≠ ≈ · — ✓ é")
        assertEquals("\"John\" -> Joseph ... != ~ - - ? é", s)
        assertTrue(s.all { it.code in 32..126 || it.code in 0xA1..0xFF })
    }

    @Test fun pageSnapshotsAreEmbeddedWhenSupplied() {
        val img = AndroidImageDecoderTestImage.png(300, 400)
        val r = report("F_editor_incremental.pdf")
        val pdf = EvidenceReportPdf.build(r, snapshots = listOf(com.docintegrity.forensics.report.PageSnapshot("Page 1 (examined)", img)))
        PDDocument.load(pdf).use { d ->
            var images = 0
            for (p in d.pages) p.resources.xObjectNames.forEach { n -> if (p.resources.isImageXObject(n)) images++ }
            assertEquals(1, images)
        }
    }
}

/** Builds a small PNG with the platform encoder (native graphics). */
object AndroidImageDecoderTestImage {
    fun png(w: Int, h: Int): ByteArray {
        val bmp = android.graphics.Bitmap.createBitmap(w, h, android.graphics.Bitmap.Config.ARGB_8888)
        bmp.eraseColor(android.graphics.Color.rgb(240, 240, 240))
        val bo = java.io.ByteArrayOutputStream(); bmp.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, bo); return bo.toByteArray()
    }
}
