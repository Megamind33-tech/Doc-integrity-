package com.docintegrity.forensics

import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.engine.ForensicReport
import com.docintegrity.forensics.image.*
import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Side
import com.docintegrity.forensics.model.Verdict
import com.docintegrity.forensics.pdf.content.ContentExtractor
import com.docintegrity.forensics.pdf.content.RectD
import com.docintegrity.forensics.pdf.images.PdfImageExtractor
import com.docintegrity.forensics.pdf.raw.PdfFile
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.Random

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class ImageForensicsTest {
    @Before fun init() { RobolectricSupport.initPdfBox(); ImageDecoders.default = AndroidImageDecoder() }

    private fun jpeg(name: String): ByteArray = PdfImageExtractor.extract(PdfFile.open(Fixtures.bytes(name))!!).images.first().data
    private fun run(n: String): ForensicReport = ForensicEngine().analyze(Fixtures.bytes(n), n)
    private fun ForensicReport.img() = findings.filter { it.area == Area.IMAGE }
    private fun ForensicReport.imgIds() = img().map { it.id }.toSet()
    private fun ForensicReport.imgIndicators() = img().filter { it.evidence == EvidenceClass.INDICATOR }.map { it.id }

    // ---- JPEG container --------------------------------------------------------------------------------------------

    @Test fun jpegStructureOfRealScansIsReadCorrectly() {
        val j75 = JpegInspector.inspect(jpeg("G0_scan_unedited.pdf"))!!
        assertEquals(1654, j75.width); assertEquals(2339, j75.height)
        assertEquals("4:2:0", j75.subsampling); assertFalse(j75.progressive)
        assertEquals(75, j75.ijgQuality)
        assertEquals(92, JpegInspector.inspect(jpeg("G_scan_amount_edited.pdf"))!!.ijgQuality)
        assertEquals(88, JpegInspector.inspect(jpeg("A_original.pdf"))!!.ijgQuality)
    }

    @Test fun nonStandardTablesAreNotAssignedAQuality() {
        val b = jpeg("G0_scan_unedited.pdf").copyOf()
        // corrupt the first luminance DQT entries so that they no longer match any IJG-scaled standard table
        var i = 2
        while (i + 4 < b.size) { if ((b[i].toInt() and 0xFF) == 0xFF && (b[i + 1].toInt() and 0xFF) == 0xDB) { for (k in 0 until 20) b[i + 5 + k] = (3 + k * 7).toByte(); break }; i++ }
        assertNull(JpegInspector.inspect(b)!!.ijgQuality)
    }

    @Test fun exifSoftwareAndPhotoshopTraceAreParsed() {
        val j = JpegInspector.inspect(jpeg("Gx_scan_editor_traces.pdf"))!!
        assertEquals("Adobe Photoshop 25.1 (Windows)", j.exifSoftware)
        assertEquals("2025:03:02 14:11:09", j.exifDateTime)
    }

    @Test fun bytesAfterEndOfImageAreCounted() {
        val b = jpeg("G0_scan_unedited.pdf") + "SECRET-PAYLOAD".toByteArray()
        assertEquals(14, JpegInspector.inspect(b)!!.trailingBytes)
        assertEquals(0, JpegInspector.inspect(jpeg("G0_scan_unedited.pdf"))!!.trailingBytes)
    }

    @Test fun garbageAndTruncatedJpegsDoNotCrash() {
        assertNull(JpegInspector.inspect(ByteArray(50) { it.toByte() }))
        val t = jpeg("G0_scan_unedited.pdf").copyOf(300)
        assertNotNull(JpegInspector.inspect(t))
    }

    // ---- noise analysis on controlled images -------------------------------------------------------------------------

    private fun grainy(w: Int, h: Int, sigma: Double, seed: Long = 5, patch: IntArray? = null): GrayImage {
        val rnd = Random(seed)
        val d = ByteArray(w * h)
        for (y in 0 until h) for (x in 0 until w) {
            var v = 242.0 + rnd.nextGaussian() * sigma
            if (patch != null && x in patch[0] until patch[2] && y in patch[1] until patch[3]) v = 242.0
            d[y * w + x] = v.coerceIn(0.0, 255.0).toInt().toByte()
        }
        return GrayImage(w, h, d)
    }

    @Test fun flatPatchInsideGrainyPageIsFoundWithItsLocation() {
        val r = NoiseAnalysis.analyze(grainy(800, 800, 2.5, patch = intArrayOf(300, 300, 420, 340)))
        assertTrue(r.informative)
        assertEquals(1, r.lowNoiseRegions.size)
        val g = r.lowNoiseRegions[0]
        assertTrue(g.x0 <= 320 && g.x1 >= 400 && g.y0 <= 320 && g.y1 >= 320)
    }

    @Test fun uniformlyGrainyPageHasNoRegion() {
        assertTrue(NoiseAnalysis.analyze(grainy(800, 800, 2.5)).lowNoiseRegions.isEmpty())
    }

    @Test fun denoisedOrWhitenedPageIsReportedNotInformativeNeverClean() {
        val r = NoiseAnalysis.analyze(grainy(800, 800, 0.0))
        assertFalse(r.informative)
        assertTrue(r.note.contains("almost no grain"))
        assertTrue(NoiseAnalysis.analyze(grainy(800, 800, 0.3)).informative.not())
    }

    @Test fun flatMarginsAtThePageEdgeAreNotFlagged() {
        val r = NoiseAnalysis.analyze(grainy(800, 800, 2.5, patch = intArrayOf(0, 0, 800, 90)))
        assertTrue("a blank top margin is normal", r.lowNoiseRegions.isEmpty())
    }

    @Test fun tinyFlatSpecksAreIgnored() {
        assertTrue(NoiseAnalysis.analyze(grainy(800, 800, 2.5, patch = intArrayOf(300, 300, 320, 316))).lowNoiseRegions.isEmpty())
    }

    // ---- real scan fixtures ---------------------------------------------------------------------------------------------

    @Test fun grainyScanEditedWithAFlatPatchIsFlaggedAtThePatch() {
        val r = run("Gh_scan_hq_grainy_amount_edited.pdf")
        val f = r.img().first { it.id == "IMG_NOISE_PATCH" }
        assertEquals("never established", EvidenceClass.INDICATOR, f.evidence)
        assertEquals(Verdict.SUSPICIOUS_INDICATORS, r.verdict.verdict)
        val amount = ContentExtractor.extract(Fixtures.bytes("A_original.pdf")).pages[0].words.first { it.text.contains("4,250.00") }.rect
        assertTrue("region lies on the edited amount", f.regions.any { reg ->
            RectD(reg.x, reg.y, reg.x + reg.w, reg.y + reg.h).intersectionArea(amount) / amount.area > 0.3 && reg.side == Side.SUBMITTED
        })
        assertTrue(f.unknown.contains("matching noise"))
    }

    @Test fun unEditedGrainyScanRaisesNothing() {
        val r = run("Gh0_scan_hq_grainy_unedited.pdf")
        assertEquals(emptyList<String>(), r.imgIndicators())
        assertEquals(Verdict.NO_INDICATORS_DETECTED, r.verdict.verdict)
    }

    @Test fun separateImagePlacedOverAScanIsFlaggedWithItsResolution() {
        val f = run("Gs_scan_image_overlay.pdf").img().first { it.id == "IMG_OVER_SCAN" }
        assertEquals(EvidenceClass.INDICATOR, f.evidence)
        assertTrue(f.detected.contains("600 dpi") && f.detected.contains("200 dpi"))
        assertTrue(f.regions.isNotEmpty())
    }

    @Test fun editorTraceInImageMetadataIsContextNotAnIndicator() {
        val r = run("Gx_scan_editor_traces.pdf")
        val f = r.img().first { it.id == "IMG_EDITOR_TRACE" }
        assertEquals(EvidenceClass.INFO, f.evidence)
        assertTrue(f.unknown.contains("cropping, resizing and compressing"))
        assertEquals(emptyList<String>(), r.imgIndicators())
    }

    @Test fun whitenedScansAreNotInformativeAndNotCalledClean() {
        for (n in listOf("Gn0_scan_whitened_unedited.pdf", "Gn_scan_whitened_amount_edited.pdf")) {
            val r = run(n)
            assertTrue(n, "IMG_NOISE_NOT_INFORMATIVE" in r.imgIds())
            assertTrue(r.img().first { it.id == "IMG_NOISE_NOT_INFORMATIVE" }.unknown.contains("not a clean result"))
        }
    }

    // ---- documented misses: pinned so that nobody mistakes them for coverage ---------------------------------------------

    @Test fun knownFalseNegativesOfImageForensics() {
        // G: edit + whole-page re-save at q92. Gb: same edit re-saved at the SAME quality. Gp: patch pasted from another
        // scan. Gn: edit on a scan whose background scanner software whitened. None of these leaves a trace these methods can see.
        for (n in listOf("G_scan_amount_edited.pdf", "Gb_scan_amount_edited_same_quality.pdf", "Gp_scan_patch_pasted.pdf", "Gn_scan_whitened_amount_edited.pdf")) {
            assertEquals("$n: documented false negative", emptyList<String>(), run(n).imgIndicators())
        }
    }

    @Test fun imageFindingsAreNeverEstablishedEvidence() {
        for (n in Fixtures.names().filter { it.startsWith("G") || it == "A_original.pdf" || it == "K_photo_swapped.pdf" }) {
            assertTrue(n, run(n).img().none { it.evidence == EvidenceClass.ESTABLISHED })
        }
    }

    @Test fun withoutADecoderTheLimitIsStatedNotHidden() {
        ImageDecoders.default = null
        val r = run("Gh_scan_hq_grainy_amount_edited.pdf")
        assertTrue(r.img().any { it.id == "IMG_LIMITED" })
        assertFalse("IMG_NOISE_PATCH" in r.imgIds())
    }
}
