package com.docintegrity.forensics

import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.pdf.content.*
import org.junit.Assert.*
import org.junit.Test

class ContentAnalyzerTest {
    private val W = 612.0
    private val H = 792.0

    private fun text(order: Int, s: String, x: Double, y: Double, size: Float = 12f, mode: Int = 0, rgb: Int? = 0, base: Double = y + 10) =
        TextOp(order, RectD(x, y, x + s.length * 6.0, y + 12), s, "Helv", size, mode, rgb, base,
            s.mapIndexed { i, c -> GlyphBox(c.toString(), RectD(x + i * 6.0, y, x + i * 6.0 + 6, y + 12)) })

    private fun page(vararg ops: PaintOp, words: List<WordInfo> = emptyList()) =
        DocumentContent(listOf(PageContent(0, W, H, 0, words, ops.toList(), emptyList())), emptyList(), false)

    private fun ids(d: DocumentContent) = ContentAnalyzer.analyze(d).findings.map { it.id }

    @Test fun textCoveredByLaterWhiteRectangleIsFlagged() {
        val d = page(text(0, "Total 4,250.00", 100.0, 200.0), FillOp(1, RectD(160.0, 198.0, 190.0, 214.0), 0xFFFFFF, true, true))
        val f = ContentAnalyzer.analyze(d).findings.first { it.id == "CONTENT_COVERED_TEXT" }
        assertEquals(EvidenceClass.INDICATOR, f.evidence)
        assertTrue(f.regions.isNotEmpty())
        assertTrue(f.unknown.contains("Redaction boxes"))
    }

    @Test fun backgroundFillDrawnBeforeTextIsNotFlagged() {
        val d = page(FillOp(0, RectD(90.0, 190.0, 300.0, 220.0), 0xEEEEEE, true, true), text(1, "Shaded cell", 100.0, 200.0))
        assertFalse("CONTENT_COVERED_TEXT" in ids(d))
    }

    @Test fun semiTransparentHighlightIsNotCover() {
        val d = page(text(0, "Highlighted", 100.0, 200.0), FillOp(1, RectD(90.0, 198.0, 300.0, 214.0), 0xFFFF00, false, true))
        assertFalse("CONTENT_COVERED_TEXT" in ids(d))
    }

    @Test fun thinUnderlineRuleDoesNotCover() {
        val d = page(text(0, "Underlined", 100.0, 200.0), FillOp(1, RectD(100.0, 211.0, 160.0, 212.0), 0, true, true))
        assertFalse("CONTENT_COVERED_TEXT" in ids(d))
    }

    @Test fun imageDrawnOverTextIsFlagged() {
        val d = page(text(0, "Name: John", 100.0, 200.0), ImageOp(1, RectD(95.0, 195.0, 200.0, 220.0), 50, 20, false, "png"))
        assertTrue("CONTENT_COVERED_TEXT" in ids(d))
    }

    @Test fun invisibleTextOnTypesetPageIsFlaggedButOcrLayerIsNot() {
        val hidden = page(text(0, "secret", 100.0, 200.0, mode = 3))
        assertTrue("CONTENT_HIDDEN_TEXT" in ids(hidden))
        val scanImg = ImageOp(0, RectD(0.0, 0.0, W, H), 1700, 2200, false, "jpg")
        val ocr = page(scanImg, text(1, "scanned words", 100.0, 200.0, mode = 3))
        val got = ids(ocr)
        assertFalse("CONTENT_HIDDEN_TEXT" in got)
        assertTrue("CONTENT_OCR_LAYER" in got)
        assertEquals(EvidenceClass.INFO, ContentAnalyzer.analyze(ocr).findings.first { it.id == "CONTENT_OCR_LAYER" }.evidence)
    }

    @Test fun whiteTextOnWhitePageIsHiddenButWhiteOnDarkIsNot() {
        assertTrue("CONTENT_HIDDEN_TEXT" in ids(page(text(0, "ghost", 100.0, 200.0, rgb = 0xFFFFFF))))
        val d = page(FillOp(0, RectD(90.0, 190.0, 300.0, 220.0), 0x000000, true, true), text(1, "Reversed heading", 100.0, 200.0, rgb = 0xFFFFFF))
        assertFalse("CONTENT_HIDDEN_TEXT" in ids(d))
    }

    @Test fun visibleTextOverScanIsFlaggedOcrOnlyIsNot() {
        val scanImg = ImageOp(0, RectD(0.0, 0.0, W, H), 1700, 2200, false, "jpg")
        val edited = page(scanImg, FillOp(1, RectD(400.0, 300.0, 520.0, 320.0), 0xFAFAFA, true, true), text(2, "ZMW 42,500.00", 405.0, 302.0))
        val f = ContentAnalyzer.analyze(edited).findings.first { it.id == "CONTENT_SCAN_OVERLAY" }
        assertEquals(EvidenceClass.INDICATOR, f.evidence)
        assertEquals(2, f.regions.size)
        assertFalse("CONTENT_SCAN_OVERLAY" in ids(page(scanImg, text(1, "ocr", 10.0, 10.0, mode = 3))))
    }

    @Test fun wordsMixingFontsAreFlaggedStrongerWhenTheyContainDigits() {
        fun w(t: String, faces: List<String>) = WordInfo(0, 0, t, RectD(100.0, 200.0, 160.0, 212.0), 12f, t.mapIndexed { i, c -> CharFont(c.toString(), faces[i]) })
        val digits = page(words = listOf(w("4,250", listOf("Arial", "Arial", "Calibri", "Arial", "Arial"))))
        val f = ContentAnalyzer.analyze(digits).findings.first { it.id == "CONTENT_MIXED_FONT_WORD" }
        assertEquals(EvidenceClass.INDICATOR, f.evidence)
        val alpha = page(words = listOf(w("Name", listOf("Arial", "Arial", "Arial", "Calibri"))))
        assertEquals(EvidenceClass.INFO, ContentAnalyzer.analyze(alpha).findings.first { it.id == "CONTENT_MIXED_FONT_WORD" }.evidence)
        val same = page(words = listOf(w("4,250", List(5) { "Arial" })))
        assertFalse("CONTENT_MIXED_FONT_WORD" in ids(same))
    }

    @Test fun baselineOffsetFlaggedOnlyInsideTheDefinedBand() {
        fun line(dy: Double) = page(text(0, "Received:", 72.0, 200.0, base = 210.0), text(1, "Joseph", 150.0, 200.0, base = 210.0 + dy))
        assertTrue("CONTENT_BASELINE_OFFSET" in ids(line(0.9)))
        assertFalse("CONTENT_BASELINE_OFFSET" in ids(line(0.0)))
        assertFalse("CONTENT_BASELINE_OFFSET" in ids(line(0.05)))   // rounding noise
        assertFalse("CONTENT_BASELINE_OFFSET" in ids(line(4.0)))    // clearly a different line/superscript, out of band
    }

    @Test fun differentFontSizesAreNeverCompared() {
        val d = page(text(0, "Total", 72.0, 200.0, size = 12f, base = 210.0), text(1, "x2", 150.0, 200.0, size = 8f, base = 210.9))
        assertFalse("CONTENT_BASELINE_OFFSET" in ids(d))
    }

    @Test fun pageKindsDistinguishVectorRasterAndMixed() {
        val scanImg = ImageOp(0, RectD(0.0, 0.0, W, H), 1700, 2200, false, "jpg")
        assertEquals(ContentAnalyzer.PageKind.VECTOR, ContentAnalyzer.analyze(page(text(0, "hi", 10.0, 10.0), words = listOf(WordInfo(0, 0, "hi", RectD(0.0, 0.0, 1.0, 1.0), 12f, emptyList())))).pageKinds[0])
        assertEquals(ContentAnalyzer.PageKind.RASTER, ContentAnalyzer.analyze(page(scanImg)).pageKinds[0])
        assertEquals(ContentAnalyzer.PageKind.MIXED, ContentAnalyzer.analyze(page(scanImg, text(1, "stamp", 10.0, 10.0))).pageKinds[0])
    }
}
