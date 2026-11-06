package com.docintegrity.forensics

import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.pdf.analysis.MetadataAnalyzer
import com.docintegrity.forensics.pdf.analysis.ToolCategory
import com.docintegrity.forensics.pdf.analysis.ToolFingerprints
import com.docintegrity.forensics.pdf.raw.PdfFile
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class MetadataAndFingerprintTest {
    private val now = Instant.parse("2026-11-06T12:00:00Z")

    private fun analyse(info: String? = null, xmp: String? = null): com.docintegrity.forensics.pdf.analysis.MetadataResult {
        val objs = PdfSynth.page().toMutableMap()
        var extra = ""
        if (info != null) { objs[6] = info; extra += " /Info 6 0 R" }
        if (xmp != null) { objs[7] = xmp; objs[1] = "<< /Type /Catalog /Pages 2 0 R /Metadata 7 0 R >>" }
        return MetadataAnalyzer.analyze(PdfFile.open(PdfSynth.build(objs, extra).bytes)!!, now)
    }

    private fun ids(r: com.docintegrity.forensics.pdf.analysis.MetadataResult) = r.findings.map { it.id }

    // ---- tool recognition (string level: these do NOT prove any file was made by these tools) ----------------

    @Test fun recognisesWordProcessorLabelsWithoutAccusing() {
        val c = ToolFingerprints.inspect("Info /Producer", "Microsoft® Word for Microsoft 365")
        assertTrue(c.any { it.tool == "Microsoft Word" && it.category == ToolCategory.WORD_PROCESSOR })
        assertTrue(c.all { it.caution.contains("does not indicate alteration") || it.caution.contains("ordinary") })
        assertTrue(ToolFingerprints.inspect("Info /Producer", "LibreOffice 7.6").any { it.tool.startsWith("LibreOffice") })
    }

    @Test fun recognisesEditorsConvertersScannersAndGenerators() {
        fun cat(s: String) = ToolFingerprints.inspect("x", s).map { it.category }
        assertTrue(cat("Adobe Acrobat Pro (64-bit) 24.2").contains(ToolCategory.PDF_EDITOR))
        assertTrue(cat("Foxit PDF Editor").contains(ToolCategory.PDF_EDITOR))
        assertTrue(cat("iLovePDF").contains(ToolCategory.CONVERTER))
        assertTrue(cat("GPL Ghostscript 10.02.1").contains(ToolCategory.CONVERTER))
        assertTrue(cat("Skia/PDF m118").contains(ToolCategory.PDF_GENERATOR))
        assertTrue(cat("Mac OS X 14.1 Quartz PDFContext").contains(ToolCategory.PDF_GENERATOR))
        assertTrue(cat("Canon iR-ADV C5535").contains(ToolCategory.SCANNER_OCR))
        assertTrue(cat("Adobe Scan for Android").contains(ToolCategory.SCANNER_OCR))
        assertTrue(cat("ABBYY FineReader PDF 16").contains(ToolCategory.SCANNER_OCR))
    }

    @Test fun unknownSoftwareProducesNoClue() {
        assertTrue(ToolFingerprints.inspect("x", "Acme Billing System 3.1").isEmpty())
        assertTrue(ToolFingerprints.inspect("x", "").isEmpty())
    }

    // ---- metadata consistency ------------------------------------------------------------------------------

    @Test fun cleanMetadataRaisesNoIndicator() {
        val r = analyse("<< /Creator (Writer) /Producer (LibreOffice 7.6) /CreationDate (D:20240312101500Z) /ModDate (D:20240312101500Z) >>")
        assertTrue(r.findings.none { it.evidence == EvidenceClass.INDICATOR })
        assertTrue("TOOL_LABELS" in ids(r))
    }

    @Test fun modificationBeforeCreationIsFlagged() {
        val r = analyse("<< /CreationDate (D:20240315000000Z) /ModDate (D:20240301000000Z) >>")
        assertTrue("META_MOD_BEFORE_CREATION" in ids(r))
        assertEquals(EvidenceClass.INDICATOR, r.findings.first { it.id == "META_MOD_BEFORE_CREATION" }.evidence)
    }

    @Test fun modifiedAfterCreationIsInformationOnly() {
        val r = analyse("<< /CreationDate (D:20240301000000Z) /ModDate (D:20240315000000Z) >>")
        val f = r.findings.first { it.id == "META_MODIFIED_AFTER_CREATION" }
        assertEquals(EvidenceClass.INFO, f.evidence)
    }

    @Test fun futureDatesAreFlaggedButSkewIsTolerated() {
        assertTrue("META_DATE_IN_FUTURE" in ids(analyse("<< /CreationDate (D:20300101000000Z) >>")))
        assertFalse("META_DATE_IN_FUTURE" in ids(analyse("<< /CreationDate (D:20261106180000Z) >>")))  // 6 h ahead: within tolerance
    }

    @Test fun malformedDateFlagged() {
        assertTrue("META_DATE_UNPARSEABLE" in ids(analyse("<< /CreationDate (yesterday afternoon) >>")))
    }

    @Test fun infoAndXmpAgreeNoConflict() {
        val r = analyse(
            "<< /Producer (Acme PDF) /Creator (Acme Writer) /CreationDate (D:20240312101500+02'00') >>",
            PdfSynth.xmp("<pdf:Producer>Acme PDF</pdf:Producer>", "<xmp:CreatorTool>Acme Writer</xmp:CreatorTool>", "<xmp:CreateDate>2024-03-12T10:15:00+02:00</xmp:CreateDate>"),
        )
        assertTrue(r.findings.none { it.id.startsWith("META_CONFLICT") })
    }

    @Test fun infoXmpConflictsAreIndicatorsNotFraud() {
        val r = analyse(
            "<< /Producer (Foxit PDF Editor) /Creator (Writer) /CreationDate (D:20240312101500Z) /ModDate (D:20240901101500Z) >>",
            PdfSynth.xmp("<pdf:Producer>Microsoft Word</pdf:Producer>", "<xmp:CreateDate>2023-01-02T08:00:00Z</xmp:CreateDate>", "<xmp:ModifyDate>2024-03-12T10:15:00Z</xmp:ModifyDate>"),
        )
        val got = ids(r)
        assertTrue("META_CONFLICT_PRODUCER" in got)
        assertTrue("META_CONFLICT_CREATE_DATE" in got)
        assertTrue("META_CONFLICT_MOD_DATE" in got)
        val f = r.findings.first { it.id == "META_CONFLICT_PRODUCER" }
        assertEquals(EvidenceClass.INDICATOR, f.evidence)
        assertFalse(f.establishes.contains("fraud", ignoreCase = true))
        assertTrue(f.unknown.contains("cannot distinguish") || f.unknown.contains("cannot tell"))
    }

    @Test fun xmpConversionHistoryIsReportedAsClaim() {
        val hist = """<xmpMM:History><rdf:Seq><rdf:li rdf:parseType="Resource"><stEvt:action>converted</stEvt:action><stEvt:parameters>from application/vnd.openxmlformats-officedocument.wordprocessingml.document to application/pdf</stEvt:parameters><stEvt:softwareAgent>Microsoft Word</stEvt:softwareAgent><stEvt:when>2024-03-12T10:15:00Z</stEvt:when></rdf:li></rdf:Seq></xmpMM:History>"""
        val r = analyse("<< /Creator (Word) >>", PdfSynth.xmp("<xmp:CreatorTool>Microsoft Word</xmp:CreatorTool>", history = hist))
        val f = r.findings.first { it.id == "XMP_HISTORY" }
        assertTrue(f.detected.contains("converted"))
        assertTrue(f.establishes.contains("format conversion"))
        assertEquals(EvidenceClass.INFO, f.evidence)
        assertEquals(1, r.xmp.data!!.history.size)
    }

    @Test fun xmpWithDoctypeIsNeverParsed() {
        val evil = PdfSynth.stream("/Type /Metadata /Subtype /XML", "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>")
        val r = analyse(null, evil)
        assertNull(r.xmp.data)
        assertTrue("META_XMP_NOT_PARSED" in ids(r))
    }

    @Test fun missingMetadataIsInformationNotAccusation() {
        val r = analyse()
        val f = r.findings.first { it.id == "META_NONE" }
        assertEquals(EvidenceClass.INFO, f.evidence)
    }

    @Test fun toolChainWithRewriterIsABlockingLimitationNotAnIndicator() {
        val r = analyse("<< /Creator (Microsoft Word) /Producer (GPL Ghostscript 10.0) >>")
        val f = r.findings.first { it.id == "HISTORY_REWRITE_TOOL" }
        assertEquals(EvidenceClass.LIMITATION, f.evidence)
        assertTrue(f.blocking)
        assertTrue(r.findings.none { it.evidence == EvidenceClass.INDICATOR })
    }

    @Test fun wordCreatedWordProducedIsNotAChain() {
        val r = analyse("<< /Creator (Microsoft® Word 2016) /Producer (Microsoft® Word 2016) >>")
        assertTrue("TOOL_CHAIN" !in ids(r))
    }
}
