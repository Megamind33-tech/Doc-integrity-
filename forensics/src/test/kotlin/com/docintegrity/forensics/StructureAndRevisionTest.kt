package com.docintegrity.forensics

import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.pdf.analysis.ChangeType
import com.docintegrity.forensics.pdf.analysis.ObjectKind
import com.docintegrity.forensics.pdf.analysis.RevisionAnalyzer
import com.docintegrity.forensics.pdf.analysis.StructureAnalyzer
import com.docintegrity.forensics.pdf.raw.PdfFile
import org.junit.Assert.*
import org.junit.Test

class StructureAndRevisionTest {

    private fun structure(b: ByteArray) = StructureAnalyzer.analyze(PdfFile.open(b)!!)
    private fun ids(b: ByteArray) = structure(b).findings.map { it.id }

    @Test fun cleanSyntheticDocumentHasNoStructuralIndicators() {
        val r = structure(PdfSynth.build(PdfSynth.page()).bytes)
        assertTrue(r.findings.none { it.evidence == EvidenceClass.INDICATOR })
        assertEquals(1, r.pageCount)
    }

    @Test fun lengtheningEditWithStalePointerIsReportedAsRebuiltXref() {
        val doc = PdfSynth.build(PdfSynth.page("BT /F1 12 Tf 72 700 Td (Amount 100.00) Tj ET"))
        val edited = String(doc.bytes, Charsets.ISO_8859_1).replace("(Amount 100.00)", "(Amount 1000000.00)")
        val f = structure(edited.toByteArray(Charsets.ISO_8859_1)).findings.first { it.id == "STRUCT_XREF_REBUILT" }
        assertEquals(EvidenceClass.INDICATOR, f.evidence)
        assertTrue(f.unknown.contains("manual byte-level editing"))
    }

    @Test fun lengtheningEditWithFixedPointerButWrongObjectOffsetsIsReportedAsMismatch() {
        val doc = PdfSynth.build(PdfSynth.page("BT /F1 12 Tf 72 700 Td (Amount 100.00) Tj ET"))
        var s = String(doc.bytes, Charsets.ISO_8859_1).replace("(Amount 100.00)", "(Amount 1000000.00)")
        val newXref = s.lastIndexOf("\nxref\n") + 1
        s = s.replace(Regex("startxref\\s+\\d+"), "startxref\n$newXref")
        val f = structure(s.toByteArray(Charsets.ISO_8859_1)).findings.first { it.id == "STRUCT_XREF_MISMATCH" }
        assertEquals(EvidenceClass.INDICATOR, f.evidence)
        assertTrue(f.unknown.contains("buggy generators"))   // alternative explanations are stated
    }

    @Test fun sameLengthEditLeavesNoStructuralTrace() {
        // Honest negative: an in-place edit that keeps byte counts identical is NOT visible to structural checks.
        val doc = PdfSynth.build(PdfSynth.page("BT /F1 12 Tf 72 700 Td (Amount 100.00) Tj ET"))
        val edited = String(doc.bytes, Charsets.ISO_8859_1).replace("(Amount 100.00)", "(Amount 900.00)")
        val r = structure(edited.toByteArray(Charsets.ISO_8859_1))
        assertTrue(r.findings.none { it.evidence == EvidenceClass.INDICATOR })
    }

    @Test fun trailingDataAfterEofIsReported() {
        val doc = PdfSynth.build(PdfSynth.page())
        val withTail = doc.bytes + "\nSECRET-PAYLOAD-12345".toByteArray()
        assertTrue("STRUCT_TRAILING_DATA" in ids(withTail))
    }

    @Test fun trailingWhitespaceIsNotReported() {
        val doc = PdfSynth.build(PdfSynth.page())
        assertFalse("STRUCT_TRAILING_DATA" in ids(doc.bytes + "\r\n\r\n  ".toByteArray()))
    }

    @Test fun unreferencedContentStreamIsReportedWithRecoveredText() {
        val objs = PdfSynth.page().toMutableMap()
        objs[6] = PdfSynth.stream("", "BT /F1 12 Tf 72 600 Td (Original salary 5000) Tj ET")   // nothing refers to obj 6
        val r = structure(PdfSynth.build(objs).bytes)
        val f = r.findings.first { it.id == "STRUCT_ORPHANS" }
        assertEquals(EvidenceClass.INDICATOR, f.evidence)
        assertTrue(f.details.any { it.second.contains("Original salary 5000") })
        assertTrue(r.orphans.any { it.kind == ObjectKind.CONTENT_STREAM && 6 in it.objectNumbers })
    }

    @Test fun rolledBackUpdateLeavesUnlistedObjectsAndTrailingData() {
        val v0 = PdfSynth.build(PdfSynth.page("BT /F1 12 Tf 72 700 Td (Pay 100) Tj ET"))
        val v1 = PdfSynth.update(v0, mapOf(4 to PdfSynth.stream("", "BT /F1 12 Tf 72 700 Td (Pay 900) Tj ET")))
        // an attacker (or a failed save) removes the trailing xref+trailer, leaving the appended object behind
        val s = String(v1.bytes, Charsets.ISO_8859_1)
        val cutAt = s.lastIndexOf("xref\n", s.length).let { s.lastIndexOf("\nxref\n") + 1 }
        val rolled = s.substring(0, cutAt).toByteArray(Charsets.ISO_8859_1)
        val got = ids(rolled)
        assertTrue("STRUCT_TRAILING_DATA" in got)
        assertTrue("STRUCT_UNLISTED_OBJECTS" in got)
    }

    // ---- revisions ------------------------------------------------------------------------------------------

    @Test fun contentReplacementInUpdateIsAnIndicatorWithObjectDetail() {
        val v0 = PdfSynth.build(PdfSynth.page("BT /F1 12 Tf 72 700 Td (Pay 100) Tj ET"))
        val v1 = PdfSynth.update(v0, mapOf(4 to PdfSynth.stream("", "BT /F1 12 Tf 72 700 Td (Pay 900) Tj ET")))
        val r = RevisionAnalyzer.analyze(PdfFile.open(v1.bytes)!!)
        assertEquals(2, r.revisions.size)
        val ch = r.revisions[1].changes.single()
        assertEquals(4, ch.num); assertEquals(ChangeType.REPLACED, ch.type); assertEquals(ObjectKind.CONTENT_STREAM, ch.kind); assertEquals(0, ch.page)
        val f = r.findings.first { it.id == "REV_UPDATE_1" }
        assertEquals(EvidenceClass.INDICATOR, f.evidence)
        assertTrue(f.unknown.contains("not an independent, trusted original"))
    }

    @Test fun metadataOnlyUpdateIsInformation() {
        val v0 = PdfSynth.build(PdfSynth.page() + (6 to "<< /Producer (Acme) /ModDate (D:20240101000000Z) >>"), "/Info 6 0 R")
        val v1 = PdfSynth.update(v0, mapOf(6 to "<< /Producer (Acme) /ModDate (D:20240601000000Z) >>"), "/Info 6 0 R")
        val r = RevisionAnalyzer.analyze(PdfFile.open(v1.bytes)!!)
        val f = r.findings.first { it.id == "REV_UPDATE_1" }
        assertEquals(EvidenceClass.INFO, f.evidence)
        assertEquals(1, r.revisions[1].infoChanges.size)
        assertTrue(r.revisions[1].infoChanges[0].startsWith("ModDate"))
    }

    @Test fun identicalRewriteIsNotCountedAsChange() {
        val v0 = PdfSynth.build(PdfSynth.page())
        val v1 = PdfSynth.update(v0, mapOf(5 to "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))
        val r = RevisionAnalyzer.analyze(PdfFile.open(v1.bytes)!!)
        assertEquals(ChangeType.REWRITTEN_IDENTICAL, r.revisions[1].changes.single().type)
        assertFalse(r.revisions[1].touchesVisibleContent)
    }

    @Test fun singleRevisionStatesHistoryUnavailableWithoutImplyingInnocence() {
        val r = RevisionAnalyzer.analyze(PdfFile.open(PdfSynth.build(PdfSynth.page()).bytes)!!)
        val f = r.findings.single()
        assertEquals("REV_SINGLE", f.id)
        assertTrue(f.unknown.contains("cannot be distinguished from an original"))
    }

    @Test fun threeRevisionsAreOrderedAndHashed() {
        val v0 = PdfSynth.build(PdfSynth.page("BT /F1 12 Tf 72 700 Td (A) Tj ET"))
        val v1 = PdfSynth.update(v0, mapOf(4 to PdfSynth.stream("", "BT /F1 12 Tf 72 700 Td (B) Tj ET")))
        val v2 = PdfSynth.update(v1, mapOf(4 to PdfSynth.stream("", "BT /F1 12 Tf 72 700 Td (C) Tj ET")))
        val r = RevisionAnalyzer.analyze(PdfFile.open(v2.bytes)!!)
        assertEquals(3, r.revisions.size)
        assertEquals(com.docintegrity.forensics.util.Hashing.sha256(v0.bytes), r.revisions[0].prefixSha256)
        assertEquals(com.docintegrity.forensics.util.Hashing.sha256(v1.bytes), r.revisions[1].prefixSha256)
        assertEquals(com.docintegrity.forensics.util.Hashing.sha256(v2.bytes), r.revisions[2].prefixSha256)
    }
}
