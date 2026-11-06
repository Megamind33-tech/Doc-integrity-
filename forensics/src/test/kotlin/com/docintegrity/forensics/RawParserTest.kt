package com.docintegrity.forensics

import com.docintegrity.forensics.pdf.raw.PdfDict
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.pdf.raw.PdfInt
import com.docintegrity.forensics.pdf.raw.PdfLexer
import com.docintegrity.forensics.pdf.raw.PdfName
import com.docintegrity.forensics.pdf.raw.PdfRef
import com.docintegrity.forensics.pdf.raw.PdfString
import com.docintegrity.forensics.pdf.raw.PdfArray
import com.docintegrity.forensics.util.Hashing
import org.junit.Assert.*
import org.junit.Test

class RawParserTest {
    private fun parse(s: String) = PdfLexer(s.toByteArray(Charsets.ISO_8859_1)).parseObject()

    @Test fun parsesScalarsNamesStringsRefs() {
        assertEquals(PdfInt(-12), parse("-12"))
        assertEquals(PdfName("A B"), parse("/A#20B"))
        assertEquals("a(b)c\n", (parse("(a\\(b\\)c\\n)") as PdfString).text())
        assertEquals("AB", (parse("<4142>") as PdfString).text())
        assertEquals(PdfRef(12, 0), parse("12 0 R"))
        val arr = parse("[1 2 R 3 /X (s)]") as PdfArray
        assertEquals(4, arr.size)   // "1 2 R" is one ref
        val d = parse("<< /A 1 /B << /C [1 2 3] >> /D (x) >>") as PdfDict
        assertEquals(1L, d.int("A"))
        assertNotNull(d.dict("B"))
    }

    @Test fun utf16StringsDecode() {
        val s = parse("<FEFF0041004200E9>") as PdfString
        assertEquals("ABé", s.text())
    }

    @Test fun readsSingleRevisionDocument() {
        val doc = PdfSynth.build(PdfSynth.page())
        val f = PdfFile.open(doc.bytes)!!
        assertEquals(1, f.revisions.size)
        assertFalse(f.xrefReconstructed)
        assertEquals("1.4", f.version)
        assertTrue(f.hasBinaryMarkerComment)
        assertEquals(0, f.trailingDataBytes)
        assertEquals(doc.bytes.size, f.revisions[0].prefixEnd)
    }

    @Test fun incrementalUpdateGivesRecoverableEarlierRevision() {
        val v0 = PdfSynth.build(PdfSynth.page("BT /F1 12 Tf 72 700 Td (Pay 100) Tj ET"))
        val v1 = PdfSynth.update(v0, mapOf(4 to PdfSynth.stream("", "BT /F1 12 Tf 72 700 Td (Pay 900) Tj ET")))
        val f = PdfFile.open(v1.bytes)!!
        assertEquals(2, f.revisions.size)
        // earlier revision reconstructs byte-for-byte
        assertEquals(Hashing.sha256(v0.bytes), Hashing.sha256(f.prefix(0)))
        // each revision resolves object 4 to its own content
        fun content(rev: Int) = String((f.getObject(4, rev) as com.docintegrity.forensics.pdf.raw.PdfStream).rawBytes(), Charsets.ISO_8859_1)
        assertTrue(content(0).contains("Pay 100"))
        assertTrue(content(1).contains("Pay 900"))
    }

    @Test fun commentLineAfterEofDoesNotMoveTheRevisionBoundary() {
        // Regression: editors such as MuPDF write "% Written by ..." after %%EOF.
        val v0 = PdfSynth.build(PdfSynth.page("BT /F1 12 Tf 72 700 Td (Pay 100) Tj ET"))
        val padded = PdfSynth.Doc(v0.bytes + "\n% Written by TestEditor 1.0\n\n".toByteArray(), v0.offsets, v0.size)
        val v1 = PdfSynth.update(padded, mapOf(4 to PdfSynth.stream("", "BT /F1 12 Tf 72 700 Td (Pay 900) Tj ET")))
        val f = PdfFile.open(v1.bytes)!!
        assertEquals(2, f.revisions.size)
        assertEquals(v0.bytes.size, f.revisions[0].prefixEnd)
        assertEquals(Hashing.sha256(v0.bytes), Hashing.sha256(f.prefix(0)))
    }

    @Test fun damagedXrefIsRebuiltAndReported() {
        val doc = PdfSynth.build(PdfSynth.page())
        val s = String(doc.bytes, Charsets.ISO_8859_1)
        val broken = s.substringBeforeLast("startxref") + "startxref\n99999\n%%EOF\n"
        val f = PdfFile.open(broken.toByteArray(Charsets.ISO_8859_1))!!
        assertTrue(f.xrefReconstructed)
        assertNotNull(f.getObject(4))
    }

    @Test fun notAPdfIsRejected() {
        assertNull(PdfFile.open("hello world, this is text".toByteArray()))
    }

    @Test fun readsXrefStreamAndObjectStreamFromRealFiles() {
        // LibreOffice (PDF 1.7) and Chromium (Skia) write compressed object/xref streams
        for (n in listOf("B_roundtrip_unchanged.pdf", "N1_control_browser_print.pdf", "E_native_docx_export.pdf")) {
            val f = PdfFile.open(Fixtures.bytes(n))!!
            assertFalse("$n xref rebuilt", f.xrefReconstructed)
            assertNotNull("$n has catalog", f.getObject((f.trailerValue("Root") as PdfRef).num))
        }
    }

    @Test fun linearisedFileIsOneRevision() {
        val f = PdfFile.open(Fixtures.bytes("G0_scan_unedited.pdf"))!!
        assertTrue(f.linearized)
        assertEquals(1, f.revisions.size)
    }
}
