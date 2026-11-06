package com.docintegrity.forensics

import com.docintegrity.forensics.compare.DocxReader
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class DocxReaderTest {
    private fun docx(documentXml: String, extra: Map<String, ByteArray> = emptyMap()): ByteArray {
        val bo = ByteArrayOutputStream()
        ZipOutputStream(bo).use { z ->
            fun put(n: String, b: ByteArray) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() }
            put("word/document.xml", documentXml.toByteArray())
            for ((n, b) in extra) put(n, b)
        }
        return bo.toByteArray()
    }
    private val NS = "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\""

    @Test fun extractsParagraphsTablesAndHeaders() {
        val d = docx(
            """<w:document $NS><w:body><w:p><w:r><w:t>Receipt No: RC-1</w:t></w:r></w:p>
               <w:tbl><w:tr><w:tc><w:p><w:r><w:t>Total</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>ZMW 4,250.00</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>""",
            mapOf("word/header1.xml" to """<w:hdr $NS><w:p><w:r><w:t>Finance Office</w:t></w:r></w:p></w:hdr>""".toByteArray()),
        )
        assertTrue(DocxReader.looksLikeDocx(d))
        val c = DocxReader.read(d)!!
        assertTrue(c.text.contains("Receipt No: RC-1"))
        assertTrue(c.text.contains("ZMW 4,250.00"))
        assertTrue("headers are part of what a reader sees", c.text.contains("Finance Office"))
    }

    @Test fun trackedChangesAreCountedAndDeletedTextExcluded() {
        val d = docx("""<w:document $NS><w:body><w:p><w:r><w:t>Pay </w:t></w:r>
            <w:del w:id="1" w:author="Alice" w:date="2024-05-01T10:00:00Z"><w:r><w:delText>100</w:delText></w:r></w:del>
            <w:ins w:id="2" w:author="Bob"><w:r><w:t>900</w:t></w:r></w:ins></w:p></w:body></w:document>""")
        val c = DocxReader.read(d)!!
        assertEquals("Pay 900", c.text.replace(Regex("\\s+"), " ").trim())
        assertEquals(1, c.trackedDeletions); assertEquals(1, c.trackedInsertions)
        assertEquals(setOf("Alice", "Bob"), c.revisionAuthors)
    }

    @Test fun corePropertiesAreRead() {
        val d = docx("""<w:document $NS><w:body><w:p><w:r><w:t>x</w:t></w:r></w:p></w:body></w:document>""",
            mapOf("docProps/core.xml" to """<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Finance</dc:creator><cp:lastModifiedBy>Someone Else</cp:lastModifiedBy></cp:coreProperties>""".toByteArray()))
        val c = DocxReader.read(d)!!
        assertEquals("Someone Else", c.core["lastModifiedBy"])
    }

    @Test fun doctypeIsRefusedNotParsed() {
        val d = docx("""<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><w:document $NS><w:body><w:p><w:r><w:t>&x;</w:t></w:r></w:p></w:body></w:document>""")
        assertNull(DocxReader.read(d))
    }

    @Test fun nonDocxIsRejected() {
        assertFalse(DocxReader.looksLikeDocx("%PDF-1.4".toByteArray()))
        assertFalse(DocxReader.looksLikeDocx(ByteArray(0)))
        assertNull(DocxReader.read(ByteArray(10)))
    }
}
