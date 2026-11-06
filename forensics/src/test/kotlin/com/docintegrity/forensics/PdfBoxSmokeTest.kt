package com.docintegrity.forensics

import androidx.test.core.app.ApplicationProvider
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import com.tom_roush.pdfbox.pdmodel.PDDocument
import com.tom_roush.pdfbox.text.PDFTextStripper
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PdfBoxSmokeTest {
    @Test
    fun loadsAndExtractsText() {
        PDFBoxResourceLoader.init(ApplicationProvider.getApplicationContext())
        val content = "BT /F1 24 Tf 72 700 Td (Hello Forensics 1,234.50) Tj ET"
        val objs = listOf(
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            "<< /Length ${content.length} >>\nstream\n$content\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        )
        val sb = StringBuilder("%PDF-1.4\n")
        val offs = ArrayList<Int>()
        objs.forEachIndexed { i, o -> offs.add(sb.length); sb.append("${i + 1} 0 obj\n$o\nendobj\n") }
        val xref = sb.length
        sb.append("xref\n0 ${objs.size + 1}\n0000000000 65535 f \n")
        offs.forEach { sb.append(String.format("%010d 00000 n \n", it)) }
        sb.append("trailer\n<< /Size ${objs.size + 1} /Root 1 0 R >>\nstartxref\n$xref\n%%EOF\n")
        val bytes = sb.toString().toByteArray(Charsets.ISO_8859_1)
        PDDocument.load(bytes).use { doc ->
            val text = PDFTextStripper().getText(doc)
            println("EXTRACTED: [$text]")
            assertTrue(text.contains("Hello Forensics 1,234.50"))
        }
    }
}
