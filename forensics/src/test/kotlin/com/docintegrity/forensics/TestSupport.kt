package com.docintegrity.forensics

import com.docintegrity.forensics.compare.PageRenderer
import com.docintegrity.forensics.image.GrayImage
import java.io.File

/** Renders pages with poppler's pdftoppm (test environment only). */
class PdftoppmRenderer : PageRenderer {
    override fun render(pdfBytes: ByteArray, page: Int, widthPx: Int): GrayImage? {
        val dir = java.nio.file.Files.createTempDirectory("render").toFile()
        try {
            val pdf = File(dir, "in.pdf").also { it.writeBytes(pdfBytes) }
            val p = ProcessBuilder("pdftoppm", "-gray", "-f", "${page + 1}", "-l", "${page + 1}", "-scale-to-x", "$widthPx", "-scale-to-y", "-1", pdf.path, File(dir, "out").path)
                .redirectErrorStream(true).start()
            p.inputStream.readBytes(); p.waitFor()
            val out = dir.listFiles()!!.firstOrNull { it.name.startsWith("out") } ?: return null
            return readPgm(out.readBytes())
        } finally { dir.deleteRecursively() }
    }

    private fun readPgm(b: ByteArray): GrayImage {
        var p = 0
        fun token(): String { while (b[p].toInt().toChar().isWhitespace()) p++; val s = p; while (!b[p].toInt().toChar().isWhitespace()) p++; return String(b, s, p - s) }
        require(token() == "P5")
        val w = token().toInt(); val h = token().toInt(); token(); p++
        return GrayImage(w, h, b.copyOfRange(p, p + w * h))
    }

    companion object {
        val available: Boolean by lazy { try { ProcessBuilder("pdftoppm", "-v").redirectErrorStream(true).start().also { it.inputStream.readBytes() }.waitFor(); true } catch (e: Exception) { false } }
    }
}
