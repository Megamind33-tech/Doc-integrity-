package com.docintegrity.forensics.compare

import java.io.ByteArrayInputStream
import java.util.zip.ZipInputStream
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.w3c.dom.Node

class DocxImage(val name: String, val bytes: ByteArray)

class DocxContent(
    /** Body text, one paragraph per line, then headers/footers/footnotes. Deleted (tracked) text is excluded. */
    val text: String,
    val images: List<DocxImage>,
    val core: Map<String, String>,
    val app: Map<String, String>,
    val trackedInsertions: Int,
    val trackedDeletions: Int,
    val revisionAuthors: Set<String>,
    val hasComments: Boolean,
)

/** Reads the parts of a .docx that matter for comparison. XML is parsed only if it contains no DOCTYPE/ENTITY. */
object DocxReader {
    private const val W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    private const val MAX_ENTRY = 64L * 1024 * 1024
    private const val MAX_TOTAL = 256L * 1024 * 1024

    fun looksLikeDocx(bytes: ByteArray): Boolean {
        if (bytes.size < 4 || bytes[0] != 'P'.code.toByte() || bytes[1] != 'K'.code.toByte()) return false
        return try { readEntries(bytes).containsKey("word/document.xml") } catch (e: Exception) { false }
    }

    private fun readEntries(bytes: ByteArray): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        var total = 0L
        ZipInputStream(ByteArrayInputStream(bytes)).use { z ->
            while (true) {
                val e = z.nextEntry ?: break
                if (e.isDirectory) continue
                val keep = e.name == "word/document.xml" || e.name.startsWith("word/media/") || e.name.matches(Regex("word/(header|footer)\\d*\\.xml")) ||
                    e.name == "word/footnotes.xml" || e.name == "word/endnotes.xml" || e.name == "docProps/core.xml" || e.name == "docProps/app.xml" || e.name == "word/comments.xml"
                val buf = java.io.ByteArrayOutputStream()
                val tmp = ByteArray(16 * 1024)
                var n: Int
                var size = 0L
                while (z.read(tmp).also { n = it } > 0) {
                    size += n; total += n
                    if (size > MAX_ENTRY || total > MAX_TOTAL) throw IllegalStateException("archive too large (possible zip bomb)")
                    if (keep) buf.write(tmp, 0, n)
                }
                if (keep) out[e.name] = buf.toByteArray()
            }
        }
        return out
    }

    fun read(bytes: ByteArray): DocxContent? {
        val parts = try { readEntries(bytes) } catch (e: Exception) { return null }
        val doc = parts["word/document.xml"] ?: return null
        var ins = 0; var del = 0
        val authors = LinkedHashSet<String>()
        val sb = StringBuilder()
        fun parse(b: ByteArray): Element? {
            val s = String(b, Charsets.UTF_8)
            if (s.contains("<!DOCTYPE", true) || s.contains("<!ENTITY", true)) return null
            return try {
                val f = DocumentBuilderFactory.newInstance(); f.isNamespaceAware = true
                f.newDocumentBuilder().parse(ByteArrayInputStream(b)).documentElement
            } catch (e: Exception) { null }
        }
        fun walk(n: Node, para: StringBuilder) {
            var c = n.firstChild
            while (c != null) {
                if (c is Element) {
                    val ln = c.localName
                    if (c.namespaceURI == W) {
                        when (ln) {
                            "del" -> { del++; c.getAttributeNS(W, "author").takeIf { it.isNotEmpty() }?.let { authors.add(it) } }
                            "delText", "instrText" -> {}
                            "t" -> para.append(c.textContent)
                            "tab" -> para.append('\t')
                            "br", "cr" -> para.append(' ')
                            "noBreakHyphen" -> para.append('-')
                            "ins" -> { ins++; c.getAttributeNS(W, "author").takeIf { it.isNotEmpty() }?.let { authors.add(it) }; walk(c, para) }
                            "p" -> { val p = StringBuilder(); walk(c, p); sb.append(p.toString().trim()).append('\n') }
                            else -> walk(c, para)
                        }
                    } else walk(c, para)
                }
                c = c.nextSibling
            }
        }
        parse(doc)?.let { walk(it, StringBuilder()) } ?: return null
        for ((name, b) in parts) if (name.matches(Regex("word/(header|footer)\\d*\\.xml")) || name == "word/footnotes.xml" || name == "word/endnotes.xml") parse(b)?.let { walk(it, StringBuilder()) }
        fun props(b: ByteArray?): Map<String, String> {
            val root = b?.let { parse(it) } ?: return emptyMap()
            val m = LinkedHashMap<String, String>()
            var c = root.firstChild
            while (c != null) { if (c is Element) m[c.localName] = c.textContent.trim(); c = c.nextSibling }
            return m
        }
        return DocxContent(
            text = sb.toString().trimEnd(),
            images = parts.filterKeys { it.startsWith("word/media/") }.map { DocxImage(it.key.substringAfterLast('/'), it.value) },
            core = props(parts["docProps/core.xml"]), app = props(parts["docProps/app.xml"]),
            trackedInsertions = ins, trackedDeletions = del, revisionAuthors = authors, hasComments = parts.containsKey("word/comments.xml"),
        )
    }
}
