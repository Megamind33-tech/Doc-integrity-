package com.docintegrity.forensics.pdf.analysis

import com.docintegrity.forensics.pdf.raw.PdfArray
import com.docintegrity.forensics.pdf.raw.PdfDict
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.pdf.raw.PdfName
import com.docintegrity.forensics.pdf.raw.PdfObj
import com.docintegrity.forensics.pdf.raw.PdfRef
import com.docintegrity.forensics.pdf.raw.PdfStream
import com.docintegrity.forensics.pdf.raw.PdfString
import com.docintegrity.forensics.pdf.raw.StreamDecoder
import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.w3c.dom.Node

data class XmpEvent(
    val action: String?,
    val whenIso: String?,
    val softwareAgent: String?,
    val changed: String?,
    val parameters: String?,
    val instanceId: String?,
)

data class XmpData(
    /** Flattened simple properties, keyed "prefix:name". List-valued properties are joined with "; ". */
    val props: Map<String, String>,
    val history: List<XmpEvent>,
    val derivedFrom: Map<String, String>,
)

/** Result of looking for XMP: either absent, rejected for safety, unparseable, or parsed. */
class XmpResult(val present: Boolean, val rawLength: Int, val data: XmpData?, val note: String?)

object MetadataReader {

    private val INFO_KEYS = listOf("Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate", "Trapped")

    fun catalog(file: PdfFile, rev: Int): PdfDict? {
        val root = file.trailerValue("Root", rev)
        return file.resolve(root, rev) as? PdfDict
    }

    /** All string-valued Info entries as of [rev] (null if there is no Info dictionary). */
    fun readInfo(file: PdfFile, rev: Int): Map<String, String>? {
        val ref = file.trailerValue("Info", rev)
        val d = file.resolve(ref, rev) as? PdfDict ?: return null
        val out = LinkedHashMap<String, String>()
        for (k in INFO_KEYS) valueText(file, d[k], rev)?.let { out[k] = it }
        for ((k, v) in d.map) if (k !in INFO_KEYS) valueText(file, v, rev)?.let { out[k] = it }
        return out
    }

    private fun valueText(file: PdfFile, o: PdfObj?, rev: Int): String? = when (val r = file.resolve(o, rev)) {
        is PdfString -> r.text()
        is PdfName -> "/" + r.value
        else -> null
    }

    /** Trailer /ID as hex strings (permanent id, instance id) as of [rev]. */
    fun readFileId(file: PdfFile, rev: Int): Pair<String, String>? {
        val a = file.resolve(file.trailerValue("ID", rev), rev) as? PdfArray ?: return null
        val x = (a[0] as? PdfString)?.bytes ?: return null
        val y = (a[1] as? PdfString)?.bytes ?: return null
        return com.docintegrity.forensics.util.Hashing.hex(x) to com.docintegrity.forensics.util.Hashing.hex(y)
    }

    fun readXmp(file: PdfFile, rev: Int): XmpResult {
        val cat = catalog(file, rev) ?: return XmpResult(false, 0, null, null)
        val stream = file.resolve(cat["Metadata"], rev) as? PdfStream ?: return XmpResult(false, 0, null, null)
        val bytes = StreamDecoder.decode(stream).bytes
        return parseXmp(bytes)
    }

    fun parseXmp(bytes: ByteArray): XmpResult {
        val text = String(bytes, Charsets.UTF_8)
        // Never hand attacker-controlled DTDs/entities to an XML parser (XXE / entity expansion).
        if (text.contains("<!DOCTYPE", ignoreCase = true) || text.contains("<!ENTITY", ignoreCase = true)) {
            return XmpResult(true, bytes.size, null, "XMP contains a DOCTYPE/ENTITY declaration; it was NOT parsed for safety (this is itself unusual).")
        }
        return try {
            val dbf = DocumentBuilderFactory.newInstance()
            dbf.isNamespaceAware = true
            dbf.isXIncludeAware = false
            val doc = dbf.newDocumentBuilder().parse(ByteArrayInputStream(bytes))
            XmpResult(true, bytes.size, extract(doc.documentElement), null)
        } catch (e: Exception) {
            XmpResult(true, bytes.size, null, "XMP packet present but not parseable XML (${e.javaClass.simpleName}).")
        }
    }

    private const val RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
    private val PREFIX = mapOf(
        "http://purl.org/dc/elements/1.1/" to "dc",
        "http://ns.adobe.com/xap/1.0/" to "xmp",
        "http://ns.adobe.com/pdf/1.3/" to "pdf",
        "http://ns.adobe.com/xap/1.0/mm/" to "xmpMM",
        "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#" to "stEvt",
        "http://ns.adobe.com/xap/1.0/sType/ResourceRef#" to "stRef",
        "http://www.aiim.org/pdfa/ns/id/" to "pdfaid",
        "http://ns.adobe.com/photoshop/1.0/" to "photoshop",
        "http://ns.microsoft.com/office/2006/metadata/properties" to "msoffice",
    )

    private fun qname(e: Node): String {
        val uri = e.namespaceURI
        val p = PREFIX[uri] ?: e.prefix ?: ""
        val l = e.localName ?: e.nodeName
        return if (p.isEmpty()) l else "$p:$l"
    }

    private fun children(e: Element): List<Element> {
        val out = ArrayList<Element>()
        var c = e.firstChild
        while (c != null) { if (c is Element) out.add(c); c = c.nextSibling }
        return out
    }

    private fun extract(root: Element): XmpData {
        val props = LinkedHashMap<String, String>()
        val history = ArrayList<XmpEvent>()
        val derived = LinkedHashMap<String, String>()
        fun walk(e: Element) {
            if (e.namespaceURI == RDF && e.localName == "Description") {
                val attrs = e.attributes
                for (i in 0 until attrs.length) {
                    val a = attrs.item(i)
                    if (a.namespaceURI == "http://www.w3.org/2000/xmlns/" || a.nodeName.startsWith("xmlns")) continue
                    if (a.namespaceURI == RDF) continue
                    props[qname(a)] = a.nodeValue
                }
                for (c in children(e)) {
                    val name = qname(c)
                    when (name) {
                        "xmpMM:History" -> history.addAll(parseHistory(c))
                        "xmpMM:DerivedFrom" -> derived.putAll(parseStruct(c))
                        else -> flattenValue(c)?.let { if (it.isNotEmpty() && props.size < 300) props[name] = it }
                    }
                }
            } else {
                for (c in children(e)) walk(c)
            }
        }
        walk(root)
        return XmpData(props, history, derived)
    }

    private fun flattenValue(e: Element): String? {
        val kids = children(e)
        if (kids.isEmpty()) return e.textContent?.trim()
        val container = kids.firstOrNull { it.namespaceURI == RDF && (it.localName == "Seq" || it.localName == "Bag" || it.localName == "Alt") }
        if (container != null) {
            return children(container).filter { it.localName == "li" }.joinToString("; ") { it.textContent?.trim().orEmpty() }
        }
        return e.textContent?.trim()
    }

    private fun parseStruct(e: Element): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        fun collect(x: Element) {
            val attrs = x.attributes
            for (i in 0 until attrs.length) {
                val a = attrs.item(i)
                if (a.namespaceURI == RDF || a.nodeName.startsWith("xmlns")) continue
                out[qname(a)] = a.nodeValue
            }
            for (c in children(x)) {
                if (c.namespaceURI == RDF && c.localName == "Description") collect(c) else out[qname(c)] = c.textContent?.trim().orEmpty()
            }
        }
        collect(e)
        return out
    }

    private fun parseHistory(e: Element): List<XmpEvent> {
        val seq = children(e).firstOrNull { it.namespaceURI == RDF } ?: return emptyList()
        return children(seq).filter { it.localName == "li" }.map { li ->
            val m = parseStruct(li)
            XmpEvent(
                action = m["stEvt:action"], whenIso = m["stEvt:when"], softwareAgent = m["stEvt:softwareAgent"],
                changed = m["stEvt:changed"], parameters = m["stEvt:parameters"], instanceId = m["stEvt:instanceID"],
            )
        }
    }
}
