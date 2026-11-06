package com.docintegrity.forensics

/**
 * Builds small, fully controlled PDFs for edge-case tests (damaged xref, rolled-back updates, conflicting
 * metadata, orphaned content). Real-world behaviour is covered separately by the generated fixtures.
 */
object PdfSynth {
    fun stream(dict: String, data: String) = "<< $dict /Length ${data.length} >>\nstream\n$data\nendstream"

    class Doc(val bytes: ByteArray, val offsets: Map<Int, Int>, val size: Int)

    /** Objects: number -> body. Object 1 must be the catalog. [trailerExtra] is appended inside the trailer dict. */
    fun build(objects: Map<Int, String>, trailerExtra: String = "", version: String = "1.4"): Doc {
        val sb = StringBuilder("%PDF-$version\n%âãÏÓ\n")
        val offs = LinkedHashMap<Int, Int>()
        for ((n, body) in objects) { offs[n] = sb.length; sb.append("$n 0 obj\n$body\nendobj\n") }
        val size = (objects.keys.maxOrNull() ?: 0) + 1
        val xref = sb.length
        sb.append("xref\n0 $size\n")
        sb.append("0000000000 65535 f \n")
        for (n in 1 until size) {
            val o = offs[n]
            if (o == null) sb.append("0000000000 00000 f \n") else sb.append(String.format("%010d 00000 n \n", o))
        }
        sb.append("trailer\n<< /Size $size /Root 1 0 R $trailerExtra >>\nstartxref\n$xref\n%%EOF\n")
        return Doc(sb.toString().toByteArray(Charsets.ISO_8859_1), offs, size)
    }

    /** Appends an incremental update replacing/adding [objects]; returns the new full file. */
    fun update(base: Doc, objects: Map<Int, String>, trailerExtra: String = "", prevXref: Int? = null): Doc {
        val prev = prevXref ?: Regex("startxref\\s+(\\d+)").findAll(String(base.bytes, Charsets.ISO_8859_1)).last().groupValues[1].toInt()
        val sb = StringBuilder(String(base.bytes, Charsets.ISO_8859_1))
        val offs = LinkedHashMap<Int, Int>(base.offsets)
        val changed = LinkedHashMap<Int, Int>()
        for ((n, body) in objects) { changed[n] = sb.length; offs[n] = sb.length; sb.append("$n 0 obj\n$body\nendobj\n") }
        val size = maxOf(base.size, (objects.keys.maxOrNull() ?: 0) + 1)
        val xref = sb.length
        sb.append("xref\n")
        for ((n, o) in changed.entries.sortedBy { it.key }) sb.append("$n 1\n").append(String.format("%010d 00000 n \n", o))
        sb.append("trailer\n<< /Size $size /Root 1 0 R /Prev $prev $trailerExtra >>\nstartxref\n$xref\n%%EOF\n")
        return Doc(sb.toString().toByteArray(Charsets.ISO_8859_1), offs, size)
    }

    fun page(contents: String = "BT /F1 12 Tf 72 700 Td (Hello) Tj ET"): Map<Int, String> = linkedMapOf(
        1 to "<< /Type /Catalog /Pages 2 0 R >>",
        2 to "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3 to "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        4 to stream("", contents),
        5 to "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    )

    fun xmp(vararg props: String, history: String = ""): String =
        stream(
            "/Type /Metadata /Subtype /XML",
            """<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:pdf="http://ns.adobe.com/pdf/1.3/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#">${props.joinToString("")}$history</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>""",
        )
}
