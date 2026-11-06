package com.docintegrity.forensics.pdf.analysis

import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.pdf.raw.ContentTokenizer
import com.docintegrity.forensics.pdf.raw.PdfArray
import com.docintegrity.forensics.pdf.raw.PdfDict
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.pdf.raw.PdfLexer
import com.docintegrity.forensics.pdf.raw.PdfObj
import com.docintegrity.forensics.pdf.raw.PdfRef
import com.docintegrity.forensics.pdf.raw.PdfStream
import com.docintegrity.forensics.pdf.raw.StreamDecoder
import com.docintegrity.forensics.pdf.raw.XrefEntryType

class PageSummary(
    val index: Int,
    val width: Double?,
    val height: Double?,
    val rotate: Int,
    val contentStreams: Int,
    val images: Int,
    val annotations: Int,
    val fonts: List<String>,
)

class FontInfo(
    val resourceName: String,
    val objNum: Int?,
    val baseFont: String?,
    val subtype: String?,
    val embedded: Boolean,
    val subsetTag: String?,
    val face: String?,
    val hasToUnicode: Boolean,
    val pages: Set<Int>,
)

class OrphanGroup(val kind: ObjectKind, val objectNumbers: List<Int>, val recoveredText: List<String>)

class StructureResult(
    val pageCount: Int,
    val pages: List<PageSummary>,
    val fonts: List<FontInfo>,
    val orphans: List<OrphanGroup>,
    val findings: List<Finding>,
)

object StructureAnalyzer {

    private val STANDARD_14 = setOf(
        "Helvetica", "Helvetica-Bold", "Helvetica-Oblique", "Helvetica-BoldOblique", "Times-Roman", "Times-Bold", "Times-Italic",
        "Times-BoldItalic", "Courier", "Courier-Bold", "Courier-Oblique", "Courier-BoldOblique", "Symbol", "ZapfDingbats",
    )

    fun analyze(file: PdfFile): StructureResult {
        val findings = ArrayList<Finding>()
        val rev = file.lastRevision
        val view = DocView(file, rev)

        // ---- file framing ---------------------------------------------------------------------------------
        if (file.headerOffset > 0) {
            findings.add(
                Finding(
                    id = "STRUCT_HEADER_JUNK", area = Area.STRUCTURE, evidence = EvidenceClass.INFO,
                    title = "Data before the %PDF header",
                    detected = "${file.headerOffset} byte(s) precede the %PDF- header.",
                    establishes = "The file does not begin with the PDF header. Readers tolerate up to 1024 bytes of leading data; all byte offsets in the file are then shifted.",
                    unknown = "Mail gateways and some uploaders prepend data; so can manual editing.",
                ),
            )
        }
        if (file.trailingDataBytes > 0) {
            findings.add(
                Finding(
                    id = "STRUCT_TRAILING_DATA", area = Area.STRUCTURE, evidence = EvidenceClass.INDICATOR,
                    title = "Data after the final %%EOF marker",
                    detected = "${file.trailingDataBytes} non-whitespace byte(s) follow the last %%EOF.",
                    establishes = "The file contains bytes that no revision accounts for.",
                    unknown = "Possible causes: a truncated or interrupted incremental update, a rolled-back revision, transfer corruption, or a payload appended on purpose. The bytes were not interpreted as document content.",
                ),
            )
        }
        if (file.encrypted) {
            findings.add(
                Finding(
                    id = "STRUCT_ENCRYPTED", area = Area.STRUCTURE, evidence = EvidenceClass.LIMITATION, blocking = true,
                    title = "Document is encrypted",
                    detected = "The trailer declares /Encrypt.",
                    establishes = "Streams and strings are encrypted. The structural parser cannot read content streams, fonts or metadata strings without decryption.",
                    unknown = "Everything about content inside encrypted objects. Cross-reference structure and object counts were still examined.",
                ),
            )
        }
        if (file.linearized) {
            val declared = file.linearizedDeclaredLength
            val rev0End = file.revisions.firstOrNull()?.prefixEnd
            if (declared != null && rev0End != null && Math.abs(declared - rev0End.toLong()) > 3) {
                val updated = file.revisions.size > 1
                findings.add(
                    Finding(
                        id = "STRUCT_LINEARIZED_MISMATCH", area = Area.STRUCTURE,
                        evidence = if (updated) EvidenceClass.INFO else EvidenceClass.INDICATOR,
                        title = "Linearisation length does not match the file",
                        detected = "The /Linearized dictionary declares length $declared, but the first revision ends at byte $rev0End.",
                        establishes = if (updated) "The file was extended after it was linearised (consistent with the incremental updates found)." else "The declared linearised length does not match the actual file; the file was altered or truncated after optimisation, or the writer was faulty.",
                        unknown = "Line-ending conversion during transfer also changes the length. The file cannot show which cause applies.",
                    ),
                )
            }
        }

        // ---- cross-reference integrity ---------------------------------------------------------------------
        val knownOffsets = HashSet<Int>()
        var checked = 0
        val mismatches = ArrayList<String>()
        val streamRanges = ArrayList<IntRange>()
        for (r in file.revisions) for (s in r.sections) for ((num, e) in s.entries) {
            if (e.type != XrefEntryType.IN_USE) continue
            val off = e.a.toInt()
            knownOffsets.add(off)
            if (file.xrefReconstructed) continue
            checked++
            val ind = file.indirectAt(off)
            if (ind == null || ind.num != num) {
                if (mismatches.size < 10) mismatches.add("object $num: xref offset $off does not start \"$num ${e.b} obj\"")
                else if (mismatches.size == 10) mismatches.add("…")
            } else (ind.value as? PdfStream)?.let { streamRanges.add(it.dataStart until it.dataStart + it.dataLength) }
        }
        val mismatchCount = mismatches.count { it != "…" }
        if (!file.xrefReconstructed && mismatchCount > 0) {
            findings.add(
                Finding(
                    id = "STRUCT_XREF_MISMATCH", area = Area.STRUCTURE, evidence = EvidenceClass.INDICATOR,
                    title = "Cross-reference offsets do not match object positions",
                    detected = "$mismatchCount of $checked cross-reference entries point to the wrong place" + (if (mismatches.contains("…")) " (first 10 shown)." else "."),
                    establishes = "Bytes in the file were inserted, removed or moved after the cross-reference table was written, or the writer was defective. Viewers silently repair this.",
                    unknown = "Hand-editing a PDF in a hex editor produces exactly this pattern, but so do buggy generators and damaged transfers.",
                    details = mismatches.map { "xref" to it },
                ),
            )
        } else if (file.xrefReconstructed) {
            findings.add(
                Finding(
                    id = "STRUCT_XREF_REBUILT", area = Area.STRUCTURE, evidence = EvidenceClass.INDICATOR,
                    title = "Cross-reference data missing or unusable",
                    detected = file.structuralNotes.joinToString("; ").ifEmpty { "Object table was rebuilt by scanning." },
                    establishes = "A normal PDF reader would have had to repair this file to open it.",
                    unknown = "Truncation, damaged transfer, defective writers and manual byte-level editing are all possible causes.",
                ),
            )
        }
        val missingMarkers = file.structuralNotes.filter { it.startsWith("revision") }
        if (missingMarkers.isNotEmpty()) {
            findings.add(
                Finding(
                    id = "STRUCT_MARKER_MISSING", area = Area.STRUCTURE, evidence = EvidenceClass.INFO,
                    title = "Revision end marker not found", detected = missingMarkers.joinToString("; "),
                    establishes = "A cross-reference section has no matching startxref/%%EOF.",
                    unknown = "Reconstructed version boundaries for this revision are approximate.",
                ),
            )
        }

        // ---- objects not listed in any cross-reference section ----------------------------------------------
        if (!file.xrefReconstructed) {
            val unlisted = scanUnlistedObjects(file, knownOffsets, streamRanges)
            if (unlisted.isNotEmpty()) {
                findings.add(
                    Finding(
                        id = "STRUCT_UNLISTED_OBJECTS", area = Area.STRUCTURE, evidence = EvidenceClass.INDICATOR,
                        title = "Objects present in the file but absent from every cross-reference section",
                        detected = "${unlisted.size} object header(s) found outside any listed stream: " + unlisted.take(8).joinToString { "obj ${it.first} at byte ${it.second}" } + if (unlisted.size > 8) ", …" else ".",
                        establishes = "The file holds object data that no revision lists. It is invisible to a normal reader.",
                        unknown = "Typical benign causes are leftovers from a tool that appended without cleaning up, or a rolled-back/truncated update. Hidden or discarded content is another possibility; the objects were not decoded as document content.",
                    ),
                )
            }
        }

        // ---- pages, fonts -----------------------------------------------------------------------------------
        val fonts = collectFonts(file, view)
        val pages = view.pages.map { p ->
            val imgs = view.xobjectOwner.entries.count { (num, owners) ->
                p.index in owners && (file.getObject(num, rev).let { o -> (o as? PdfStream)?.dict?.name("Subtype") == "Image" })
            }
            val annots = (file.resolve(p.dict["Annots"], rev) as? PdfArray)?.size ?: 0
            val cs = when (val c = file.resolve(p.dict["Contents"], rev)) { is PdfArray -> c.size; null -> 0; else -> 1 }
            val box = p.mediaBox
            PageSummary(
                p.index, box?.let { Math.abs(it[2] - it[0]) }, box?.let { Math.abs(it[3] - it[1]) }, p.rotate, cs, imgs, annots,
                fonts.filter { p.index in it.pages }.map { it.baseFont ?: it.resourceName },
            )
        }
        if (view.catalog == null && !file.encrypted) {
            findings.add(
                Finding(
                    id = "STRUCT_NO_CATALOG", area = Area.STRUCTURE, evidence = EvidenceClass.INDICATOR,
                    title = "Document catalog could not be read",
                    detected = "The trailer's /Root does not resolve to a catalog dictionary.",
                    establishes = "The page tree could not be reached; page-level checks did not run.",
                    unknown = "Damage, truncation or manual editing.",
                ),
            )
        }

        // font findings
        if (fonts.isNotEmpty()) {
            findings.add(
                Finding(
                    id = "FONT_LIST", area = Area.FONTS, evidence = EvidenceClass.INFO,
                    title = "${fonts.map { it.face ?: it.baseFont }.distinct().size} font face(s) used",
                    detected = fonts.joinToString("\n") { f ->
                        "${f.baseFont ?: "(unnamed)"} · ${f.subtype ?: "?"} · ${if (f.embedded) "embedded" else "not embedded"}" +
                            (f.subsetTag?.let { " · subset $it" } ?: "") + " · pages ${f.pages.sorted().joinToString { (it + 1).toString() }}"
                    },
                    establishes = "These are the font resources the pages declare.",
                    unknown = "Fonts show how text was typeset, not what it says or who wrote it. Software substitutes fonts during conversion, so the same visible document can legitimately use different fonts in different files.",
                ),
            )
            val multi = fonts.filter { it.face != null && it.subsetTag != null }
                .groupBy { it.face!! }
                .filter { (_, list) -> list.map { it.subsetTag }.distinct().size > 1 }
                .flatMap { (face, list) ->
                    val pageSets = list.flatMap { it.pages }.groupingBy { it }.eachCount().filter { it.value > 1 }.keys
                    if (pageSets.isEmpty()) emptyList() else listOf(Triple(face, list.map { it.subsetTag!! }.distinct(), pageSets.sorted()))
                }
            if (multi.isNotEmpty()) {
                findings.add(
                    Finding(
                        id = "FONT_MULTI_SUBSET", area = Area.FONTS, evidence = EvidenceClass.INDICATOR,
                        title = "Same typeface embedded as several separate subsets on one page",
                        detected = multi.joinToString("; ") { (face, tags, pgs) -> "$face as ${tags.joinToString("/")} on page ${pgs.joinToString { (it + 1).toString() }}" },
                        establishes = "Text on the same page was set with the same typeface but through different font subsets. Most generators create one subset per typeface for a document.",
                        unknown = "Editors that insert or replace text often create a new subset, but so do tools that merge or overlay pages and some print drivers. This is a prompt to look at the text, not proof of editing.",
                    ),
                )
            }
        }

        // ---- orphaned objects ---------------------------------------------------------------------------------
        val orphans = if (!file.xrefReconstructed && !file.encrypted) findOrphans(file, view) else emptyList()
        if (orphans.isNotEmpty()) {
            val notable = orphans.filter { it.kind in setOf(ObjectKind.PAGE, ObjectKind.CONTENT_STREAM, ObjectKind.IMAGE, ObjectKind.FORM_XOBJECT) }
            findings.add(
                Finding(
                    id = "STRUCT_ORPHANS", area = Area.STRUCTURE,
                    evidence = if (notable.isNotEmpty()) EvidenceClass.INDICATOR else EvidenceClass.INFO,
                    title = "Unreferenced objects remain in the file",
                    detected = orphans.joinToString("; ") { "${it.objectNumbers.size}× ${it.kind.label} (obj ${it.objectNumbers.take(6).joinToString()}${if (it.objectNumbers.size > 6) "…" else ""})" },
                    establishes = "These objects are live in the cross-reference table but nothing in the document refers to them, so no viewer displays them." +
                        (if (notable.isNotEmpty()) " At least some are page content, pages or images, which can mean content was removed from the document without being purged from the file." else ""),
                    unknown = "Writers that do not garbage-collect leave unreferenced objects behind routinely; deleted content is one cause among several. See the recovered text preview, if any.",
                    details = orphans.flatMap { g -> g.recoveredText.map { "recovered from ${g.kind.label}" to it } },
                ),
            )
        }

        val result = StructureResult(pages.size, pages, fonts, orphans, findings)
        return result
    }

    // ------------------------------------------------------------------------------------------------------------

    private fun collectFonts(file: PdfFile, view: DocView): List<FontInfo> {
        val rev = file.lastRevision
        val byKey = LinkedHashMap<String, FontInfo>()
        val pagesFor = HashMap<String, MutableSet<Int>>()
        for (p in view.pages) {
            val fd = file.resolve(p.resources?.get("Font"), rev) as? PdfDict ?: continue
            for ((resName, ref) in fd.map) {
                val num = (ref as? PdfRef)?.num
                val key = num?.toString() ?: "inline:${p.index}:$resName"
                pagesFor.getOrPut(key) { HashSet() }.add(p.index)
                if (byKey.containsKey(key)) continue
                val font = file.resolve(ref, rev) as? PdfDict ?: continue
                byKey[key] = describeFont(file, resName, num, font)
            }
        }
        return byKey.map { (k, f) -> FontInfo(f.resourceName, f.objNum, f.baseFont, f.subtype, f.embedded, f.subsetTag, f.face, f.hasToUnicode, pagesFor[k] ?: emptySet()) }
    }

    private fun describeFont(file: PdfFile, resName: String, num: Int?, font: PdfDict): FontInfo {
        val rev = file.lastRevision
        val subtype = font.name("Subtype")
        val base = font.name("BaseFont")
        var desc = file.resolve(font["FontDescriptor"], rev) as? PdfDict
        if (subtype == "Type0") {
            val df = (file.resolve(font["DescendantFonts"], rev) as? PdfArray)?.items?.firstOrNull()
            val dfd = file.resolve(df, rev) as? PdfDict
            desc = file.resolve(dfd?.get("FontDescriptor"), rev) as? PdfDict
        }
        val embedded = desc != null && (desc.has("FontFile") || desc.has("FontFile2") || desc.has("FontFile3"))
        val m = base?.let { Regex("^([A-Z]{6})\\+(.+)$").find(it) }
        return FontInfo(resName, num, base, subtype, embedded || subtype == "Type3", m?.groupValues?.get(1), m?.groupValues?.get(2) ?: base, font.has("ToUnicode"), emptySet())
    }

    private fun scanUnlistedObjects(file: PdfFile, known: Set<Int>, streamRanges: List<IntRange>): List<Pair<Int, Int>> {
        val out = ArrayList<Pair<Int, Int>>()
        val bytes = file.bytes
        val lx = PdfLexer(bytes)
        var p = 0
        val sorted = streamRanges.sortedBy { it.first }
        while (true) {
            val i = lx.indexOf(" obj", p)
            if (i < 0) break
            p = i + 4
            // header must be "N G obj" at line start
            var s = i - 1
            while (s >= 0 && PdfLexer.isDigit(bytes[s].toInt() and 0xFF)) s--
            val genStart = s + 1
            if (genStart == i || s < 0 || bytes[s].toInt() != ' '.code) continue
            s--
            while (s >= 0 && PdfLexer.isDigit(bytes[s].toInt() and 0xFF)) s--
            val numStart = s + 1
            if (numStart >= genStart - 1) continue
            if (numStart > 0 && !PdfLexer.isWhite(bytes[numStart - 1].toInt() and 0xFF)) continue
            if (numStart in known) continue
            if (insideRange(sorted, numStart)) continue
            val num = String(bytes, numStart, genStart - 1 - numStart, Charsets.ISO_8859_1).toIntOrNull() ?: continue
            out.add(num to numStart)
            if (out.size > 200) break
        }
        return out
    }

    private fun insideRange(sorted: List<IntRange>, pos: Int): Boolean {
        var lo = 0; var hi = sorted.size - 1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            val r = sorted[mid]
            if (pos < r.first) hi = mid - 1 else if (pos > r.last) lo = mid + 1 else return true
        }
        return false
    }

    private fun findOrphans(file: PdfFile, view: DocView): List<OrphanGroup> {
        val rev = file.lastRevision
        val reachable = HashSet<Int>()
        val queue = ArrayDeque<Int>()
        fun seed(o: PdfObj?) { refsIn(o).forEach { if (reachable.add(it.num)) queue.add(it.num) } }
        seed(file.trailerValue("Root", rev)); seed(file.trailerValue("Info", rev)); seed(file.trailerValue("Encrypt", rev))
        while (queue.isNotEmpty()) {
            val n = queue.removeFirst()
            val o = file.getObject(n, rev) ?: continue
            seed(o)
        }
        val structural = HashSet<Int>()
        for (n in file.liveObjectNumbers(rev)) {
            val o = file.getObject(n, rev) ?: continue
            val d = (o as? PdfStream)?.dict ?: o as? PdfDict
            if (d != null && (d.name("Type") == "XRef" || d.name("Type") == "ObjStm" || d.has("Linearized"))) structural.add(n)
            // linearisation hint streams are located by offset, not by reference
            if (o is PdfStream && file.linearized && d?.has("S") == true && !d.has("Type")) structural.add(n)
        }
        val groups = LinkedHashMap<ObjectKind, MutableList<Int>>()
        for (n in file.liveObjectNumbers(rev).sorted()) {
            if (n in reachable || n in structural) continue
            val o = file.getObject(n, rev) ?: continue
            groups.getOrPut(view.kindOf(n, o)) { ArrayList() }.add(n)
        }
        return groups.map { (k, nums) ->
            val recovered = ArrayList<String>()
            if (k == ObjectKind.OTHER || k == ObjectKind.CONTENT_STREAM) {
                for (n in nums.take(10)) {
                    val s = file.getObject(n, rev) as? PdfStream ?: continue
                    val dec = StreamDecoder.decode(s)
                    if (dec.stoppedAt != null || dec.bytes.isEmpty()) continue
                    val text = String(dec.bytes, Charsets.ISO_8859_1)
                    if (!Regex("(?<![A-Za-z0-9])(BT)(?![A-Za-z0-9])").containsMatchIn(text)) continue
                    val strings = ContentTokenizer.shownStrings(dec.bytes).filter { it.isNotBlank() }
                    if (strings.isNotEmpty()) recovered.add("obj $n: " + strings.joinToString(" ").take(240))
                }
            }
            OrphanGroup(if (k == ObjectKind.OTHER && recovered.isNotEmpty()) ObjectKind.CONTENT_STREAM else k, nums, recovered)
        }
    }
}
