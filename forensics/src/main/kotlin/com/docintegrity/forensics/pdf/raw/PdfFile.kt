package com.docintegrity.forensics.pdf.raw

enum class XrefEntryType { FREE, IN_USE, COMPRESSED }

/**
 * One cross-reference entry. For IN_USE: [a] = byte offset, [b] = generation.
 * For COMPRESSED: [a] = object-stream number, [b] = index inside the stream.
 */
data class XrefEntry(val num: Int, val type: XrefEntryType, val a: Long, val b: Int)

enum class XrefKind { TABLE, STREAM, RECONSTRUCTED }

class XrefSection(
    val startOffset: Int,
    val kind: XrefKind,
    val entries: Map<Int, XrefEntry>,
    val trailer: PdfDict,
    val prev: Long?,
    val hybridStreamOffset: Long?,
    val endOffset: Int,
)

/** A `startxref N ... %%EOF` marker located in the file. */
data class EofMarker(val startxrefPos: Int, val value: Long, val eofEnd: Int)

/**
 * A revision = the file as it stood after one save. Revision 0 is the original; every further revision is an
 * incremental update appended to the file. [prefixEnd] is the exclusive byte offset at which that revision's
 * complete, standalone file image ends (so `bytes[0, prefixEnd)` is a self-contained earlier version).
 */
class Revision(
    val index: Int,
    val sections: List<XrefSection>,
    val headStart: Int,
    val marker: EofMarker?,
    val prefixEnd: Int,
) {
    val trailer: PdfDict get() = sections.first().trailer
    /** Offset at which this revision's own new bytes begin (end of previous revision). */
    var bodyStart: Int = 0
        internal set
}

/**
 * Read-only structural view of a PDF file's bytes. Never mutates [bytes].
 */
class PdfFile private constructor(val bytes: ByteArray) {

    var headerOffset: Int = 0; private set
    var version: String? = null; private set
    var hasBinaryMarkerComment: Boolean = false; private set
    var revisions: List<Revision> = emptyList(); private set
    var xrefReconstructed: Boolean = false; private set
    var structuralNotes: MutableList<String> = ArrayList(); private set
    var linearized: Boolean = false; private set
    var linearizedDeclaredLength: Long? = null; private set
    var encrypted: Boolean = false; private set
    /** Bytes after the final `%%EOF` that are not just whitespace. */
    var trailingDataBytes: Int = 0; private set
    var markers: List<EofMarker> = emptyList(); private set

    private val parseCache = HashMap<Int, PdfIndirect?>()
    private val objStmCache = HashMap<Int, Map<Int, PdfObj>?>()

    val lastRevision: Int get() = revisions.size - 1

    private fun lexer(pos: Int = 0) = PdfLexer(bytes, pos)

    // ---------------------------------------------------------------------------------------------------------
    // Opening
    // ---------------------------------------------------------------------------------------------------------

    companion object {
        /** Returns null if the data does not look like a PDF at all. */
        fun open(bytes: ByteArray): PdfFile? {
            val f = PdfFile(bytes)
            if (!f.readHeader()) return null
            f.markers = f.findMarkers()
            val ok = try { f.buildFromXref() } catch (e: Exception) { f.structuralNotes.add("xref chain unreadable: ${e.message}"); false }
            if (!ok) f.reconstruct()
            f.postProcess()
            return f
        }
    }

    private fun readHeader(): Boolean {
        val lx = lexer()
        val idx = lx.indexOf("%PDF-", 0, minOf(bytes.size, 1024))
        if (idx < 0) return false
        headerOffset = idx
        var e = idx + 5
        val sb = StringBuilder()
        while (e < bytes.size && sb.length < 8 && (Character.isDigit(bytes[e].toInt()) || bytes[e].toInt() == '.'.code)) { sb.append(bytes[e].toInt().toChar()); e++ }
        version = sb.toString().ifEmpty { null }
        // binary marker comment on the 2nd line (>= 4 bytes with high bit set)
        var p = e
        while (p < bytes.size && bytes[p].toInt() != 10 && bytes[p].toInt() != 13) p++
        while (p < bytes.size && (bytes[p].toInt() == 10 || bytes[p].toInt() == 13)) p++
        if (p < bytes.size && bytes[p].toInt() == '%'.code) {
            var high = 0
            var q = p + 1
            while (q < bytes.size && q < p + 20 && bytes[q].toInt() != 10 && bytes[q].toInt() != 13) { if (bytes[q].toInt() < 0) high++; q++ }
            hasBinaryMarkerComment = high >= 3
        }
        return true
    }

    private fun findMarkers(): List<EofMarker> {
        val lx = lexer()
        val out = ArrayList<EofMarker>()
        var from = 0
        while (true) {
            val i = lx.indexOf("startxref", from)
            if (i < 0) break
            from = i + 9
            val l2 = PdfLexer(bytes, from)
            // NOTE: skipWs() would treat "%%EOF" as a comment and swallow it, so skip raw whitespace only.
            while (l2.pos < bytes.size && PdfLexer.isWhite(bytes[l2.pos].toInt() and 0xFF)) l2.pos++
            val s = l2.pos
            val tok = l2.readRegularToken()
            val v = tok.toLongOrNull() ?: continue
            if (s == l2.pos) continue
            while (l2.pos < bytes.size && PdfLexer.isWhite(bytes[l2.pos].toInt() and 0xFF)) l2.pos++
            val eof = if (l2.pos + 5 <= bytes.size && l2.startsWithKeyword("%%EOF")) l2.pos else l2.indexOf("%%EOF", l2.pos, minOf(bytes.size, l2.pos + 64))
            val eofEnd = if (eof < 0) {
                -1
            } else {
                var e = eof + 5
                if (e < bytes.size && bytes[e].toInt() == 13) e++
                if (e < bytes.size && bytes[e].toInt() == 10) e++
                e
            }
            out.add(EofMarker(i, v, if (eofEnd < 0) l2.pos else eofEnd))
        }
        return out
    }

    private fun buildFromXref(): Boolean {
        val last = markers.lastOrNull() ?: return false
        val chain = ArrayList<XrefSection>() // newest -> oldest
        val seen = HashSet<Long>()
        var off: Long? = last.value
        while (off != null) {
            if (!seen.add(off)) { structuralNotes.add("cyclic /Prev chain at offset $off"); break }
            if (off < 0 || off >= bytes.size) { structuralNotes.add("xref offset $off outside file"); return false }
            val sec = parseXrefSection(off.toInt()) ?: return false
            chain.add(sec)
            off = sec.prev
        }
        if (chain.isEmpty()) return false
        revisions = groupRevisions(chain.reversed())
        return true
    }

    private fun groupRevisions(oldestFirst: List<XrefSection>): List<Revision> {
        // Detect linearization pair (first-page xref located BEFORE the main xref, linked via /Prev).
        detectLinearization()
        val groups = ArrayList<List<XrefSection>>()
        var i = 0
        if (linearized && oldestFirst.size >= 2 && oldestFirst[1].startOffset < oldestFirst[0].startOffset &&
            oldestFirst[1].prev == oldestFirst[0].startOffset.toLong()
        ) {
            groups.add(listOf(oldestFirst[1], oldestFirst[0])) // first-page section is the "head"
            i = 2
        }
        while (i < oldestFirst.size) { groups.add(listOf(oldestFirst[i])); i++ }

        val revs = ArrayList<Revision>()
        var prevEnd = headerOffset
        for ((idx, g) in groups.withIndex()) {
            val head = g.first()
            val marker = markers.filter { it.value == head.startOffset.toLong() && it.startxrefPos > head.startOffset }
                .minByOrNull { it.startxrefPos }
                ?: markers.filter { it.value == head.startOffset.toLong() }.minByOrNull { it.startxrefPos }
            val end = marker?.eofEnd ?: g.maxOf { it.endOffset }
            if (marker == null) structuralNotes.add("revision $idx: no startxref/%%EOF marker found for xref at ${head.startOffset}")
            val rev = Revision(idx, g, head.startOffset, marker, end)
            rev.bodyStart = prevEnd
            prevEnd = end
            revs.add(rev)
        }
        return revs
    }

    private fun detectLinearization() {
        val lx = lexer(headerOffset)
        // first indirect object after header
        var p = headerOffset
        while (p < minOf(bytes.size, headerOffset + 2048)) {
            val i = lx.indexOf(" obj", p, minOf(bytes.size, headerOffset + 2048))
            if (i < 0) break
            // walk back to start of "N G"
            var s = i
            while (s > 0 && (PdfLexer.isDigit(bytes[s - 1].toInt() and 0xFF) || bytes[s - 1].toInt() == ' '.code)) s--
            val ind = try { PdfLexer(bytes).parseIndirectAt(s) } catch (e: Exception) { null }
            val d = ind?.value as? PdfDict
            if (d != null && d.has("Linearized")) {
                linearized = true
                linearizedDeclaredLength = d.int("L")
            }
            break
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Xref parsing
    // ---------------------------------------------------------------------------------------------------------

    private fun parseXrefSection(offset: Int): XrefSection? {
        val lx = PdfLexer(bytes, offset)
        lx.skipWs()
        val start = lx.pos
        return if (lx.startsWithKeyword("xref")) parseTable(start) else parseStreamSection(start)
    }

    private fun parseTable(start: Int): XrefSection? {
        val lx = PdfLexer(bytes, start)
        lx.readRegularToken() // xref
        val entries = LinkedHashMap<Int, XrefEntry>()
        while (true) {
            lx.skipWs()
            if (lx.startsWithKeyword("trailer")) break
            val a = lx.readRegularToken().toLongOrNull() ?: return null
            val b = lx.readRegularToken().toIntOrNull() ?: return null
            var first = a.toInt()
            for (k in 0 until b) {
                val off = lx.readRegularToken().toLongOrNull() ?: return null
                val gen = lx.readRegularToken().toIntOrNull() ?: return null
                val flag = lx.readRegularToken()
                val num = first + k
                entries[num] = when (flag) {
                    "n" -> XrefEntry(num, XrefEntryType.IN_USE, off, gen)
                    "f" -> XrefEntry(num, XrefEntryType.FREE, off, gen)
                    else -> return null
                }
            }
        }
        lx.readRegularToken() // trailer
        val trailer = lx.parseObject() as? PdfDict ?: return null
        val endOffset = lx.pos
        val prev = trailer.int("Prev")
        var hybrid: Long? = null
        val merged = LinkedHashMap(entries)
        trailer.int("XRefStm")?.let { stmOff ->
            hybrid = stmOff
            parseStreamSection(stmOff.toInt())?.let { h ->
                for ((n, e) in h.entries) {
                    val existing = merged[n]
                    if (existing == null || existing.type == XrefEntryType.FREE) merged[n] = e
                }
            }
        }
        return XrefSection(start, XrefKind.TABLE, merged, trailer, prev, hybrid, endOffset)
    }

    private fun parseStreamSection(start: Int): XrefSection? {
        val ind = PdfLexer(bytes).parseIndirectAt(start) ?: return null
        val st = ind.value as? PdfStream ?: return null
        if (st.dict.name("Type") != "XRef") return null
        val w = st.dict.array("W")?.items?.map { ((it as? PdfInt)?.value ?: 0L).toInt() } ?: return null
        if (w.size < 3 || w.any { it < 0 || it > 8 }) return null
        val size = st.dict.int("Size")?.toInt() ?: 0
        val index = st.dict.array("Index")?.items?.map { ((it as? PdfInt)?.value ?: 0L).toInt() } ?: listOf(0, size)
        val data = StreamDecoder.decode(st).bytes
        val rowLen = w.sum()
        if (rowLen == 0) return null
        val entries = LinkedHashMap<Int, XrefEntry>()
        var p = 0
        var ix = 0
        while (ix + 1 < index.size) {
            val first = index[ix]; val count = index[ix + 1]
            for (k in 0 until count) {
                if (p + rowLen > data.size) break
                fun field(width: Int): Long { var v = 0L; repeat(width) { v = (v shl 8) or (data[p++].toLong() and 0xFF) }; return v }
                val type = if (w[0] == 0) 1L else field(w[0])
                val f2 = field(w[1])
                val f3 = field(w[2])
                val num = first + k
                entries[num] = when (type) {
                    0L -> XrefEntry(num, XrefEntryType.FREE, f2, f3.toInt())
                    1L -> XrefEntry(num, XrefEntryType.IN_USE, f2, f3.toInt())
                    2L -> XrefEntry(num, XrefEntryType.COMPRESSED, f2, f3.toInt())
                    else -> XrefEntry(num, XrefEntryType.FREE, 0, 0)
                }
            }
            ix += 2
        }
        return XrefSection(ind.startOffset, XrefKind.STREAM, entries, st.dict, st.dict.int("Prev"), null, ind.endOffset)
    }

    // ---------------------------------------------------------------------------------------------------------
    // Reconstruction when xref data is unusable
    // ---------------------------------------------------------------------------------------------------------

    private fun reconstruct() {
        xrefReconstructed = true
        val entries = LinkedHashMap<Int, XrefEntry>()
        var trailer: PdfDict? = null
        val lx = lexer()
        var p = 0
        val n = bytes.size
        // Scan for "N G obj" at token boundaries.
        while (p < n) {
            val i = lx.indexOf("obj", p)
            if (i < 0) break
            p = i + 3
            if (i > 0 && PdfLexer.isRegular(bytes[i - 1].toInt() and 0xFF) && !PdfLexer.isDigit(bytes[i - 1].toInt() and 0xFF)) continue
            if (i >= 3 && lx.startsWithKeywordAt(i - 3, "end")) continue
            // walk back over "N G "
            var s = i - 1
            while (s >= 0 && PdfLexer.isWhite(bytes[s].toInt() and 0xFF)) s--
            val genEnd = s + 1
            while (s >= 0 && PdfLexer.isDigit(bytes[s].toInt() and 0xFF)) s--
            val genStart = s + 1
            if (genStart >= genEnd) continue
            while (s >= 0 && PdfLexer.isWhite(bytes[s].toInt() and 0xFF)) s--
            val numEnd = s + 1
            while (s >= 0 && PdfLexer.isDigit(bytes[s].toInt() and 0xFF)) s--
            val numStart = s + 1
            if (numStart >= numEnd) continue
            val num = String(bytes, numStart, numEnd - numStart, Charsets.ISO_8859_1).toIntOrNull() ?: continue
            val gen = String(bytes, genStart, genEnd - genStart, Charsets.ISO_8859_1).toIntOrNull() ?: continue
            entries[num] = XrefEntry(num, XrefEntryType.IN_USE, numStart.toLong(), gen)
        }
        // last "trailer" dictionary
        var t = -1
        var from = 0
        while (true) { val k = lx.indexOf("trailer", from); if (k < 0) break; t = k; from = k + 7 }
        if (t >= 0) trailer = try { PdfLexer(bytes, t + 7).parseObject() as? PdfDict } catch (e: Exception) { null }
        val tmpSection = XrefSection(0, XrefKind.RECONSTRUCTED, entries, trailer ?: PdfDict(emptyMap()), null, null, n)
        revisions = listOf(Revision(0, listOf(tmpSection), 0, null, n).also { it.bodyStart = headerOffset })
        // Fall back to XRef stream dictionaries / ObjStm contents for Root and compressed objects.
        if (trailer == null || !trailer.has("Root")) {
            for ((_, e) in entries) {
                val s = indirectAt(e.a.toInt())?.value as? PdfStream ?: continue
                if (s.dict.name("Type") == "XRef" && s.dict.has("Root")) {
                    revisions = listOf(Revision(0, listOf(XrefSection(0, XrefKind.RECONSTRUCTED, entries, s.dict, null, null, n)), 0, null, n).also { it.bodyStart = headerOffset })
                }
            }
        }
        // add compressed objects from object streams
        val extra = LinkedHashMap<Int, XrefEntry>()
        for ((num, e) in entries) {
            val s = indirectAt(e.a.toInt())?.value as? PdfStream ?: continue
            if (s.dict.name("Type") == "ObjStm") {
                val contained = loadObjStm(num, e.a.toInt()) ?: continue
                var idx = 0
                for (cn in contained.keys) { if (!entries.containsKey(cn)) extra[cn] = XrefEntry(cn, XrefEntryType.COMPRESSED, num.toLong(), idx); idx++ }
            }
        }
        if (extra.isNotEmpty()) {
            val sec = revisions[0].sections[0]
            revisions = listOf(Revision(0, listOf(XrefSection(0, XrefKind.RECONSTRUCTED, entries + extra, sec.trailer, null, null, n)), 0, null, n).also { it.bodyStart = headerOffset })
        }
        structuralNotes.add("cross-reference data missing or unusable; object table rebuilt by scanning the file (revision history cannot be derived)")
    }

    private fun PdfLexer.startsWithKeywordAt(at: Int, kw: String): Boolean {
        if (at < 0 || at + kw.length > bytes.size) return false
        for (i in kw.indices) if (bytes[at + i].toInt() != kw[i].code) return false
        return true
    }

    private fun postProcess() {
        // trailing data after the last %%EOF
        val lastEnd = revisions.lastOrNull()?.prefixEnd ?: bytes.size
        var tail = 0
        for (i in lastEnd until bytes.size) if (!PdfLexer.isWhite(bytes[i].toInt() and 0xFF)) tail++
        trailingDataBytes = tail
        encrypted = revisions.any { it.sections.any { s -> s.trailer.has("Encrypt") } }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Object access
    // ---------------------------------------------------------------------------------------------------------

    internal fun indirectAt(offset: Int): PdfIndirect? {
        if (offset < 0 || offset >= bytes.size) return null
        return parseCache.getOrPut(offset) {
            try {
                PdfLexer(bytes).parseIndirectAt(offset) { ref ->
                    val o = getObject(ref.num, lastRevision)
                    (o as? PdfInt)?.value
                }
            } catch (e: Exception) { null }
        }
    }

    /** Finds the xref entry governing [num] as seen from [rev] (inclusive), plus the revision that defined it. */
    fun lookup(num: Int, rev: Int = lastRevision): Pair<XrefEntry, Int>? {
        for (r in minOf(rev, lastRevision) downTo 0) {
            for (s in revisions[r].sections) {
                s.entries[num]?.let { return it to r }
            }
        }
        return null
    }

    fun getObject(num: Int, rev: Int = lastRevision): PdfObj? = getIndirect(num, rev)?.value

    fun getIndirect(num: Int, rev: Int = lastRevision, depth: Int = 0): PdfIndirect? {
        if (depth > 8) return null
        val (e, _) = lookup(num, rev) ?: return null
        return when (e.type) {
            XrefEntryType.FREE -> null
            XrefEntryType.IN_USE -> indirectAt(e.a.toInt())?.takeIf { it.num == num }
                ?: run {
                    // tolerate a mismatching header number only if offset points at an object of that number
                    null
                }
            XrefEntryType.COMPRESSED -> {
                val stmEntry = lookup(e.a.toInt(), rev)?.first ?: return null
                if (stmEntry.type != XrefEntryType.IN_USE) return null
                val m = loadObjStm(e.a.toInt(), stmEntry.a.toInt()) ?: return null
                m[num]?.let { PdfIndirect(num, 0, it, stmEntry.a.toInt(), stmEntry.a.toInt()) }
            }
        }
    }

    /** Dereferences [o] if it is a reference. */
    fun resolve(o: PdfObj?, rev: Int = lastRevision): PdfObj? {
        var cur = o
        var guard = 0
        while (cur is PdfRef && guard++ < 16) cur = getObject(cur.num, rev)
        return cur
    }

    private fun loadObjStm(stmNum: Int, offset: Int): Map<Int, PdfObj>? = objStmCache.getOrPut(offset) {
        try {
            val st = indirectAt(offset)?.value as? PdfStream ?: return@getOrPut null
            if (st.dict.name("Type") != "ObjStm") return@getOrPut null
            val n = st.dict.int("N")?.toInt() ?: return@getOrPut null
            val first = st.dict.int("First")?.toInt() ?: return@getOrPut null
            val data = StreamDecoder.decode(st).bytes
            val lx = PdfLexer(data)
            val nums = ArrayList<Int>(); val offs = ArrayList<Int>()
            for (i in 0 until n) {
                nums.add(lx.readRegularToken().toIntOrNull() ?: break)
                offs.add(lx.readRegularToken().toIntOrNull() ?: break)
            }
            val out = LinkedHashMap<Int, PdfObj>()
            for (i in nums.indices) {
                val l2 = PdfLexer(data, first + offs[i])
                try { out[nums[i]] = l2.parseObject() } catch (e: Exception) { /* skip bad member */ }
            }
            out
        } catch (e: Exception) { null }
    }

    /** All object numbers that are live (in use / compressed) as of [rev]. */
    fun liveObjectNumbers(rev: Int = lastRevision): Set<Int> {
        val nums = LinkedHashSet<Int>()
        val dead = HashSet<Int>()
        for (r in minOf(rev, lastRevision) downTo 0) {
            for (s in revisions[r].sections) for ((n, e) in s.entries) {
                if (n in nums || n in dead) continue
                if (e.type == XrefEntryType.FREE) dead.add(n) else nums.add(n)
            }
        }
        return nums
    }

    fun trailerAt(rev: Int = lastRevision): PdfDict = revisions[minOf(rev, lastRevision)].trailer

    /** Root-bearing trailer values, falling back to older sections for keys that updates don't repeat. */
    fun trailerValue(key: String, rev: Int = lastRevision): PdfObj? {
        for (r in minOf(rev, lastRevision) downTo 0) for (s in revisions[r].sections) s.trailer[key]?.let { return it }
        return null
    }

    fun prefix(rev: Int): ByteArray = bytes.copyOfRange(0, revisions[rev].prefixEnd)
}
