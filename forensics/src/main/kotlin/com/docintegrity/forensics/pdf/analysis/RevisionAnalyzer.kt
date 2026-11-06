package com.docintegrity.forensics.pdf.analysis

import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.pdf.raw.PdfDict
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.pdf.raw.PdfObj
import com.docintegrity.forensics.pdf.raw.PdfStream
import com.docintegrity.forensics.pdf.raw.StreamDecoder
import com.docintegrity.forensics.pdf.raw.XrefEntryType
import com.docintegrity.forensics.util.Hashing

enum class ChangeType(val label: String) {
    NEW("added"),
    REPLACED("replaced"),
    FREED("removed"),
    REWRITTEN_IDENTICAL("rewritten without change"),
}

class ObjectChange(
    val rev: Int,
    val num: Int,
    val gen: Int,
    val type: ChangeType,
    val kind: ObjectKind,
    val page: Int?,
    val summary: String,
    val annotSubtype: String? = null,
)

class RevisionInfo(
    val index: Int,
    /** Offset where this revision's own bytes begin. */
    val startOffset: Int,
    /** Exclusive end of the standalone file image of this revision. */
    val endOffset: Int,
    val xrefKinds: List<String>,
    val prefixSha256: String,
    val changes: List<ObjectChange>,
    val pagesBefore: Int,
    val pagesAfter: Int,
    val infoChanges: List<String>,
) {
    val newBytes get() = endOffset - startOffset
    val contentPages: Set<Int> = changes.filter {
        (it.kind == ObjectKind.CONTENT_STREAM && it.type != ChangeType.REWRITTEN_IDENTICAL) ||
            (it.kind == ObjectKind.PAGE && it.type == ChangeType.REPLACED && it.summary.contains("/Contents"))
    }.mapNotNull { it.page }.toSet()
    val imageChanges = changes.count { it.kind == ObjectKind.IMAGE && (it.type == ChangeType.NEW || it.type == ChangeType.REPLACED) }
    val fontsAdded = changes.count { it.kind == ObjectKind.FONT && it.type == ChangeType.NEW }
    val overlayAnnots = changes.filter { it.kind == ObjectKind.ANNOTATION && it.type == ChangeType.NEW && it.annotSubtype in OVERLAY_ANNOTS }
    val widgetChanges = changes.count { it.kind == ObjectKind.FORM_FIELD && it.type != ChangeType.REWRITTEN_IDENTICAL }
    val signatureObjects = changes.count { it.kind == ObjectKind.SIGNATURE && it.type == ChangeType.NEW }
    val pageCountChanged get() = pagesBefore != pagesAfter
    val pageObjectsReplaced = changes.count { it.kind == ObjectKind.PAGE && it.type == ChangeType.REPLACED }
    val formXObjectChanges = changes.count { it.kind == ObjectKind.FORM_XOBJECT && it.type != ChangeType.REWRITTEN_IDENTICAL }

    /** True when the update touched what a reader sees on the page (as opposed to forms, signatures or metadata). */
    val touchesVisibleContent: Boolean
        get() = contentPages.isNotEmpty() || imageChanges > 0 || fontsAdded > 0 || pageCountChanged || overlayAnnots.isNotEmpty() || formXObjectChanges > 0

    companion object {
        val OVERLAY_ANNOTS = setOf("FreeText", "Stamp", "Square", "Circle", "Ink", "Redact", "Polygon", "Line", "Watermark")
    }
}

class RevisionResult(val revisions: List<RevisionInfo>, val findings: List<Finding>)

object RevisionAnalyzer {

    private const val MAX_LISTED = 40

    fun analyze(file: PdfFile): RevisionResult {
        val infos = ArrayList<RevisionInfo>()
        val findings = ArrayList<Finding>()
        val views = HashMap<Int, DocView>()
        fun view(r: Int) = views.getOrPut(r) { DocView(file, r) }

        for (rev in file.revisions) {
            val changes = ArrayList<ObjectChange>()
            var infoChanges = emptyList<String>()
            val pagesAfter = view(rev.index).pages.size
            var pagesBefore = pagesAfter
            if (rev.index > 0 && !file.xrefReconstructed) {
                pagesBefore = view(rev.index - 1).pages.size
                val after = view(rev.index)
                val before = view(rev.index - 1)
                val nums = LinkedHashSet<Int>()
                for (s in rev.sections) nums.addAll(s.entries.keys)
                for (num in nums.sorted()) {
                    val entry = rev.sections.firstNotNullOf { it.entries[num] }
                    val prevObj = file.getObject(num, rev.index - 1)
                    if (entry.type == XrefEntryType.FREE) {
                        if (prevObj != null) {
                            changes.add(ObjectChange(rev.index, num, entry.b, ChangeType.FREED, before.kindOf(num, prevObj), before.pageOwner(num), "object marked free in this update"))
                        }
                        continue
                    }
                    val obj = file.getObject(num, rev.index) ?: continue
                    val kind = after.kindOf(num, obj)
                    val page = after.pageOwner(num)
                    val sub = after.annotationSubtype(if (obj is PdfStream) obj.dict else obj)
                    if (prevObj == null) {
                        changes.add(ObjectChange(rev.index, num, entry.b, ChangeType.NEW, kind, page, describeNew(obj, kind), sub))
                    } else if (!sameObject(prevObj, obj)) {
                        changes.add(ObjectChange(rev.index, num, entry.b, ChangeType.REPLACED, kind, page, describeDiff(file, prevObj, obj, kind), sub))
                    } else {
                        changes.add(ObjectChange(rev.index, num, entry.b, ChangeType.REWRITTEN_IDENTICAL, kind, page, "identical content rewritten at a new offset", sub))
                    }
                }
                infoChanges = diffInfo(file, rev.index)
            }
            infos.add(
                RevisionInfo(
                    index = rev.index, startOffset = rev.bodyStart, endOffset = rev.prefixEnd,
                    xrefKinds = rev.sections.map { it.kind.name.lowercase() },
                    prefixSha256 = Hashing.sha256(file.bytes, 0, rev.prefixEnd),
                    changes = changes, pagesBefore = pagesBefore, pagesAfter = pagesAfter, infoChanges = infoChanges,
                ),
            )
        }

        findings += revisionFindings(file, infos)
        return RevisionResult(infos, findings)
    }

    // ------------------------------------------------------------------------------------------------------------

    private fun revisionFindings(file: PdfFile, infos: List<RevisionInfo>): List<Finding> {
        val out = ArrayList<Finding>()
        if (file.xrefReconstructed) {
            out.add(
                Finding(
                    id = "REV_UNAVAILABLE_XREF_DAMAGED", area = Area.REVISIONS, evidence = EvidenceClass.LIMITATION, blocking = true,
                    title = "Revision history could not be derived",
                    detected = "The cross-reference data is missing or unusable and the object table had to be rebuilt by scanning.",
                    establishes = "Revision boundaries cannot be determined reliably for this file.",
                    unknown = "Whether earlier versions are present in the bytes. Treat any earlier-version claim as unavailable.",
                ),
            )
            return out
        }
        val updates = infos.drop(1)
        if (updates.isEmpty()) {
            out.add(
                Finding(
                    id = "REV_SINGLE", area = Area.REVISIONS, evidence = EvidenceClass.INFO,
                    title = "Single revision: no incremental-update history",
                    detected = "The file contains exactly one revision" + (if (file.linearized) " (linearised for fast web view)." else "."),
                    establishes = "No earlier version of this document can be recovered from the file itself.",
                    unknown = "Absence of history does not mean the document was never edited: editors that rewrite the whole file (re-saving, converting, printing to PDF) leave no incremental history. A PDF that was regenerated cannot be distinguished from an original on this evidence alone.",
                ),
            )
            return out
        }
        out.add(
            Finding(
                id = "REV_COUNT", area = Area.REVISIONS, evidence = EvidenceClass.INFO,
                title = "${updates.size} incremental update${if (updates.size == 1) "" else "s"} found (${infos.size} revisions)",
                detected = "The file has ${infos.size} cross-reference sections chained with /Prev; each update appends new bytes after the previous %%EOF.",
                establishes = "Earlier versions of this file exist inside it and can be reconstructed and compared.",
                unknown = "Why the updates were made. Signing, form filling, adding annotations and compression-free re-saves all create incremental updates.",
                details = infos.map { "Revision ${it.index}" to "bytes ${it.startOffset}–${it.endOffset}, SHA-256 of this version: ${it.prefixSha256}" },
            ),
        )
        for (u in updates) {
            val parts = ArrayList<String>()
            if (u.contentPages.isNotEmpty()) parts.add("page content changed on page${if (u.contentPages.size > 1) "s" else ""} ${u.contentPages.sorted().joinToString { (it + 1).toString() }}")
            if (u.imageChanges > 0) parts.add("${u.imageChanges} image object${if (u.imageChanges > 1) "s" else ""} added/replaced")
            if (u.fontsAdded > 0) parts.add("${u.fontsAdded} new font${if (u.fontsAdded > 1) "s" else ""}")
            if (u.pageCountChanged) parts.add("page count ${u.pagesBefore} → ${u.pagesAfter}")
            if (u.overlayAnnots.isNotEmpty()) parts.add("overlay-capable annotations added (${u.overlayAnnots.groupingBy { it.annotSubtype ?: "?" }.eachCount().entries.joinToString { "${it.key}×${it.value}" }})")
            if (u.formXObjectChanges > 0) parts.add("${u.formXObjectChanges} form XObject(s) changed")
            if (u.widgetChanges > 0) parts.add("${u.widgetChanges} form field object(s) changed")
            if (u.signatureObjects > 0) parts.add("${u.signatureObjects} signature object(s) added")
            if (u.infoChanges.isNotEmpty()) parts.add("document information changed (${u.infoChanges.size})")
            if (parts.isEmpty()) parts.add("no visible-content objects changed (${u.changes.size} object(s) touched)")
            val visible = u.touchesVisibleContent
            val listed = u.changes.filter { it.type != ChangeType.REWRITTEN_IDENTICAL }.take(MAX_LISTED)
            out.add(
                Finding(
                    id = "REV_UPDATE_${u.index}",
                    area = Area.REVISIONS,
                    evidence = if (visible) EvidenceClass.INDICATOR else EvidenceClass.INFO,
                    title = "Revision ${u.index}: " + if (visible) "visible content was changed after the previous save" else "update without visible-content changes",
                    detected = parts.joinToString("; ") + ".",
                    establishes = if (visible) {
                        "The file's own history shows that content objects were added or replaced after revision ${u.index - 1}. The earlier version is recoverable and can be compared with this one."
                    } else {
                        "An update was appended, but none of the page content, images, fonts or page structure changed."
                    },
                    unknown = if (visible) {
                        "Whether the change was legitimate (e.g. a correction, completing a form, a stamp) or deceptive. A document carrying both versions inside it is also something an editor can construct deliberately, so this history is not an independent, trusted original."
                    } else {
                        "Whether the metadata, forms or annotations touched are material to the document's meaning."
                    },
                    details = buildList {
                        add("Bytes appended" to "${u.newBytes}")
                        u.infoChanges.forEach { add("Info change" to it) }
                        listed.forEach { c ->
                            add("obj ${c.num} ${c.kind.label}" + (c.page?.let { " (page ${it + 1})" } ?: "") to "${c.type.label}: ${c.summary}")
                        }
                        val more = u.changes.count { it.type != ChangeType.REWRITTEN_IDENTICAL } - listed.size
                        if (more > 0) add("…" to "$more more object changes not listed")
                    },
                ),
            )
        }
        return out
    }

    private fun diffInfo(file: PdfFile, rev: Int): List<String> {
        val a = MetadataReader.readInfo(file, rev - 1) ?: emptyMap()
        val b = MetadataReader.readInfo(file, rev) ?: emptyMap()
        val out = ArrayList<String>()
        for (k in (a.keys + b.keys).toSortedSet()) {
            val x = a[k]; val y = b[k]
            if (x == y) continue
            out.add("$k: " + (x?.let { "“$it”" } ?: "(absent)") + " → " + (y?.let { "“$it”" } ?: "(removed)"))
        }
        return out
    }

    // ------------------------------------------------------------------------------------------------------------
    // Object comparison helpers
    // ------------------------------------------------------------------------------------------------------------

    private fun sameObject(a: PdfObj, b: PdfObj): Boolean = when {
        a is PdfStream && b is PdfStream -> a.sameContentAs(b)
        a is PdfStream || b is PdfStream -> false
        else -> a == b
    }

    private fun describeNew(o: PdfObj, kind: ObjectKind): String = when (o) {
        is PdfStream -> "stream, ${o.dataLength} bytes" + filterNote(o)
        is PdfDict -> "dictionary with keys ${o.map.keys.take(8).joinToString(" ") { "/$it" }}"
        else -> o.toString().take(80)
    }

    private fun filterNote(s: PdfStream): String {
        val f = StreamDecoder.filtersOf(s.dict)
        return if (f.isEmpty()) "" else " (${f.joinToString("+")})"
    }

    private fun describeDiff(file: PdfFile, before: PdfObj, after: PdfObj, kind: ObjectKind): String {
        val bd = (before as? PdfStream)?.dict ?: before as? PdfDict
        val ad = (after as? PdfStream)?.dict ?: after as? PdfDict
        val parts = ArrayList<String>()
        if (bd != null && ad != null) {
            val keys = (bd.map.keys + ad.map.keys).filter { it != "Length" }
            val changed = keys.filter { bd[it] != ad[it] }
            if (changed.isNotEmpty()) parts.add("changed keys " + changed.take(8).joinToString(" ") { "/$it" })
        }
        if (before is PdfStream && after is PdfStream) {
            if (!java.util.Arrays.equals(before.rawBytes(), after.rawBytes())) {
                if (kind == ObjectKind.CONTENT_STREAM || kind == ObjectKind.FORM_XOBJECT) {
                    val b = contentStats(before); val a = contentStats(after)
                    parts.add("stream bytes changed (${before.dataLength}→${after.dataLength}); text-show ops ${b.first}→${a.first}, image/form draws ${b.second}→${a.second}")
                } else {
                    parts.add("stream bytes changed (${before.dataLength}→${after.dataLength})")
                }
            }
        }
        if (parts.isEmpty()) parts.add("value changed")
        return parts.joinToString("; ")
    }

    /** (text-show operators, XObject draws) in a decoded content stream; a rough, explicitly approximate size measure. */
    private fun contentStats(s: PdfStream): Pair<Int, Int> {
        val d = StreamDecoder.decode(s)
        if (d.stoppedAt != null) return 0 to 0
        val t = String(d.bytes, Charsets.ISO_8859_1)
        return Regex("(?<![A-Za-z0-9])(Tj|TJ)(?![A-Za-z0-9])").findAll(t).count() to Regex("(?<![A-Za-z0-9])Do(?![A-Za-z0-9])").findAll(t).count()
    }
}
