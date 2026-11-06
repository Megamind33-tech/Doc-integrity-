package com.docintegrity.forensics.pdf.analysis

import com.docintegrity.forensics.pdf.raw.PdfArray
import com.docintegrity.forensics.pdf.raw.PdfDict
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.pdf.raw.PdfObj
import com.docintegrity.forensics.pdf.raw.PdfRef
import com.docintegrity.forensics.pdf.raw.PdfStream

enum class ObjectKind(val label: String) {
    CATALOG("Catalog"),
    PAGE_TREE("Page tree node"),
    PAGE("Page"),
    CONTENT_STREAM("Page content stream"),
    FONT("Font"),
    FONT_DESCRIPTOR("Font descriptor"),
    FONT_FILE("Embedded font program"),
    IMAGE("Image"),
    FORM_XOBJECT("Form XObject"),
    ANNOTATION("Annotation"),
    FORM_FIELD("Form field"),
    ACROFORM("Interactive form dictionary"),
    SIGNATURE("Signature"),
    XMP("XMP metadata"),
    INFO("Info dictionary"),
    XREF_STREAM("Cross-reference stream"),
    OBJECT_STREAM("Object stream"),
    EMBEDDED_FILE("Embedded file"),
    STRUCTURE_TAG("Tagged-PDF structure element"),
    SECURITY("Encryption / security"),
    OTHER("Other object"),
}

class PageInfo(
    val index: Int,
    val objNum: Int,
    val dict: PdfDict,
    val resources: PdfDict?,
    val mediaBox: DoubleArray?,
    val rotate: Int,
)

/**
 * The document tree as it stood at one revision: page order, which object numbers are page content / images /
 * annotations, and a classifier for arbitrary objects. All lookups go through [PdfFile] with a revision limit, so the
 * view of an older revision is reconstructed from bytes that were really in the file at that point.
 */
class DocView(val file: PdfFile, val rev: Int) {

    val catalogNum: Int? = (file.trailerValue("Root", rev) as? PdfRef)?.num
    val catalog: PdfDict? = file.resolve(file.trailerValue("Root", rev), rev) as? PdfDict
    val infoNum: Int? = (file.trailerValue("Info", rev) as? PdfRef)?.num
    val pages: List<PageInfo>
    val contentOwner = HashMap<Int, Int>()
    val annotOwner = HashMap<Int, Int>()
    val xobjectOwner = HashMap<Int, MutableSet<Int>>()
    val fontOwner = HashMap<Int, MutableSet<Int>>()
    private val pageTreeNums = HashSet<Int>()
    private val pageNums = HashMap<Int, Int>()
    private val metadataNum: Int? = (catalog?.get("Metadata") as? PdfRef)?.num
    private val acroFormNum: Int? = (catalog?.get("AcroForm") as? PdfRef)?.num
    private val acroFormFieldNums = HashSet<Int>()

    init {
        val out = ArrayList<PageInfo>()
        val root = catalog?.get("Pages")
        walk(root, null, null, null, 0, HashSet(), out)
        pages = out
        for (p in pages) {
            pageNums[p.objNum] = p.index
            when (val c = p.dict["Contents"]) {
                is PdfRef -> {
                    val r = file.resolve(c, rev)
                    if (r is PdfArray) r.items.forEach { (it as? PdfRef)?.let { rr -> contentOwner[rr.num] = p.index } } else contentOwner[c.num] = p.index
                }
                is PdfArray -> c.items.forEach { (it as? PdfRef)?.let { rr -> contentOwner[rr.num] = p.index } }
                else -> {}
            }
            val annots = file.resolve(p.dict["Annots"], rev) as? PdfArray
            annots?.items?.forEach { (it as? PdfRef)?.let { rr -> annotOwner[rr.num] = p.index } }
            val xo = file.resolve(p.resources?.get("XObject"), rev) as? PdfDict
            xo?.map?.values?.forEach { (it as? PdfRef)?.let { rr -> xobjectOwner.getOrPut(rr.num) { HashSet() }.add(p.index) } }
            val fonts = file.resolve(p.resources?.get("Font"), rev) as? PdfDict
            fonts?.map?.values?.forEach { (it as? PdfRef)?.let { rr -> fontOwner.getOrPut(rr.num) { HashSet() }.add(p.index) } }
        }
        val acro = file.resolve(catalog?.get("AcroForm"), rev) as? PdfDict
        (file.resolve(acro?.get("Fields"), rev) as? PdfArray)?.items?.forEach { collectFields(it, 0) }
    }

    private fun collectFields(o: PdfObj, depth: Int) {
        if (depth > 16) return
        val r = o as? PdfRef ?: return
        if (!acroFormFieldNums.add(r.num)) return
        val d = file.resolve(r, rev) as? PdfDict ?: return
        (file.resolve(d["Kids"], rev) as? PdfArray)?.items?.forEach { collectFields(it, depth + 1) }
    }

    private fun walk(node: PdfObj?, nodeNum: Int?, inheritedRes: PdfDict?, inheritedBox: DoubleArray?, depth: Int, visited: MutableSet<Int>, out: MutableList<PageInfo>, inheritedRot: Int = 0) {
        if (depth > 64 || node == null) return
        val num = (node as? PdfRef)?.num ?: nodeNum
        if (num != null && !visited.add(num)) return
        val d = file.resolve(node, rev) as? PdfDict ?: return
        val res = (file.resolve(d["Resources"], rev) as? PdfDict) ?: inheritedRes
        val box = boxOf(d["MediaBox"]) ?: inheritedBox
        val rot = (d.int("Rotate")?.toInt()) ?: inheritedRot
        val kids = file.resolve(d["Kids"], rev) as? PdfArray
        val type = d.name("Type")
        if (kids != null && type != "Page") {
            num?.let { pageTreeNums.add(it) }
            for (k in kids.items) walk(k, null, res, box, depth + 1, visited, out, rot)
        } else if (num != null) {
            out.add(PageInfo(out.size, num, d, res, box, ((rot % 360) + 360) % 360))
        }
    }

    private fun boxOf(o: PdfObj?): DoubleArray? {
        val a = file.resolve(o, rev) as? PdfArray ?: return null
        if (a.size < 4) return null
        val v = a.items.map { x -> file.resolve(x, rev).let { r -> (r as? com.docintegrity.forensics.pdf.raw.PdfInt)?.value?.toDouble() ?: (r as? com.docintegrity.forensics.pdf.raw.PdfReal)?.value } }
        if (v.any { it == null }) return null
        return doubleArrayOf(v[0]!!, v[1]!!, v[2]!!, v[3]!!)
    }

    fun pageIndexOfObject(num: Int): Int? = pageNums[num]

    /** Best-effort page that an object belongs to (content stream, annotation, XObject), or null. */
    fun pageOwner(num: Int): Int? = pageNums[num] ?: contentOwner[num] ?: annotOwner[num] ?: xobjectOwner[num]?.minOrNull() ?: fontOwner[num]?.minOrNull()

    fun kindOf(num: Int, obj: PdfObj?): ObjectKind {
        if (num == catalogNum) return ObjectKind.CATALOG
        if (num == infoNum) return ObjectKind.INFO
        if (num == metadataNum) return ObjectKind.XMP
        if (num == acroFormNum) return ObjectKind.ACROFORM
        if (num in pageNums) return ObjectKind.PAGE
        if (num in pageTreeNums) return ObjectKind.PAGE_TREE
        if (num in contentOwner) return ObjectKind.CONTENT_STREAM
        val dict = when (obj) { is PdfStream -> obj.dict; is PdfDict -> obj; else -> null } ?: return ObjectKind.OTHER
        val type = dict.name("Type")
        val sub = dict.name("Subtype")
        return when {
            type == "XRef" -> ObjectKind.XREF_STREAM
            type == "ObjStm" -> ObjectKind.OBJECT_STREAM
            type == "Sig" || type == "DocTimeStamp" || dict.has("ByteRange") -> ObjectKind.SIGNATURE
            type == "Metadata" -> ObjectKind.XMP
            type == "StructElem" || type == "StructTreeRoot" || type == "MCR" || type == "OBJR" -> ObjectKind.STRUCTURE_TAG
            type == "EmbeddedFile" -> ObjectKind.EMBEDDED_FILE
            type == "Filespec" -> ObjectKind.EMBEDDED_FILE
            type == "Catalog" -> ObjectKind.CATALOG
            type == "Pages" -> ObjectKind.PAGE_TREE
            type == "Page" -> ObjectKind.PAGE
            type == "FontDescriptor" -> ObjectKind.FONT_DESCRIPTOR
            type == "Font" || (sub in FONT_SUBTYPES && dict.has("BaseFont")) -> ObjectKind.FONT
            sub == "Image" -> ObjectKind.IMAGE
            sub == "Form" && obj is PdfStream && type != "Annot" -> ObjectKind.FORM_XOBJECT
            (obj is PdfStream) && (dict.has("Length1") || dict.has("Length2") || sub == "OpenType" || sub == "Type1C" || sub == "CIDFontType0C") -> ObjectKind.FONT_FILE
            num in annotOwner || type == "Annot" || (sub != null && sub in ANNOT_SUBTYPES && type != "XObject") -> if (sub == "Widget" || num in acroFormFieldNums) ObjectKind.FORM_FIELD else ObjectKind.ANNOTATION
            num in acroFormFieldNums || dict.has("FT") -> ObjectKind.FORM_FIELD
            dict.has("StmF") || dict.has("StrF") || (dict.has("Filter") && dict.has("V") && dict.has("R")) -> ObjectKind.SECURITY
            else -> ObjectKind.OTHER
        }
    }

    fun annotationSubtype(obj: PdfObj?): String? = (obj as? PdfDict)?.name("Subtype")

    companion object {
        val FONT_SUBTYPES = setOf("Type1", "TrueType", "Type0", "Type3", "MMType1", "CIDFontType0", "CIDFontType2")
        val ANNOT_SUBTYPES = setOf(
            "Text", "Link", "FreeText", "Line", "Square", "Circle", "Polygon", "PolyLine", "Highlight", "Underline", "Squiggly", "StrikeOut",
            "Stamp", "Caret", "Ink", "Popup", "FileAttachment", "Sound", "Movie", "Widget", "Screen", "PrinterMark", "TrapNet", "Watermark",
            "3D", "Redact",
        )
    }
}

/** References contained in [o] (not following them). */
fun refsIn(o: PdfObj?, out: MutableList<PdfRef> = ArrayList()): MutableList<PdfRef> {
    when (o) {
        is PdfRef -> out.add(o)
        is PdfArray -> o.items.forEach { refsIn(it, out) }
        is PdfDict -> o.map.values.forEach { refsIn(it, out) }
        is PdfStream -> refsIn(o.dict, out)
        else -> {}
    }
    return out
}
