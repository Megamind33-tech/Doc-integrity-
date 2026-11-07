package com.docintegrity.forensics.compare

import com.docintegrity.forensics.image.GrayImage
import com.docintegrity.forensics.image.ImageDecoders
import com.docintegrity.forensics.image.PerceptualHash
import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.model.Region
import com.docintegrity.forensics.model.Side
import com.docintegrity.forensics.pdf.content.DocumentContent
import com.docintegrity.forensics.pdf.content.RectD
import com.docintegrity.forensics.pdf.images.ExtractedImage
import com.docintegrity.forensics.pdf.images.PdfImageExtractor
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.util.FileHashes
import com.docintegrity.forensics.util.Hashing
import java.text.Normalizer

// ================================================================================================================
// Inputs
// ================================================================================================================

enum class ReferenceKind(val label: String) {
    PDF("PDF"), DOCX("Word document (.docx)"), IMAGE("image"), HASH_ONLY("trusted hash"), ISSUER_RECORD("issuer record")
}

class ReferenceFile(val name: String, val bytes: ByteArray)

/**
 * What the examiner supplies as the trusted reference. Everything here is user-asserted: the tool cannot verify
 * that a "trusted" original really is the issuer's original, and says so in the report.
 */
class ReferenceInput(
    val file: ReferenceFile? = null,
    /** Hex digests (MD5/SHA-1/SHA-256/SHA-512, algorithm inferred from length) obtained from a trusted channel. */
    val hashes: List<String> = emptyList(),
    /** Field name -> value, copied from a verified issuer record or verification portal. */
    val issuerRecord: Map<String, String> = emptyMap(),
) {
    val isEmpty get() = file == null && hashes.none { it.isNotBlank() } && issuerRecord.values.none { it.isNotBlank() }
}

/** Renders PDF pages to grayscale. Implemented on Android with PdfRenderer; tests inject their own. */
interface PageRenderer {
    fun render(pdfBytes: ByteArray, page: Int, widthPx: Int): GrayImage?
}

// ================================================================================================================
// Results
// ================================================================================================================

enum class Tri { YES, NO, UNKNOWN }

class HashCheck(val algorithm: String, val supplied: String, val computed: String, val match: Boolean)

enum class HunkKind { ADDED, REMOVED, REPLACED }

class Tok(val text: String, val key: String, val page: Int, val line: Int, val rect: RectD?, val pageW: Double, val pageH: Double)

class TextHunk(val kind: HunkKind, val reference: List<Tok>, val submitted: List<Tok>, val category: EntityType?, val context: String) {
    val referenceText get() = reference.joinToString(" ") { it.text }
    val submittedText get() = submitted.joinToString(" ") { it.text }
    val page: Int get() = (submitted.firstOrNull() ?: reference.firstOrNull())?.page ?: -1
}

enum class SegKind { EQUAL, REMOVED, ADDED }
class Segment(val kind: SegKind, val text: String)
class SideBySide(val reference: List<Segment>, val submitted: List<Segment>)

enum class DeltaKind { CHANGED, MISSING, ADDED }
class EntityDelta(val type: EntityType, val kind: DeltaKind, val label: String?, val reference: String?, val submitted: String?, val page: Int?)

enum class ImageVerdict(val label: String) {
    IDENTICAL("identical bytes"), SAME_PICTURE("same picture, different encoding"), LOCALLY_DIFFERENT("same picture with local differences"),
    SIMILAR("similar picture; review"), DIFFERENT("different picture"), MISSING_IN_SUBMITTED("not present in submitted"), ADDED_IN_SUBMITTED("added in submitted"),
}
class ImageMatch(val verdict: ImageVerdict, val reference: String?, val submitted: String?, val hashDistance: Int?, val page: Int?)

class PageVisual(val page: Int, val diff: com.docintegrity.forensics.compare.VisualDiffResult, val pageWidth: Double, val pageHeight: Double)

class IssuerFieldResult(val field: String, val expected: String, val matched: Boolean, val found: List<String>)

class ComparisonResult(
    val referenceKind: ReferenceKind?,
    val referenceName: String?,
    val referenceSha256: String?,
    val hashChecks: List<HashCheck>,
    val bytesIdentical: Tri,
    val textCompared: Boolean,
    val textHunks: List<TextHunk>,
    val textTruncated: Boolean,
    val sideBySide: SideBySide?,
    val entityDeltas: List<EntityDelta>,
    val images: List<ImageMatch>,
    val visual: List<PageVisual>,
    val issuer: List<IssuerFieldResult>,
    val meaningChanged: Tri,
    val referenceTextAvailable: Boolean,
    val referenceDocxNotes: List<String>,
    val findings: List<Finding>,
)

// ================================================================================================================
// Engine
// ================================================================================================================

object ComparisonEngine {

    private const val SAME_PICTURE_MAX = 5
    private const val SIMILAR_MAX = 12
    private const val LOCAL_BLOCK_MAD = 38
    private const val MIN_IMAGE_SIDE = 40
    private const val MAX_VISUAL_PAGES = 12
    private const val MAX_LISTED = 14

    private const val UNVERIFIED = "This tool cannot verify that the reference you supplied is itself authentic; the comparison is only as reliable as that reference."

    fun compare(
        submittedBytes: ByteArray,
        submittedHashes: FileHashes,
        submittedFile: PdfFile?,
        submittedContent: DocumentContent?,
        ref: ReferenceInput,
        renderer: PageRenderer?,
    ): ComparisonResult {
        val findings = ArrayList<Finding>()

        // ---- 1. exact hashes ---------------------------------------------------------------------------------
        val checks = ArrayList<HashCheck>()
        for (h in ref.hashes.filter { it.isNotBlank() }) {
            val hex = Hashing.normaliseHexHash(h)
            val alg = Hashing.algorithmForHexLength(hex.length)
            if (alg == null) {
                findings.add(
                    Finding(
                        id = "CMP_HASH_BAD", area = Area.COMPARISON, evidence = EvidenceClass.LIMITATION,
                        title = "Reference hash not recognised",
                        detected = "“$h” is not a valid MD5, SHA-1, SHA-256 or SHA-512 hex digest (got ${hex.length} hex digits).",
                        establishes = "That value was not used.", unknown = "Whether the file matches the digest you intended to supply.",
                    ),
                )
                continue
            }
            val computed = when (alg) { "MD5" -> submittedHashes.md5; "SHA-1" -> submittedHashes.sha1; "SHA-256" -> submittedHashes.sha256; else -> submittedHashes.sha512 }
            checks.add(HashCheck(alg, hex, computed, computed == hex))
        }
        var refFileHash: String? = null
        var refFileBytesIdentical = Tri.UNKNOWN
        ref.file?.let {
            refFileHash = Hashing.sha256(it.bytes)
            refFileBytesIdentical = if (refFileHash == submittedHashes.sha256) Tri.YES else Tri.NO
        }
        val hashMismatch = checks.filter { !it.match }
        val hashMatch = checks.filter { it.match }
        val bytesIdentical = when {
            hashMismatch.isNotEmpty() || refFileBytesIdentical == Tri.NO -> Tri.NO
            hashMatch.isNotEmpty() || refFileBytesIdentical == Tri.YES -> Tri.YES
            else -> Tri.UNKNOWN
        }
        if (hashMatch.isNotEmpty()) {
            findings.add(
                Finding(
                    id = "CMP_HASH_MATCH", area = Area.COMPARISON, evidence = EvidenceClass.INFO,
                    title = "File bytes match the reference hash",
                    detected = hashMatch.joinToString("; ") { "${it.algorithm} ${it.computed}" },
                    establishes = "The examined file is byte-for-byte the file that the reference hash describes. No byte of it has changed relative to that file.",
                    unknown = "Whether the reference hash itself came from a trustworthy source, and whether the content of that file is true. A matching hash says nothing about whether the information inside is genuine. $UNVERIFIED",
                ),
            )
        }
        if (hashMismatch.isNotEmpty()) {
            val onlyHashes = ref.file == null
            findings.add(
                Finding(
                    id = "CMP_HASH_MISMATCH", area = Area.COMPARISON,
                    evidence = if (onlyHashes) EvidenceClass.ESTABLISHED else EvidenceClass.INFO,
                    title = "File bytes differ from the reference hash",
                    detected = hashMismatch.joinToString("; ") { "${it.algorithm}: reference ${it.supplied.take(20)}… ≠ file ${it.computed.take(20)}…" },
                    establishes = "The examined file is not byte-identical to the file the reference hash describes." +
                        if (onlyHashes) " Relative to the hash you designated as trusted, the file has changed (or is a different file)." else "",
                    unknown = "A hash mismatch shows the BYTES differ, not that the meaning does: re-saving, converting or optimising a PDF changes every hash while leaving its content unchanged." +
                        (if (onlyHashes) " Without the original file the content cannot be compared. " else " The content comparison below addresses meaning. ") + UNVERIFIED,
                ),
            )
        }

        // ---- no reference at all ----------------------------------------------------------------------------
        if (ref.isEmpty) {
            findings.add(noReference())
            return empty(findings)
        }

        // ---- 2. load the reference file ----------------------------------------------------------------------
        var refKind: ReferenceKind? = null
        var refPdf: PdfFile? = null
        var refContent: DocumentContent? = null
        var refDocx: DocxContent? = null
        var refImageBytes: ByteArray? = null
        val notes = ArrayList<String>()
        ref.file?.let { f ->
            val b = f.bytes
            when {
                b.size >= 5 && String(b, 0, 5, Charsets.ISO_8859_1).startsWith("%PDF") || PdfFile.open(b) != null -> {
                    refKind = ReferenceKind.PDF
                    refPdf = PdfFile.open(b)
                    if (com.docintegrity.forensics.pdf.content.ContentExtractor.isAvailable) refContent = com.docintegrity.forensics.pdf.content.ContentExtractor.extract(b)
                }
                DocxReader.looksLikeDocx(b) -> {
                    refKind = ReferenceKind.DOCX
                    refDocx = DocxReader.read(b)
                    refDocx?.let { d ->
                        if (d.trackedInsertions + d.trackedDeletions > 0) notes.add("The reference .docx itself contains ${d.trackedInsertions} tracked insertion(s) and ${d.trackedDeletions} tracked deletion(s)" + (if (d.revisionAuthors.isNotEmpty()) " by ${d.revisionAuthors.joinToString()}" else "") + "; the current (accepted) text was used.")
                        d.core["lastModifiedBy"]?.let { notes.add("Reference .docx last modified by “$it”") }
                    }
                }
                isImage(b) -> { refKind = ReferenceKind.IMAGE; refImageBytes = b }
                else -> findings.add(
                    Finding(
                        id = "CMP_REF_UNREADABLE", area = Area.COMPARISON, evidence = EvidenceClass.LIMITATION, blocking = true,
                        title = "Reference file type not supported",
                        detected = "“${f.name}” is not a PDF, .docx or recognised image.", establishes = "No content comparison was possible.",
                        unknown = "How the document differs from the reference.",
                    ),
                )
            }
        }
        if (refKind == null && ref.file == null) refKind = if (checks.isNotEmpty()) ReferenceKind.HASH_ONLY else ReferenceKind.ISSUER_RECORD

        // ---- 3. file-vs-file: bytes ---------------------------------------------------------------------------
        if (ref.file != null && refKind != null) {
            if (refFileBytesIdentical == Tri.YES) {
                findings.add(
                    Finding(
                        id = "CMP_BYTES_IDENTICAL", area = Area.COMPARISON, evidence = EvidenceClass.INFO,
                        title = "File is byte-identical to the supplied original",
                        detected = "SHA-256 ${submittedHashes.sha256} for both.",
                        establishes = "Nothing in the file differs from the original you supplied.",
                        unknown = "Whether that original is itself genuine, and whether its content is true. $UNVERIFIED",
                    ),
                )
            }
        }

        // ---- 4. text + entities -------------------------------------------------------------------------------
        val subTokens = submittedContent?.takeIf { it.wordCount > 0 }?.let { TextTokens.from(it) }
        val refTokens: List<Tok>? = when (refKind) {
            ReferenceKind.PDF -> refContent?.takeIf { it.wordCount > 0 }?.let { TextTokens.from(it) }
            ReferenceKind.DOCX -> refDocx?.text?.takeIf { it.isNotBlank() }?.let { TextTokens.from(it) }
            else -> null
        }
        var hunks = emptyList<TextHunk>()
        var truncated = false
        var side: SideBySide? = null
        val deltas = ArrayList<EntityDelta>()
        val textCompared = subTokens != null && refTokens != null
        if (textCompared) {
            val r = TextCompare.compare(refTokens!!, subTokens!!)
            hunks = r.hunks; truncated = r.truncated; side = r.sideBySide
            val refLines = TextTokens.lines(refContent?.takeIf { refKind == ReferenceKind.PDF }, refDocx?.text)
            val subLines = TextTokens.lines(submittedContent, null)
            deltas += EntityCompare.compare(EntityExtractor.extract(refLines.map { it.second }), refLines, EntityExtractor.extract(subLines.map { it.second }), subLines)
            findings += textFindings(hunks, truncated, deltas, refKind!!, ref.file!!.name)
        } else if (ref.file != null && refKind in setOf(ReferenceKind.PDF, ReferenceKind.DOCX)) {
            findings.add(
                Finding(
                    id = "CMP_TEXT_UNAVAILABLE", area = Area.COMPARISON, evidence = EvidenceClass.LIMITATION,
                    title = "Text could not be compared",
                    detected = when {
                        subTokens == null && refTokens == null -> "Neither document has an extractable text layer (both look image-based)."
                        subTokens == null -> "The examined document has no extractable text layer (it looks image-based), while the original has text."
                        else -> "The original has no extractable text layer (it looks image-based), while the examined document has text."
                    },
                    establishes = "Text, name, date, amount and number comparison was skipped. This tool does not perform OCR.",
                    unknown = "Whether the wording or figures differ. Only the rendered-page and image comparisons below can address this, and they are indicators for human review.",
                ),
            )
        }

        // ---- 5. embedded pictures -----------------------------------------------------------------------------
        val images = ArrayList<ImageMatch>()
        val subImgs = submittedFile?.let { PdfImageExtractor.extract(it).images } ?: emptyList()
        val refImgs: List<Pair<String, ByteArray?>> = when (refKind) {
            ReferenceKind.PDF -> refPdf?.let { f -> PdfImageExtractor.extract(f).images.map { "obj ${it.objNum}" to it.toBytesForCompare() } } ?: emptyList()
            ReferenceKind.DOCX -> refDocx?.images?.map { it.name to it.bytes } ?: emptyList()
            ReferenceKind.IMAGE -> listOf("reference image" to refImageBytes)
            else -> emptyList()
        }
        if (ref.file != null && (refImgs.isNotEmpty() || subImgs.isNotEmpty()) && refKind != ReferenceKind.IMAGE) {
            val scanDims = HashSet<Pair<Int, Int>>()
            for (c in listOfNotNull(submittedContent, refContent.takeIf { refKind == ReferenceKind.PDF })) for (pg in c.pages) {
                val area = pg.width * pg.height
                for (im in pg.images) if (!im.stencil && area > 0 && im.rect.area / area >= 0.6) scanDims.add(im.widthPx to im.heightPx)
            }
            images += compareImages(refImgs, subImgs, scanDims)
            findings += imageFindings(images)
        }

        // ---- 6. rendered pages --------------------------------------------------------------------------------
        val visual = ArrayList<PageVisual>()
        if (renderer != null && ref.file != null && (refKind == ReferenceKind.PDF || refKind == ReferenceKind.IMAGE)) {
            val subPages = submittedContent?.pages?.size ?: submittedFile?.let { com.docintegrity.forensics.pdf.analysis.DocView(it, it.lastRevision).pages.size } ?: 0
            val n = if (refKind == ReferenceKind.IMAGE) 1 else minOf(subPages, refContent?.pages?.size ?: subPages, MAX_VISUAL_PAGES)
            for (p in 0 until n) {
                val sub = renderer.render(submittedBytes, p, VisualDiff.TARGET_WIDTH) ?: continue
                val refImg: GrayImage? = if (refKind == ReferenceKind.PDF) renderer.render(ref.file.bytes, p, VisualDiff.TARGET_WIDTH)
                else ImageDecoders.decode(refImageBytes!!)?.gray()
                if (refImg == null) continue
                val pg = submittedContent?.pages?.getOrNull(p)
                visual.add(PageVisual(p, VisualDiff.compare(refImg, sub), pg?.width ?: 595.0, pg?.height ?: 842.0))
            }
            findings += visualFindings(visual, textCompared, hunks.isEmpty())
            if (refContent != null && submittedContent != null && refContent!!.pages.size != submittedContent.pages.size) {
                findings.add(
                    Finding(
                        id = "CMP_PAGE_COUNT", area = Area.COMPARISON, evidence = EvidenceClass.ESTABLISHED,
                        title = "Page count differs from the original",
                        detected = "Original: ${refContent!!.pages.size} page(s); examined: ${submittedContent.pages.size} page(s).",
                        establishes = "Relative to the original you supplied, pages were added or removed (or the document was reflowed).",
                        unknown = "Which pages, and whether the change is substantive. Converting between formats can reflow pages. $UNVERIFIED",
                    ),
                )
            }
        }

        // ---- 7. issuer record ---------------------------------------------------------------------------------
        val issuer = ArrayList<IssuerFieldResult>()
        if (ref.issuerRecord.values.any { it.isNotBlank() } && submittedContent != null) {
            val lines = TextTokens.lines(submittedContent, null)
            val ents = EntityExtractor.extract(lines.map { it.second })
            val fullNorm = TextTokens.normalizeForSearch(lines.joinToString(" ") { it.second })
            for ((k, v) in ref.issuerRecord.filter { it.value.isNotBlank() }) issuer.add(IssuerCheck.check(k, v, ents, fullNorm))
            findings += issuerFindings(issuer)
        } else if (ref.issuerRecord.values.any { it.isNotBlank() }) {
            findings.add(
                Finding(
                    id = "CMP_ISSUER_UNAVAILABLE", area = Area.COMPARISON, evidence = EvidenceClass.LIMITATION,
                    title = "Issuer record could not be checked",
                    detected = "The examined document has no extractable text layer.", establishes = "No field of the issuer record was compared.",
                    unknown = "Whether the document's visible values agree with the record.",
                ),
            )
        }

        // ---- overall "meaning changed?" -----------------------------------------------------------------------
        val meaning = when {
            hunks.isNotEmpty() || deltas.isNotEmpty() || images.any { it.verdict in setOf(ImageVerdict.DIFFERENT, ImageVerdict.MISSING_IN_SUBMITTED, ImageVerdict.ADDED_IN_SUBMITTED, ImageVerdict.LOCALLY_DIFFERENT) } || issuer.any { !it.matched } -> Tri.YES
            textCompared || images.isNotEmpty() || issuer.isNotEmpty() -> Tri.NO
            else -> Tri.UNKNOWN
        }
        if (ref.file != null && bytesIdentical == Tri.NO && meaning == Tri.NO && textCompared) {
            findings.add(
                Finding(
                    id = "CMP_BYTES_ONLY", area = Area.COMPARISON, evidence = EvidenceClass.INFO,
                    title = "File bytes differ, but no difference in meaning was found",
                    detected = "SHA-256 differs from the supplied original, yet extracted text, names, dates, amounts, document numbers and embedded pictures all match" +
                        (if (visual.isNotEmpty()) "; ${visual.sumOf { it.diff.regions.size }} rendered-page region(s) differ" else "") + ".",
                    establishes = "The file is not a copy of the original, but nothing this tool can compare shows a change of wording or figures. This is the typical result of re-saving, converting or regenerating a document.",
                    unknown = "Changes that leave the text layer untouched (small visual edits, content inside images, hidden layers) and anything the text comparison normalises away (case, punctuation, spacing). $UNVERIFIED",
                ),
            )
        }

        return ComparisonResult(
            referenceKind = refKind, referenceName = ref.file?.name, referenceSha256 = refFileHash, hashChecks = checks,
            bytesIdentical = bytesIdentical, textCompared = textCompared, textHunks = hunks, textTruncated = truncated, sideBySide = side,
            entityDeltas = deltas, images = images, visual = visual, issuer = issuer, meaningChanged = meaning,
            referenceTextAvailable = refTokens != null, referenceDocxNotes = notes, findings = findings,
        )
    }

    // ------------------------------------------------------------------------------------------------------------

    private fun noReference() = Finding(
        id = "CMP_NO_REFERENCE", area = Area.COMPARISON, evidence = EvidenceClass.LIMITATION,
        title = "No trusted original supplied",
        detected = "No reference file, hash or issuer record was provided.",
        establishes = "Nothing about the document's ORIGINAL contents is known to this tool. All findings compare the file only against itself.",
        unknown = "What the document originally said. To test content, supply an authenticated original (PDF, image or .docx), a trusted hash, or a verified issuer record.",
    )

    private fun empty(findings: List<Finding>) = ComparisonResult(null, null, null, emptyList(), Tri.UNKNOWN, false, emptyList(), false, null, emptyList(), emptyList(), emptyList(), emptyList(), Tri.UNKNOWN, false, emptyList(), findings)

    private fun isImage(b: ByteArray): Boolean = b.size > 8 && (
        (b[0] == 0xFF.toByte() && b[1] == 0xD8.toByte()) || (b[0] == 0x89.toByte() && b[1] == 'P'.code.toByte()) ||
            (b[0] == 'G'.code.toByte() && b[1] == 'I'.code.toByte()) || (b[0] == 'B'.code.toByte() && b[1] == 'M'.code.toByte()) ||
            (b[0] == 'R'.code.toByte() && b[8] == 'W'.code.toByte())
        )

    private fun ExtractedImage.toBytesForCompare(): ByteArray? = if (kind == com.docintegrity.forensics.pdf.images.ImageKind.JPEG) data else null

    // ---- findings builders ---------------------------------------------------------------------------------------

    private fun hunkRegions(h: TextHunk): List<Region> {
        val out = ArrayList<Region>()
        fun add(toks: List<Tok>, side: Side, label: String) {
            val byPage = toks.filter { it.rect != null }.groupBy { it.page }
            for ((pg, ts) in byPage) {
                val r = ts.map { it.rect!! }.reduce { a, b -> a.union(b) }
                out.add(Region(pg, r.x0, r.y0, r.w, r.h, ts[0].pageW, ts[0].pageH, side, label))
            }
        }
        if (h.submitted.isNotEmpty()) add(h.submitted, Side.SUBMITTED, "examined: “${h.submittedText.take(40)}”")
        if (h.reference.isNotEmpty()) add(h.reference, Side.REFERENCE, "original: “${h.referenceText.take(40)}”")
        return out
    }

    private fun describe(h: TextHunk): String {
        val pg = if (h.page >= 0) " (page ${h.page + 1})" else ""
        val cat = h.category?.let { " [${it.label.lowercase()}]" } ?: ""
        val ctx = if (h.context.isNotBlank()) "${h.context} " else ""
        return when (h.kind) {
            HunkKind.REPLACED -> "$ctx“${h.referenceText}” → “${h.submittedText}”$cat$pg"
            HunkKind.ADDED -> "$ctx+ “${h.submittedText}”$cat$pg"
            HunkKind.REMOVED -> "$ctx− “${h.referenceText}”$cat$pg"
        }
    }

    private fun textFindings(hunks: List<TextHunk>, truncated: Boolean, deltas: List<EntityDelta>, kind: ReferenceKind, refName: String): List<Finding> {
        val out = ArrayList<Finding>()
        val what = if (kind == ReferenceKind.DOCX) "the supplied Word original" else "the supplied original"
        if (hunks.isEmpty()) {
            out.add(
                Finding(
                    id = "CMP_TEXT_SAME", area = Area.COMPARISON, evidence = EvidenceClass.INFO,
                    title = "Extracted text matches the original",
                    detected = "After normalising case, punctuation and spacing, the examined document's text is the same as in $what.",
                    establishes = "No wording, name, date, amount or number differs between the two text layers.",
                    unknown = "Anything outside the text layer: pictures, small visual edits, hidden layers, or text drawn as images. Spacing, case and punctuation differences are normalised away. $UNVERIFIED",
                ),
            )
            return out
        }
        val byCat = hunks.groupBy { it.category }
        out.add(
            Finding(
                id = "CMP_TEXT_DIFF", area = Area.COMPARISON, evidence = EvidenceClass.ESTABLISHED,
                title = "${hunks.size} text difference${if (hunks.size == 1) "" else "s"} from the original",
                detected = hunks.take(MAX_LISTED).joinToString("\n") { describe(it) } + if (hunks.size > MAX_LISTED) "\n… ${hunks.size - MAX_LISTED} more" else "",
                establishes = "Relative to $what, these passages were added, removed or changed in the examined document. The original and the examined text are shown side by side.",
                unknown = "Whether the difference is a falsification, a legitimate later version, or an artefact of conversion. Conversion between formats can re-flow text, and name detection is pattern-based. $UNVERIFIED" +
                    if (truncated) " The diff was too large to resolve in detail; it is reported as one block." else "",
                details = byCat.map { (c, l) -> (c?.label ?: "Other text") to "${l.size} change(s)" },
                regions = hunks.take(30).flatMap { hunkRegions(it) },
            ),
        )
        for (t in EntityType.values()) {
            val ds = deltas.filter { it.type == t }
            if (ds.isEmpty()) continue
            out.add(
                Finding(
                    id = "CMP_ENTITY_${t.name}", area = Area.COMPARISON, evidence = EvidenceClass.ESTABLISHED,
                    title = if (ds.size == 1) "${t.label} differs from the original" else "${t.label}s differ from the original (${ds.size})",
                    detected = ds.take(MAX_LISTED).joinToString("\n") { d ->
                        val lab = d.label?.let { "$it: " } ?: ""
                        when (d.kind) {
                            DeltaKind.CHANGED -> "$lab“${d.reference}” → “${d.submitted}”"
                            DeltaKind.MISSING -> "$lab“${d.reference}” is in the original but not in the examined document"
                            DeltaKind.ADDED -> "$lab“${d.submitted}” is in the examined document but not in the original"
                        } + (d.page?.let { " (page ${it + 1})" } ?: "")
                    },
                    establishes = "A ${t.label.lowercase()} value in the examined document differs from the corresponding value in the supplied original.",
                    unknown = when (t) {
                        EntityType.NAME -> "Names are recognised only after labels such as “Received from:”, so name detection is heuristic. "
                        EntityType.DATE -> "Numeric dates such as 03/04/2024 are ambiguous between day-first and month-first; both readings are tried. "
                        else -> ""
                    } + "Whether the difference is deceptive or a legitimate update. $UNVERIFIED",
                ),
            )
        }
        return out
    }

    private fun imageFindings(images: List<ImageMatch>): List<Finding> {
        if (images.isEmpty()) return emptyList()
        val bad = images.filter { it.verdict in setOf(ImageVerdict.DIFFERENT, ImageVerdict.MISSING_IN_SUBMITTED, ImageVerdict.ADDED_IN_SUBMITTED, ImageVerdict.LOCALLY_DIFFERENT) }
        val review = images.filter { it.verdict == ImageVerdict.SIMILAR }
        val out = ArrayList<Finding>()
        if (bad.isNotEmpty()) {
            out.add(
                Finding(
                    id = "CMP_IMAGE_DIFF", area = Area.COMPARISON, evidence = EvidenceClass.ESTABLISHED,
                    title = "Embedded picture differs from the original",
                    detected = bad.joinToString("\n") { m -> "${m.verdict.label}: original ${m.reference ?: "—"}, examined ${m.submitted ?: "—"}" + (m.hashDistance?.let { " (perceptual-hash distance $it of 64)" } ?: "") },
                    establishes = "A picture (for example a photograph) in the examined document does not match the picture in the supplied original.",
                    unknown = "Whether the picture was swapped deliberately or re-rendered by a conversion; tiny edits inside a picture may not be detected. Perceptual hashes compare appearance, not provenance. $UNVERIFIED",
                    details = bad.map { (it.reference ?: "—") to it.verdict.label },
                ),
            )
        }
        if (review.isNotEmpty()) {
            out.add(
                Finding(
                    id = "CMP_IMAGE_REVIEW", area = Area.COMPARISON, evidence = EvidenceClass.INDICATOR,
                    title = "Picture is similar to the original but not the same",
                    detected = review.joinToString("\n") { "original ${it.reference}, examined ${it.submitted} (distance ${it.hashDistance} of 64)" },
                    establishes = "The picture resembles the original but differs more than ordinary re-compression normally does.",
                    unknown = "Retouching, cropping or aggressive re-compression all produce this. Review the two pictures by eye.",
                ),
            )
        }
        val ok = images.filter { it.verdict == ImageVerdict.IDENTICAL || it.verdict == ImageVerdict.SAME_PICTURE }
        if (bad.isEmpty() && ok.isNotEmpty()) {
            out.add(
                Finding(
                    id = "CMP_IMAGE_SAME", area = Area.COMPARISON, evidence = EvidenceClass.INFO,
                    title = "Embedded pictures match the original",
                    detected = ok.joinToString("; ") { "${it.reference} ↔ ${it.submitted}: ${it.verdict.label}" },
                    establishes = "The pictures in the examined document are the same pictures as in the original (possibly re-encoded).",
                    unknown = "Small local retouching below the comparison's sensitivity is not excluded.",
                ),
            )
        }
        return out
    }

    private fun visualFindings(pages: List<PageVisual>, textCompared: Boolean, textSame: Boolean): List<Finding> {
        if (pages.isEmpty()) return emptyList()
        val withRegions = pages.filter { it.diff.regions.isNotEmpty() }
        val totalRegions = withRegions.sumOf { it.diff.regions.size }
        if (totalRegions == 0) {
            return listOf(
                Finding(
                    id = "CMP_VISUAL_SAME", area = Area.COMPARISON, evidence = EvidenceClass.INFO,
                    title = "Rendered pages match the original",
                    detected = "${pages.size} page(s) rendered and compared; no region differs after alignment and noise suppression.",
                    establishes = "At this sensitivity the pages look the same.",
                    unknown = "Edits smaller than the comparison grid, colour-only changes of similar brightness, and re-rendering differences hidden by the noise threshold.",
                ),
            )
        }
        val regions = withRegions.flatMap { pv ->
            pv.diff.regions.take(20).flatMap { r ->
                val x = r.nx0 * pv.pageWidth; val y = r.ny0 * pv.pageHeight; val w = (r.nx1 - r.nx0) * pv.pageWidth; val h = (r.ny1 - r.ny0) * pv.pageHeight
                listOf(
                    Region(pv.page, x, y, w, h, pv.pageWidth, pv.pageHeight, Side.SUBMITTED, "visual difference"),
                    Region(pv.page, x, y, w, h, pv.pageWidth, pv.pageHeight, Side.REFERENCE, "visual difference"),
                )
            }
        }
        val sharedTypography = textCompared && textSame
        val widespread = withRegions.any { it.diff.changedPixelShare > 0.04 }
        return listOf(
            Finding(
                id = "CMP_VISUAL_DIFF", area = Area.COMPARISON,
                evidence = if (sharedTypography && widespread) EvidenceClass.INFO else EvidenceClass.INDICATOR,
                title = "$totalRegions region(s) of the rendered pages differ from the original",
                detected = withRegions.joinToString("; ") { "page ${it.page + 1}: ${it.diff.regions.size} region(s), ${"%.1f".format(it.diff.changedPixelShare * 100)}% of pixels changed" } +
                    (if (pages.any { it.diff.aspectMismatch }) ". Page proportions differ, so alignment is approximate" else ""),
                establishes = if (sharedTypography && widespread)
                    "The pictures of the pages differ widely while the text is identical: typography and layout changed (fonts, spacing), as happens in a format conversion. This is not by itself a change of wording."
                else "Parts of the rendered pages look different from the original. Where the text layer is identical or unavailable, these regions are the only place a change could be visible.",
                unknown = "Rendered comparison cannot tell edits from re-rendering or re-scanning differences, so these regions are for human review (use the side-by-side view); they are not proof. No similarity score is computed.",
                regions = regions,
            ),
        )
    }

    private fun issuerFindings(rs: List<IssuerFieldResult>): List<Finding> {
        val out = ArrayList<Finding>()
        val bad = rs.filter { !it.matched }
        val good = rs.filter { it.matched }
        if (bad.isNotEmpty()) {
            out.add(
                Finding(
                    id = "CMP_ISSUER_MISMATCH", area = Area.COMPARISON, evidence = EvidenceClass.ESTABLISHED,
                    title = if (bad.size == 1) "1 field disagrees with the issuer record" else "${bad.size} fields disagree with the issuer record",
                    detected = bad.joinToString("\n") { r -> "${r.field}: record says “${r.expected}”; document " + if (r.found.isEmpty()) "does not contain it" else "shows " + r.found.joinToString { "“$it”" } },
                    establishes = "A value in the document differs from the value in the verified issuer record you supplied.",
                    unknown = "Whether the record was entered correctly and is current. The document may predate an update. $UNVERIFIED",
                ),
            )
        }
        if (good.isNotEmpty()) {
            out.add(
                Finding(
                    id = "CMP_ISSUER_MATCH", area = Area.COMPARISON, evidence = EvidenceClass.INFO,
                    title = if (good.size == 1) "1 field agrees with the issuer record" else "${good.size} fields agree with the issuer record",
                    detected = good.joinToString("; ") { "${it.field}: “${it.expected}”" },
                    establishes = "These values appear in the document exactly as in the issuer record.",
                    unknown = "That the rest of the document is unchanged, or that the record itself is accurate. $UNVERIFIED",
                ),
            )
        }
        return out
    }

    // ---- images ---------------------------------------------------------------------------------------------------

    private class Pic(val label: String, val raster: com.docintegrity.forensics.image.RasterImage?, val gray: GrayImage?, val dhash: Long?, val page: Int?, val sha: String?, val dims: Pair<Int, Int>?)

    private fun compareImages(refImgs: List<Pair<String, ByteArray?>>, sub: List<ExtractedImage>, skipDims: Set<Pair<Int, Int>>): List<ImageMatch> {
        fun pic(label: String, bytes: ByteArray?, page: Int?, ex: ExtractedImage?): Pic? {
            val r = when {
                ex != null -> ex.toRaster { ImageDecoders.decode(it) }
                bytes != null -> ImageDecoders.decode(bytes)
                else -> null
            }
            val g = r?.gray()
            if (g != null && (g.w < MIN_IMAGE_SIDE || g.h < MIN_IMAGE_SIDE)) return null
            val dims = ex?.let { it.width to it.height } ?: r?.let { it.w to it.h }
            if (dims != null && dims in skipDims) return null    // page-sized scans are judged by the rendered-page comparison
            return Pic(label, r, g, g?.let { PerceptualHash.dhash(it) }, page, (bytes ?: ex?.data)?.let { Hashing.sha256(it) }, dims)
        }
        val refs = refImgs.mapNotNull { (l, b) -> pic(l, b, null, null) }
        val subs = sub.mapNotNull { e -> pic("obj ${e.objNum} (${e.width}×${e.height}${if (e.pages.isNotEmpty()) ", page ${e.pages.min() + 1}" else ""})", null, e.pages.minOrNull(), e) }
        val out = ArrayList<ImageMatch>()
        val used = HashSet<Int>()
        for (r in refs) {
            var best = -1; var bestD = Int.MAX_VALUE
            for ((i, s) in subs.withIndex()) {
                if (i in used) continue
                if (r.sha != null && r.sha == s.sha) { best = i; bestD = 0; break }
                if (r.dhash != null && s.dhash != null) { val d = PerceptualHash.distance(r.dhash, s.dhash); if (d < bestD) { bestD = d; best = i } }
            }
            if (best < 0) { out.add(ImageMatch(ImageVerdict.MISSING_IN_SUBMITTED, r.label, null, null, null)); continue }
            val s = subs[best]
            used.add(best)
            val v = ImageCompare.classify(r.sha != null && r.sha == s.sha, bestD, r.raster, s.raster)
            out.add(ImageMatch(v, r.label, s.label, bestD, s.page))
        }
        for ((i, s) in subs.withIndex()) if (i !in used && refs.isNotEmpty()) out.add(ImageMatch(ImageVerdict.ADDED_IN_SUBMITTED, null, s.label, null, s.page))
        return out
    }
}

/**
 * Decides how two pictures relate. Thresholds are fixed and documented (see docs/DETECTION.md):
 *  - dHash distance <= 5 of 64 and mean colour difference <= 10/255: same picture (re-encoding noise is far below this);
 *  - a changed region found by the rendered-diff algorithm inside an otherwise matching picture: local difference;
 *  - dHash distance > 12 or mean colour difference > 30: different picture;
 *  - anything in between: similar, human review.
 */
object ImageCompare {
    const val SAME_PICTURE_MAX = 5
    const val SIMILAR_MAX = 12
    const val SAME_COLOUR_MAX = 10.0
    const val DIFFERENT_COLOUR_MIN = 30.0

    fun classify(sameBytes: Boolean, hashDistance: Int, ref: com.docintegrity.forensics.image.RasterImage?, sub: com.docintegrity.forensics.image.RasterImage?): ImageVerdict {
        if (sameBytes) return ImageVerdict.IDENTICAL
        if (hashDistance > SIMILAR_MAX) return ImageVerdict.DIFFERENT
        val colour = if (ref != null && sub != null) colourDifference(ref, sub) else 0.0
        if (colour > DIFFERENT_COLOUR_MIN) return ImageVerdict.DIFFERENT
        if (hashDistance <= SAME_PICTURE_MAX && colour <= SAME_COLOUR_MAX) {
            val regions = if (ref != null && sub != null) VisualDiff.compare(ref.gray(), sub.gray()).regions.size else 0
            return if (regions > 0) ImageVerdict.LOCALLY_DIFFERENT else ImageVerdict.SAME_PICTURE
        }
        return ImageVerdict.SIMILAR
    }

    /** Mean absolute per-channel difference (0..255) of two 32x32 colour thumbnails. */
    fun colourDifference(a: com.docintegrity.forensics.image.RasterImage, b: com.docintegrity.forensics.image.RasterImage): Double {
        val x = a.thumbnail(); val y = b.thumbnail()
        var s = 0L
        for (i in x.indices) s += Math.abs(x[i] - y[i])
        return s.toDouble() / x.size
    }
}

// ================================================================================================================
// Tokens and text diff
// ================================================================================================================

object TextTokens {
    fun key(s: String): String {
        var t = Normalizer.normalize(s, Normalizer.Form.NFKC).lowercase()
        t = t.replace('‘', '\'').replace('’', '\'').replace('“', '"').replace('”', '"').replace(Regex("[‐-―−]"), "-")
        t = t.replace(Regex("[​-‍﻿­]"), "")
        return t.trim { !(it.isLetterOrDigit() || it == '%' || it == '$' || it == '€' || it == '£') }
    }

    fun normalizeForSearch(s: String): String =
        Normalizer.normalize(s, Normalizer.Form.NFKC).lowercase().replace(Regex("[^\\p{L}\\p{N}.,%$€£/-]+"), " ").replace(Regex("\\s+"), " ").trim()

    fun from(c: DocumentContent): List<Tok> {
        val out = ArrayList<Tok>()
        for (p in c.pages) for (w in p.words) {
            val parts = w.text.split(Regex("\\s+")).filter { it.isNotEmpty() }
            for (part in parts) {
                val k = key(part)
                if (k.isNotEmpty()) out.add(Tok(part, k, p.index, w.line, w.rect, p.width, p.height))
            }
        }
        return out
    }

    fun from(text: String): List<Tok> {
        val out = ArrayList<Tok>()
        for ((li, line) in text.lines().withIndex()) for (part in line.split(Regex("\\s+")).filter { it.isNotEmpty() }) {
            val k = key(part)
            if (k.isNotEmpty()) out.add(Tok(part, k, -1, li, null, 0.0, 0.0))
        }
        return out
    }

    /** (page, text) lines: one per extracted visual line (PDF) or per paragraph (text). */
    fun lines(c: DocumentContent?, text: String?): List<Pair<Int, String>> {
        if (c != null) {
            val out = ArrayList<Pair<Int, String>>()
            for (p in c.pages) {
                val g = p.words.groupBy { it.line }
                for ((_, ws) in g.toSortedMap()) out.add(p.index to ws.sortedBy { it.rect.x0 }.joinToString(" ") { it.text })
            }
            return out
        }
        return text?.lines()?.map { -1 to it } ?: emptyList()
    }
}

class TextDiffResult(val hunks: List<TextHunk>, val truncated: Boolean, val sideBySide: SideBySide)

object TextCompare {
    fun compare(ref: List<Tok>, sub: List<Tok>): TextDiffResult {
        val r = MyersDiff.diff(ref.map { it.key }, sub.map { it.key })
        val hunks = ArrayList<TextHunk>()
        val refSegs = ArrayList<Segment>(); val subSegs = ArrayList<Segment>()
        fun join(ts: List<Tok>): String {
            val sb = StringBuilder()
            var last: Tok? = null
            for (t in ts) { if (last != null) sb.append(if (t.line != last.line || t.page != last.page) '\n' else ' '); sb.append(t.text); last = t }
            return sb.toString()
        }
        for (e in r.edits) when (e) {
            is Edit.Equal -> {
                val txt = join(sub.subList(e.bFrom, e.bTo))
                refSegs.add(Segment(SegKind.EQUAL, join(ref.subList(e.aFrom, e.aTo)))); subSegs.add(Segment(SegKind.EQUAL, txt))
            }
            is Edit.Change -> {
                val a = ref.subList(e.aFrom, e.aTo); val b = sub.subList(e.bFrom, e.bTo)
                val kind = when { a.isEmpty() -> HunkKind.ADDED; b.isEmpty() -> HunkKind.REMOVED; else -> HunkKind.REPLACED }
                val ctxStart = maxOf(0, e.bFrom - 4)
                val context = sub.subList(ctxStart, e.bFrom).filter { it.line == (b.firstOrNull() ?: sub.getOrNull(e.bFrom))?.line }.joinToString(" ") { it.text }
                hunks.add(TextHunk(kind, a, b, classify(a, b, context), context))
                if (a.isNotEmpty()) refSegs.add(Segment(SegKind.REMOVED, join(a)))
                if (b.isNotEmpty()) subSegs.add(Segment(SegKind.ADDED, join(b)))
            }
        }
        return TextDiffResult(hunks, r.truncated, SideBySide(refSegs, subSegs))
    }

    private fun classify(a: List<Tok>, b: List<Tok>, context: String): EntityType? {
        val joined = (a + b).joinToString(" ") { it.text }
        val ents = EntityExtractor.extract(listOf(joined))
        return when {
            ents.any { it.type == EntityType.DATE } -> EntityType.DATE
            ents.any { it.type == EntityType.AMOUNT } -> EntityType.AMOUNT
            ents.any { it.type == EntityType.DOC_NUMBER } -> EntityType.DOC_NUMBER
            (a + b).any { t -> t.text.any { it.isDigit() } } && (a + b).all { t -> t.text.any { it.isDigit() } || t.text.matches(Regex("[A-Za-z]{1,4}")) } -> EntityType.AMOUNT
            // names: a like-for-like replacement of 1-4 capitalised words, or any change right after a name label
            a.isNotEmpty() && b.isNotEmpty() && a.size <= 4 && b.size <= 4 && (a + b).all { t -> t.text.firstOrNull()?.isUpperCase() == true && t.text.none { it.isDigit() } } -> EntityType.NAME
            Regex("(?i)(name|received from|received by|issued to|bill(ed)? to|paid (by|to)|payee|student|employee|patient|customer|holder|beneficiary|signed by|prepared by|approved by)\\s*:?\\s*$").containsMatchIn(context) &&
                (a + b).all { t -> t.text.firstOrNull()?.isUpperCase() == true } -> EntityType.NAME
            else -> null
        }
    }
}

object EntityCompare {
    fun compare(refEnts: List<Entity>, refLines: List<Pair<Int, String>>, subEnts: List<Entity>, subLines: List<Pair<Int, String>>): List<EntityDelta> {
        val out = ArrayList<EntityDelta>()
        for (t in EntityType.values()) {
            val r = refEnts.filter { it.type == t }.toMutableList()
            val s = subEnts.filter { it.type == t }.toMutableList()
            // 1. cancel exact matches
            val sIt = s.iterator()
            val unmatchedS = ArrayList<Entity>()
            while (sIt.hasNext()) {
                val e = sIt.next()
                val m = r.firstOrNull { it.matches(e) }
                if (m != null) r.remove(m) else unmatchedS.add(e)
            }
            // 2. pair leftovers with the same label
            val remR = r.toMutableList(); val remS = unmatchedS.toMutableList()
            for (e in remS.toList()) {
                val m = remR.firstOrNull { it.label != null && it.label == e.label } ?: continue
                out.add(EntityDelta(t, DeltaKind.CHANGED, e.label, m.raw, e.raw, subLines.getOrNull(e.line)?.first?.takeIf { it >= 0 }))
                remR.remove(m); remS.remove(e)
            }
            // 3. pair remaining by position within the same type when counts match (unlabeled values)
            if (remR.size == remS.size && remR.isNotEmpty() && remR.all { it.label == null || remS.any { s2 -> s2.label == null } }) {
                for (i in remR.indices) out.add(EntityDelta(t, DeltaKind.CHANGED, remS[i].label ?: remR[i].label, remR[i].raw, remS[i].raw, subLines.getOrNull(remS[i].line)?.first?.takeIf { it >= 0 }))
            } else {
                for (e in remR) out.add(EntityDelta(t, DeltaKind.MISSING, e.label, e.raw, null, refLines.getOrNull(e.line)?.first?.takeIf { it >= 0 }))
                for (e in remS) out.add(EntityDelta(t, DeltaKind.ADDED, e.label, null, e.raw, subLines.getOrNull(e.line)?.first?.takeIf { it >= 0 }))
            }
        }
        return out
    }
}

object IssuerCheck {
    private fun typeFor(field: String): EntityType? {
        val f = field.lowercase()
        return when {
            Regex("date|dob|born|issued|expir|valid").containsMatchIn(f) -> EntityType.DATE
            Regex("amount|total|fee|balance|salary|price|sum|paid|payment").containsMatchIn(f) -> EntityType.AMOUNT
            Regex("number|\\bno\\b|ref|serial|policy|licen|passport|account|\\bid\\b|certificate|receipt|invoice").containsMatchIn(f) -> EntityType.DOC_NUMBER
            Regex("name|holder|student|employee|payee|owner|beneficiary|customer|patient").containsMatchIn(f) -> EntityType.NAME
            else -> null
        }
    }

    fun check(field: String, expected: String, docEntities: List<Entity>, normalizedFullText: String): IssuerFieldResult {
        val type = typeFor(field)
        if (type != null) {
            val want = EntityExtractor.extract(listOf(if (type == EntityType.NAME) "Name: $expected" else if (type == EntityType.DOC_NUMBER) "Ref: $expected" else expected)).firstOrNull { it.type == type }
            val candidates = docEntities.filter { it.type == type }
            if (want != null && candidates.any { it.matches(want) }) return IssuerFieldResult(field, expected, true, emptyList())
            if (type == EntityType.NAME || type == EntityType.DOC_NUMBER) {
                val needle = TextTokens.normalizeForSearch(expected)
                if (needle.isNotEmpty() && normalizedFullText.contains(needle)) return IssuerFieldResult(field, expected, true, emptyList())
            }
            return IssuerFieldResult(field, expected, false, candidates.map { it.raw }.distinct().take(4))
        }
        val needle = TextTokens.normalizeForSearch(expected)
        return IssuerFieldResult(field, expected, needle.isNotEmpty() && normalizedFullText.contains(needle), emptyList())
    }
}
