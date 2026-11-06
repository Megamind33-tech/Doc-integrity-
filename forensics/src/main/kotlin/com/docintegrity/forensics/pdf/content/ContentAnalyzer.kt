package com.docintegrity.forensics.pdf.content

import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.model.Region

/**
 * Indicators derived from paint order, fonts and positions. Operates on [DocumentContent] only (no PDF library),
 * so every rule is unit-testable with hand-built page models.
 *
 * Every rule here is a *prompt for review*. None is proof of editing: legitimate generators also produce
 * overlapping shapes, hidden OCR text and slightly misaligned runs.
 */
object ContentAnalyzer {

    /** Share of a text run's area that must lie under a later opaque object to count as "covered". */
    const val COVER_RATIO = 0.6
    /** A page image counts as a full-page scan when it spans at least this share of the page. */
    const val SCAN_PAGE_SHARE = 0.6
    const val MAX_REGIONS = 24
    private const val BASELINE_MIN = 0.25
    private const val BASELINE_MAX = 1.5
    private const val TINY_TEXT_PT = 1.5f

    private class CoveredText(val page: Int, val text: String, val rect: RectD, val by: PaintOp)

    private class BaselineLine(val page: Int, val minority: List<TextOp>, val majority: List<TextOp>, val delta: Double) {
        val minorityText get() = minority.sortedBy { it.rect.x0 }.joinToString("") { it.text }.trim()
        val majorityText get() = majority.sortedBy { it.rect.x0 }.joinToString("") { it.text }.trim()
        val rect get() = minority.map { it.rect }.reduce { a, b -> a.union(b) }
    }

    class Result(val findings: List<Finding>, val pageKinds: List<PageKind>)

    enum class PageKind(val label: String) { VECTOR("vector text"), RASTER("scanned image only"), MIXED("scanned image with text"), EMPTY("no text or images") }

    fun isScanLike(p: PageContent): Boolean {
        val pageArea = p.width * p.height
        return pageArea > 0 && p.images.any { !it.stencil && it.rect.area / pageArea >= SCAN_PAGE_SHARE }
    }

    fun analyze(doc: DocumentContent): Result {
        val findings = ArrayList<Finding>()
        val kinds = ArrayList<PageKind>()

        if (doc.errors.isNotEmpty() || doc.pages.any { it.errors.isNotEmpty() }) {
            findings.add(
                Finding(
                    id = "CONTENT_PARTIAL", area = Area.CONTENT, evidence = EvidenceClass.LIMITATION,
                    title = "Some page content could not be read",
                    detected = (doc.errors + doc.pages.flatMap { it.errors }).joinToString("; "),
                    establishes = "The affected pages were analysed only partly or not at all.",
                    unknown = "Anything the unreadable parts contain.",
                ),
            )
        }

        val covered = ArrayList<CoveredText>()
        val coveredRegions = ArrayList<Region>()
        val hidden = ArrayList<Triple<Int, TextOp, String>>()
        val overlays = ArrayList<Pair<Int, TextOp>>()
        val patches = ArrayList<Pair<Int, FillOp>>()
        val mixedWords = ArrayList<WordInfo>()
        val baseline = ArrayList<BaselineLine>()
        var ocrWords = 0

        for (p in doc.pages) {
            val scan = isScanLike(p)
            val hasText = p.words.isNotEmpty() || p.textOps.isNotEmpty()
            kinds.add(
                when {
                    scan && p.textOps.none { it.renderMode != 3 } -> if (hasText) PageKind.RASTER else PageKind.RASTER
                    scan -> PageKind.MIXED
                    hasText -> PageKind.VECTOR
                    p.images.isNotEmpty() -> PageKind.MIXED
                    else -> PageKind.EMPTY
                },
            )
            val ops = p.ops
            val bg = p.width * p.height

            // --- text covered by something painted later ---------------------------------------------------------
            // Coverage is judged per glyph, so that an opaque box over just a name or a digit inside a longer run counts.
            for (t in p.textOps) {
                if (t.renderMode == 3 || t.rect.area <= 0) continue
                val coverers = ops.filter { o ->
                    o.order > t.order && ((o is FillOp && o.opaque && o.pureRect) || (o is ImageOp && !o.stencil))
                }
                if (coverers.isEmpty()) continue
                val hit = HashSet<Int>()
                var first: PaintOp? = null
                val boxes = if (t.glyphs.isNotEmpty()) t.glyphs else listOf(GlyphBox(t.text, t.rect))
                for ((gi, g) in boxes.withIndex()) {
                    if (g.ch.isBlank() || g.rect.area <= 0) continue
                    val c = coverers.firstOrNull { it.rect.intersectionArea(g.rect) / g.rect.area >= COVER_RATIO }
                    if (c != null) { hit.add(gi); if (first == null) first = c }
                }
                if (hit.isNotEmpty()) {
                    val lo = hit.min(); val hi = hit.max()
                    val txt = (lo..hi).joinToString("") { boxes[it].ch }
                    val area = hit.map { boxes[it].rect }.reduce { x, y -> x.union(y) }
                    covered.add(CoveredText(p.index, txt, area, first!!))
                    if (coveredRegions.size < MAX_REGIONS) coveredRegions.add(area.toRegion(p.index, p.width, p.height, label = "covered: “${txt.trim().take(40)}”"))
                }
            }

            // --- hidden text -------------------------------------------------------------------------------------
            for (t in p.textOps) {
                if (t.text.isBlank()) continue
                val reason = when {
                    t.renderMode == 3 -> "invisible render mode"
                    t.fontSize in 0.01f..TINY_TEXT_PT -> "font size ${"%.1f".format(t.fontSize)} pt"
                    t.rgb == 0xFFFFFF && !underlaidByNonWhite(p, t) -> "white text on a white background"
                    else -> null
                }
                if (reason != null) {
                    if (reason == "invisible render mode" && scan) ocrWords += t.text.trim().split(Regex("\\s+")).size
                    else hidden.add(Triple(p.index, t, reason))
                }
            }

            // --- vector text / patches over a scan -----------------------------------------------------------------
            if (scan) {
                val scanOps = p.images.filter { !it.stencil && it.rect.area / bg >= SCAN_PAGE_SHARE }
                val lowest = scanOps.minOf { it.order }
                for (t in p.textOps) if (t.renderMode != 3 && t.order > lowest && t.text.isNotBlank() && t.rgb != 0xFFFFFF) overlays.add(p.index to t)
                for (f in ops.filterIsInstance<FillOp>()) if (f.order > lowest && f.opaque && f.pureRect && f.rect.area / bg < 0.5 && f.rect.area > 0 &&
                    scanOps.any { it.rect.intersectionArea(f.rect) / f.rect.area > 0.9 }
                ) patches.add(p.index to f)
            }

            // --- mixed fonts inside one word ---------------------------------------------------------------------
            for (w in p.words) {
                val faces = w.chars.filter { it.ch.isNotBlank() && it.ch.any { c -> c.isLetterOrDigit() } }.map { it.face }.toSet()
                if (faces.size >= 2 && w.text.length >= 3) mixedWords.add(w)
            }

            // --- baseline misalignment among same-size runs on one line ------------------------------------------------
            // Group runs into visual lines, then baseline clusters within each line. A line with two clusters whose
            // baselines differ by BASELINE_MIN..BASELINE_MAX pt is reported once, highlighting the smaller cluster.
            val runs = p.textOps.filter { it.renderMode != 3 && it.text.isNotBlank() && it.rect.h > 0 }
            val lines = ArrayList<MutableList<TextOp>>()
            for (r in runs.sortedBy { it.rect.y0 }) {
                val line = lines.firstOrNull { l ->
                    val ly0 = l.minOf { it.rect.y0 }; val ly1 = l.maxOf { it.rect.y1 }
                    minOf(ly1, r.rect.y1) - maxOf(ly0, r.rect.y0) >= 0.6 * minOf(ly1 - ly0, r.rect.h) && Math.abs(l[0].fontSize - r.fontSize) <= 0.05f
                }
                if (line != null) line.add(r) else lines.add(mutableListOf(r))
            }
            for (l in lines) {
                if (l.size < 2) continue
                val clusters = ArrayList<MutableList<TextOp>>()
                for (r in l.sortedBy { it.baselineY }) {
                    val c = clusters.firstOrNull { Math.abs(it[0].baselineY - r.baselineY) < 0.1 }
                    if (c != null) c.add(r) else clusters.add(mutableListOf(r))
                }
                if (clusters.size < 2) continue
                val d = Math.abs(clusters.first()[0].baselineY - clusters.last()[0].baselineY)
                if (d < BASELINE_MIN || d > BASELINE_MAX) continue
                val bySize = clusters.sortedBy { it.size }
                baseline.add(BaselineLine(p.index, bySize.first(), bySize.last(), d))
            }
        }

        // ================================================ findings ==================================================
        if (kinds.isNotEmpty()) {
            val counts = kinds.groupingBy { it }.eachCount()
            findings.add(
                Finding(
                    id = "CONTENT_PAGE_KINDS", area = Area.CONTENT, evidence = EvidenceClass.INFO,
                    title = "Page composition",
                    detected = counts.entries.joinToString("; ") { "${it.value} page(s): ${it.key.label}" } + ".",
                    establishes = "Shows whether each page is typeset text, a scanned picture, or a picture with text on it.",
                    unknown = "Whether a scan faithfully shows its source. Image-only pages cannot be text-compared without OCR, which this tool does not perform.",
                ),
            )
        }
        if (ocrWords > 0) {
            findings.add(
                Finding(
                    id = "CONTENT_OCR_LAYER", area = Area.CONTENT, evidence = EvidenceClass.INFO,
                    title = "Invisible text layer over scanned page(s)",
                    detected = "$ocrWords word(s) are present as invisible text on top of page image(s).",
                    establishes = "This is how OCR software makes scans searchable.",
                    unknown = "The hidden text is not checked against the image: OCR errors are normal, and a text layer that differs from what the picture shows cannot be detected without OCR.",
                ),
            )
        }
        if (covered.isNotEmpty()) {
            val whiteish = covered.count { c -> (c.by as? FillOp)?.rgb?.let { isNearWhite(it) } == true }
            findings.add(
                Finding(
                    id = "CONTENT_COVERED_TEXT", area = Area.CONTENT, evidence = EvidenceClass.INDICATOR,
                    title = "Text is covered by an opaque shape or image drawn after it",
                    detected = "${covered.size} piece(s) of text lie under a later opaque ${if (covered.any { it.by is ImageOp }) "rectangle/image" else "rectangle"}" +
                        (if (whiteish > 0) ", $whiteish of them under a white or near-white fill" else "") + ". Covered text: " +
                        covered.take(6).joinToString("; ") { "“${it.text.trim().take(40)}” (page ${it.page + 1})" } + if (covered.size > 6) "; …" else "",
                    establishes = "These runs are still stored in the page but are not visible to a reader, because something opaque was painted on top of them afterwards. The covered text can still be selected or extracted.",
                    unknown = "Redaction boxes, masks for layout and print-ready artwork cause the same pattern. Whether the covered text was meant to be hidden, and whether text was typed over the cover, needs human review of the highlighted regions.",
                    regions = coveredRegions,
                ),
            )
        }
        if (hidden.isNotEmpty()) {
            findings.add(
                Finding(
                    id = "CONTENT_HIDDEN_TEXT", area = Area.CONTENT, evidence = EvidenceClass.INDICATOR,
                    title = "Text that readers cannot see",
                    detected = "${hidden.size} run(s): " + hidden.take(6).joinToString("; ") { (pg, t, why) -> "“${t.text.trim().take(40)}” (page ${pg + 1}, $why)" } + if (hidden.size > 6) "; …" else "",
                    establishes = "The file contains text with no visible rendering (invisible mode, microscopic size or white on white). Text extraction and search will still return it.",
                    unknown = "Hidden text is used for accessibility, searchable scans, form data and also to plant text. Its purpose cannot be told from the file.",
                    regions = hidden.take(MAX_REGIONS).map { (pg, t, why) ->
                        val p = doc.pages[pg]; t.rect.toRegion(pg, p.width, p.height, label = "hidden ($why): “${t.text.trim().take(30)}”")
                    },
                ),
            )
        }
        if (overlays.isNotEmpty() || patches.isNotEmpty()) {
            findings.add(
                Finding(
                    id = "CONTENT_SCAN_OVERLAY", area = Area.IMAGE, evidence = EvidenceClass.INDICATOR,
                    title = "Visible text or opaque patches drawn over a scanned page",
                    detected = buildList {
                        if (overlays.isNotEmpty()) add("${overlays.size} visible text run(s) on top of a page image: " + overlays.take(5).joinToString("; ") { "“${it.second.text.trim().take(40)}” (page ${it.first + 1})" })
                        if (patches.isNotEmpty()) add("${patches.size} opaque rectangle(s) painted over the scan")
                    }.joinToString(". "),
                    establishes = "These items were added on top of the scanned picture as separate page content. A plain scan or an OCR text layer does not look like this.",
                    unknown = "Page numbers, Bates stamps, received stamps and signature fields are added over scans legitimately. Deliberate corrections of scanned content look the same. Review the highlighted regions.",
                    regions = (overlays.take(MAX_REGIONS).map { (pg, t) -> val p = doc.pages[pg]; t.rect.toRegion(pg, p.width, p.height, label = "text over scan: “${t.text.trim().take(30)}”") } +
                        patches.take(MAX_REGIONS).map { (pg, f) -> val p = doc.pages[pg]; f.rect.toRegion(pg, p.width, p.height, label = "opaque patch over scan") }).take(MAX_REGIONS),
                ),
            )
        }
        if (mixedWords.isNotEmpty()) {
            val withDigits = mixedWords.filter { w -> w.text.any { it.isDigit() } }
            findings.add(
                Finding(
                    id = "CONTENT_MIXED_FONT_WORD", area = Area.FONTS,
                    evidence = if (withDigits.isNotEmpty()) EvidenceClass.INDICATOR else EvidenceClass.INFO,
                    title = "Single words set in more than one font",
                    detected = "${mixedWords.size} word(s): " + mixedWords.take(6).joinToString("; ") { w -> "“${w.text}” (${w.faces.joinToString(" + ")})" } + if (mixedWords.size > 6) "; …" else "",
                    establishes = "Within one word, some characters use a different typeface from the rest." +
                        if (withDigits.isNotEmpty()) " This includes words with digits, where a single changed character in an amount or number can show up this way." else "",
                    unknown = "Fallback fonts for special glyphs, drop caps and mixed styling cause it legitimately. Whether characters were substituted by an editor cannot be told from the file.",
                    regions = mixedWords.take(MAX_REGIONS).map { w -> val p = doc.pages[w.page]; w.rect.toRegion(w.page, p.width, p.height, label = "mixed fonts: “${w.text}”") },
                ),
            )
        }
        if (baseline.isNotEmpty()) {
            findings.add(
                Finding(
                    id = "CONTENT_BASELINE_OFFSET", area = Area.CONTENT, evidence = EvidenceClass.INDICATOR,
                    title = "Part of a line of same-size text sits at a slightly different height",
                    detected = "${baseline.size} line(s) where some text shares a line and font size with other text but its baseline is ${"%.2f".format(BASELINE_MIN)}–${"%.1f".format(BASELINE_MAX)} pt off: " +
                        baseline.take(4).joinToString("; ") { b -> "“${b.minorityText.take(30)}” vs “${b.majorityText.take(30)}” (page ${b.page + 1}, Δ${"%.2f".format(b.delta)} pt)" },
                    establishes = "Typeset text that is laid out together normally shares one baseline. A run placed separately, by hand or by an editor, often lands a fraction of a point off.",
                    unknown = "Superscripts, inline images, some layout engines and rounding in converters produce small offsets too, and a careful editor can align inserted text exactly, so the absence of this indicator proves nothing. It is a prompt to look at the line.",
                    regions = baseline.take(MAX_REGIONS).map { b -> val p = doc.pages[b.page]; b.rect.toRegion(b.page, p.width, p.height, label = "baseline offset: “${b.minorityText.take(30)}”") },
                ),
            )
        }
        return Result(findings, kinds)
    }

    private fun isNearWhite(rgb: Int): Boolean = ((rgb shr 16) and 255) > 240 && ((rgb shr 8) and 255) > 240 && (rgb and 255) > 240

    /** True if a non-white opaque shape or image lies beneath [t] (so white text may be a deliberate knock-out). */
    private fun underlaidByNonWhite(p: PageContent, t: TextOp): Boolean = p.ops.any { o ->
        o.order < t.order && o.rect.intersectionArea(t.rect) / maxOf(t.rect.area, 1e-6) > 0.5 &&
            ((o is FillOp && o.opaque && o.rgb != null && !isNearWhite(o.rgb)) || (o is ImageOp && !o.stencil))
    }
}
