package com.docintegrity.forensics.pdf.content

/** One painted glyph with enough context to rebuild words: character, box, baseline, font and size. */
class PaintedGlyph(val ch: String, val rect: RectD, val baseline: Double, val face: String, val size: Float, val order: Int)

/**
 * Rebuilds words and lines from painted glyphs. Compared with a general-purpose text stripper this is simple on
 * purpose: it is deterministic, order-aware (glyphs hidden under later opaque shapes are dropped one-for-one, so text
 * typed over a cover-up is kept) and fully unit-testable.
 *
 * Known limits (also stated in docs/DETECTION.md): text drawn vertically or along rotated baselines is not
 * reassembled into words, and multi-column pages are read line-by-line across columns.
 */
object GlyphWords {
    /** A gap wider than this share of the font size starts a new word. */
    const val WORD_GAP_EM = 0.18

    fun build(pageIndex: Int, ops: List<PaintOp>): List<WordInfo> {
        val covered = ContentAnalyzer.coveredGlyphs(ops).toMutableList()
        val glyphs = ArrayList<PaintedGlyph>()
        for (t in ops.filterIsInstance<TextOp>()) {
            val face = t.face ?: "?"
            for ((gi, g) in t.glyphs.withIndex()) {
                val ci = covered.indexOfFirst { c -> c === g }
                if (ci >= 0) { covered.removeAt(ci); continue }
                glyphs.add(PaintedGlyph(g.ch, g.rect, g.baseline, face, t.fontSize, t.order * 100_000 + gi))
            }
        }
        if (glyphs.isEmpty()) return emptyList()
        // lines: cluster by baseline
        val lines = ArrayList<MutableList<PaintedGlyph>>()
        val lineBase = ArrayList<Double>()
        for (g in glyphs.sortedWith(compareBy({ it.baseline }, { it.rect.x0 }))) {
            val tol = maxOf(1.5, 0.4 * g.size)
            val idx = lineBase.indexOfFirst { Math.abs(it - g.baseline) <= tol }
            if (idx >= 0) lines[idx].add(g) else { lines.add(mutableListOf(g)); lineBase.add(g.baseline) }
        }
        val ordered = lines.indices.sortedBy { lineBase[it] }
        val out = ArrayList<WordInfo>()
        for ((lineNo, li) in ordered.withIndex()) {
            val gs = lines[li].sortedBy { it.rect.x0 }
            var cur = ArrayList<PaintedGlyph>()
            fun flush() {
                if (cur.isEmpty()) return
                val text = cur.joinToString("") { it.ch }
                if (text.isNotBlank()) {
                    var x0 = Double.MAX_VALUE; var y0 = Double.MAX_VALUE; var x1 = -Double.MAX_VALUE; var y1 = -Double.MAX_VALUE
                    for (g in cur) { x0 = minOf(x0, g.rect.x0); y0 = minOf(y0, g.rect.y0); x1 = maxOf(x1, g.rect.x1); y1 = maxOf(y1, g.rect.y1) }
                    out.add(WordInfo(pageIndex, lineNo, text.trim(), RectD(x0, y0, x1, y1), cur[0].size, cur.filter { it.ch.isNotBlank() }.map { CharFont(it.ch, it.face) }))
                }
                cur = ArrayList()
            }
            var prev: PaintedGlyph? = null
            for (g in gs) {
                if (g.ch.isBlank()) { flush(); prev = null; continue }
                if (prev != null && g.rect.x0 - prev.rect.x1 > WORD_GAP_EM * maxOf(prev.size, g.size)) flush()
                cur.add(g); prev = g
            }
            flush()
        }
        return out
    }
}
