package com.docintegrity.forensics.compare

import com.docintegrity.forensics.image.GrayImage

/** A region that differs, in the coordinate space of the compared raster (and normalised 0..1). */
class DiffRegion(val x0: Int, val y0: Int, val x1: Int, val y1: Int, val changedPixelShare: Double, private val w: Int, private val h: Int) {
    val nx0 get() = x0.toDouble() / w
    val ny0 get() = y0.toDouble() / h
    val nx1 get() = x1.toDouble() / w
    val ny1 get() = y1.toDouble() / h
    val widthPx get() = x1 - x0
    val heightPx get() = y1 - y0
}

class VisualDiffResult(
    val width: Int,
    val height: Int,
    val regions: List<DiffRegion>,
    /** Share of all pixels classified as changed after noise suppression. A measurement, not a similarity score. */
    val changedPixelShare: Double,
    val alignmentShiftX: Int,
    val alignmentShiftY: Int,
    /** True when the two pages have noticeably different aspect ratios, so the comparison is only approximate. */
    val aspectMismatch: Boolean,
)

/**
 * Traditional (non-ML) rendered-page comparison:
 *   1. bring both pages to one size,
 *   2. search a small translation to cancel scan/placement offset,
 *   3. blur slightly and threshold the absolute difference (suppresses JPEG and anti-aliasing noise),
 *   4. mark grid cells with enough changed pixels and merge neighbouring cells into regions.
 * Thresholds are fixed and documented; the result is a set of regions for HUMAN review.
 */
object VisualDiff {
    const val TARGET_WIDTH = 800
    const val PIXEL_THRESHOLD = 48
    const val CELL = 12
    const val CELL_CHANGED_SHARE = 0.06
    const val MAX_SHIFT = 10

    fun compare(reference: GrayImage, submitted: GrayImage): VisualDiffResult {
        val aspectRef = reference.h.toDouble() / reference.w
        val aspectSub = submitted.h.toDouble() / submitted.w
        val aspectMismatch = Math.abs(aspectRef - aspectSub) / aspectRef > 0.02
        val w = TARGET_WIDTH
        val h = maxOf(1, (w * aspectRef).toInt())
        val a = blur(reference.resize(w, h))
        val b = blur(submitted.resize(w, h))
        val (dx, dy) = bestShift(a, b)

        val diff = BooleanArray(w * h)
        var changed = 0
        for (y in 0 until h) for (x in 0 until w) {
            val sx = x + dx; val sy = y + dy
            val bv = if (sx in 0 until w && sy in 0 until h) b[sx, sy] else 255
            if (Math.abs(a[x, y] - bv) > PIXEL_THRESHOLD) { diff[y * w + x] = true; changed++ }
        }
        // grid cells
        val cw = (w + CELL - 1) / CELL; val ch = (h + CELL - 1) / CELL
        val hot = BooleanArray(cw * ch)
        for (cy in 0 until ch) for (cx in 0 until cw) {
            var n = 0; var tot = 0
            for (y in cy * CELL until minOf(h, (cy + 1) * CELL)) for (x in cx * CELL until minOf(w, (cx + 1) * CELL)) { tot++; if (diff[y * w + x]) n++ }
            if (tot > 0 && n.toDouble() / tot >= CELL_CHANGED_SHARE) hot[cy * cw + cx] = true
        }
        // connected components (8-neighbourhood) over hot cells
        val seen = BooleanArray(hot.size)
        val regions = ArrayList<DiffRegion>()
        for (start in hot.indices) {
            if (!hot[start] || seen[start]) continue
            val stack = ArrayDeque<Int>(); stack.add(start); seen[start] = true
            var minX = Int.MAX_VALUE; var minY = Int.MAX_VALUE; var maxX = -1; var maxY = -1; var px = 0
            while (stack.isNotEmpty()) {
                val c = stack.removeLast(); val cx = c % cw; val cy = c / cw
                minX = minOf(minX, cx); maxX = maxOf(maxX, cx); minY = minOf(minY, cy); maxY = maxOf(maxY, cy)
                for (ny in cy - 1..cy + 1) for (nx in cx - 1..cx + 1) {
                    if (nx !in 0 until cw || ny !in 0 until ch) continue
                    val ni = ny * cw + nx
                    if (hot[ni] && !seen[ni]) { seen[ni] = true; stack.add(ni) }
                }
            }
            val rx0 = minX * CELL; val ry0 = minY * CELL; val rx1 = minOf(w, (maxX + 1) * CELL); val ry1 = minOf(h, (maxY + 1) * CELL)
            for (y in ry0 until ry1) for (x in rx0 until rx1) if (diff[y * w + x]) px++
            regions.add(DiffRegion(rx0, ry0, rx1, ry1, px.toDouble() / ((rx1 - rx0) * (ry1 - ry0)), w, h))
        }
        return VisualDiffResult(w, h, regions.sortedBy { it.y0 * 10000 + it.x0 }, changed.toDouble() / (w * h), dx, dy, aspectMismatch)
    }

    private fun blur(g: GrayImage): GrayImage {
        val out = ByteArray(g.data.size)
        for (y in 0 until g.h) for (x in 0 until g.w) {
            var s = 0; var n = 0
            for (yy in maxOf(0, y - 1)..minOf(g.h - 1, y + 1)) for (xx in maxOf(0, x - 1)..minOf(g.w - 1, x + 1)) { s += g[xx, yy]; n++ }
            out[y * g.w + x] = (s / n).toByte()
        }
        return GrayImage(g.w, g.h, out)
    }

    /**
     * Translation search: a coarse pass on a 1/4-scale copy, then a full-resolution refinement around the coarse best,
     * so that a scan offset of any whole number of pixels (up to MAX_SHIFT) is cancelled before differencing.
     * Returns the shift to apply to [b].
     */
    private fun bestShift(a: GrayImage, b: GrayImage): Pair<Int, Int> {
        val s = 4
        val sa = a.resize(a.w / s, a.h / s); val sb = b.resize(b.w / s, b.h / s)
        var best = Long.MAX_VALUE; var bx = 0; var by = 0
        val r = MAX_SHIFT / s + 1
        for (dy in -r..r) for (dx in -r..r) {
            val sum = sad(sa, sb, dx, dy, 2)
            if (sum < best) { best = sum; bx = dx; by = dy }
        }
        var fx = bx * s; var fy = by * s
        var fbest = Long.MAX_VALUE; var rx = fx; var ry = fy
        for (dy in fy - s + 1..fy + s - 1) for (dx in fx - s + 1..fx + s - 1) {
            if (Math.abs(dx) > MAX_SHIFT || Math.abs(dy) > MAX_SHIFT) continue
            val sum = sad(a, b, dx, dy, 2)
            if (sum < fbest) { fbest = sum; rx = dx; ry = dy }
        }
        return rx to ry
    }

    private fun sad(a: GrayImage, b: GrayImage, dx: Int, dy: Int, step: Int): Long {
        var sum = 0L
        var y = 0
        while (y < a.h) {
            var x = 0
            while (x < a.w) {
                val xx = x + dx; val yy = y + dy
                val v = if (xx in 0 until b.w && yy in 0 until b.h) b[xx, yy] else 255
                sum += Math.abs(a[x, y] - v)
                x += step
            }
            y += step
        }
        return sum
    }
}
