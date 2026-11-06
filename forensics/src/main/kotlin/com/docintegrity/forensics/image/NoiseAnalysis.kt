package com.docintegrity.forensics.image

/** A rectangle in image pixels. */
class PxRect(val x0: Int, val y0: Int, val x1: Int, val y1: Int) {
    val w get() = x1 - x0
    val h get() = y1 - y0
}

class NoiseResult(
    val informative: Boolean,
    /** Median per-block noise estimate (grey levels) over the whole page. */
    val medianSigma: Double,
    val lowNoiseRegions: List<PxRect>,
    val note: String,
    /** Per-block noise estimates (row-major, [blocksX] wide); empty when not computed. Exposed for review and tests. */
    val sigma: DoubleArray = DoubleArray(0),
    val blocksX: Int = 0,
)

/**
 * Local noise-consistency analysis. Scanner and sensor grain is present everywhere on a genuine scan; content that
 * was painted or pasted digitally is often noise-free. Per 32x32 block the noise is estimated robustly (MAD of the
 * residual after a 3x3 mean filter), so a few edge pixels of text do not dominate.
 *
 * Deliberately conservative:
 *  - only runs where the page as a whole HAS measurable grain (median >= MIN_MEDIAN); denoised or binarised scans
 *    are reported as "not informative", never as clean;
 *  - a candidate must be a compact group of blocks (>= MIN_BLOCKS) that does not touch the page border (large flat
 *    margins are normal) and is surrounded by blocks that do have grain.
 * A forger who adds matching noise defeats this check, and so does scanner software that flattens the background.
 */
object NoiseAnalysis {
    const val BLOCK = 16
    const val MIN_MEDIAN = 0.9
    const val LOW_RATIO = 0.30
    const val MIN_BLOCKS = 6
    const val ENCLOSED_SHARE = 0.6

    fun analyze(g: GrayImage): NoiseResult {
        val bx = g.w / BLOCK; val by = g.h / BLOCK
        if (bx < 6 || by < 6) return NoiseResult(false, 0.0, emptyList(), "image too small for a block analysis")
        val sigma = DoubleArray(bx * by)
        val vals = DoubleArray(BLOCK * BLOCK)
        for (j in 0 until by) for (i in 0 until bx) {
            var n = 0
            for (y in j * BLOCK until (j + 1) * BLOCK) for (x in i * BLOCK until (i + 1) * BLOCK) {
                if (x < 1 || y < 1 || x >= g.w - 1 || y >= g.h - 1) { vals[n++] = 0.0; continue }
                var s = 0
                for (yy in y - 1..y + 1) for (xx in x - 1..x + 1) s += g[xx, yy]
                vals[n++] = g[x, y] - s / 9.0
            }
            val med = median(vals, n)
            for (k in 0 until n) vals[k] = Math.abs(vals[k] - med)
            sigma[j * bx + i] = 1.4826 * median(vals, n)
        }
        val med = median(sigma.copyOf(), sigma.size)
        if (med < MIN_MEDIAN) return NoiseResult(false, med, emptyList(), "the page shows almost no grain (median noise ${"%.2f".format(med)}); it looks denoised, binarised or heavily compressed, so noise cannot show where content was added")
        val low = BooleanArray(sigma.size) { sigma[it] < LOW_RATIO * med }
        val seen = BooleanArray(low.size)
        val regions = ArrayList<PxRect>()
        for (s in low.indices) {
            if (!low[s] || seen[s]) continue
            val comp = ArrayList<Int>(); val st = ArrayDeque<Int>(); st.add(s); seen[s] = true
            var touches = false
            while (st.isNotEmpty()) {
                val c = st.removeLast(); comp.add(c)
                val cx = c % bx; val cy = c / bx
                if (cx == 0 || cy == 0 || cx == bx - 1 || cy == by - 1) touches = true
                for (ny in cy - 1..cy + 1) for (nx in cx - 1..cx + 1) {
                    if (nx !in 0 until bx || ny !in 0 until by) continue
                    val ni = ny * bx + nx
                    if (low[ni] && !seen[ni]) { seen[ni] = true; st.add(ni) }
                }
            }
            if (comp.size < MIN_BLOCKS || touches) continue
            // enclosed: most blocks around the group have normal grain
            val inSet = comp.toHashSet(); var border = 0; var normal = 0
            for (c in comp) {
                val cx = c % bx; val cy = c / bx
                for ((dx, dy) in listOf(1 to 0, -1 to 0, 0 to 1, 0 to -1)) {
                    val nx = cx + dx; val ny = cy + dy
                    if (nx !in 0 until bx || ny !in 0 until by) continue
                    val ni = ny * bx + nx
                    if (ni in inSet) continue
                    border++; if (!low[ni]) normal++
                }
            }
            if (border == 0 || normal.toDouble() / border < ENCLOSED_SHARE) continue
            val xs = comp.map { it % bx }; val ys = comp.map { it / bx }
            regions.add(PxRect(xs.min() * BLOCK, ys.min() * BLOCK, (xs.max() + 1) * BLOCK, (ys.max() + 1) * BLOCK))
        }
        return NoiseResult(true, med, regions, note = if (regions.isEmpty()) "grain is consistent across the page (median ${"%.2f".format(med)})" else "${regions.size} compact region(s) have almost no grain although the page does (median ${"%.2f".format(med)})", sigma = sigma, blocksX = bx)
    }

    private fun median(a: DoubleArray, n: Int): Double {
        java.util.Arrays.sort(a, 0, n)
        return if (n == 0) 0.0 else if (n % 2 == 1) a[n / 2] else (a[n / 2 - 1] + a[n / 2]) / 2
    }
}
