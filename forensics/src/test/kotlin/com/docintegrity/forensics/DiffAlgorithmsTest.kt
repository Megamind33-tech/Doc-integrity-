package com.docintegrity.forensics

import com.docintegrity.forensics.compare.*
import com.docintegrity.forensics.image.GrayImage
import com.docintegrity.forensics.image.PerceptualHash
import com.docintegrity.forensics.image.RasterImage
import org.junit.Assert.*
import org.junit.Test
import java.util.Random

class DiffAlgorithmsTest {

    // ---- Myers ---------------------------------------------------------------------------------------------

    private fun apply(a: List<String>, b: List<String>, edits: List<Edit>): List<String> {
        val out = ArrayList<String>()
        for (e in edits) when (e) {
            is Edit.Equal -> { assertEquals(a.subList(e.aFrom, e.aTo), b.subList(e.bFrom, e.bTo)); out.addAll(b.subList(e.bFrom, e.bTo)) }
            is Edit.Change -> out.addAll(b.subList(e.bFrom, e.bTo))
        }
        return out
    }

    @Test fun editScriptReproducesTargetForRandomSequences() {
        val rnd = Random(42)
        repeat(300) {
            val n = rnd.nextInt(40); val m = rnd.nextInt(40)
            val alpha = listOf("a", "b", "c", "d")
            val a = List(n) { alpha[rnd.nextInt(alpha.size)] }
            val b = List(m) { alpha[rnd.nextInt(alpha.size)] }
            val r = MyersDiff.diff(a, b)
            assertEquals("a=$a b=$b", b, apply(a, b, r.edits))
            // edits cover both sequences completely and in order
            var ai = 0; var bi = 0
            for (e in r.edits) when (e) {
                is Edit.Equal -> { assertEquals(ai, e.aFrom); assertEquals(bi, e.bFrom); ai = e.aTo; bi = e.bTo }
                is Edit.Change -> { assertEquals(ai, e.aFrom); assertEquals(bi, e.bFrom); ai = e.aTo; bi = e.bTo }
            }
            assertEquals(a.size, ai); assertEquals(b.size, bi)
        }
    }

    @Test fun identicalSequencesGiveNoChange() {
        val a = "the quick brown fox".split(" ")
        val r = MyersDiff.diff(a, a)
        assertTrue(r.edits.all { it is Edit.Equal })
    }

    @Test fun singleWordReplacementIsOneMinimalChange() {
        val a = "received from John Mwansa on 12 March".split(" ")
        val b = "received from Joseph Mwanza on 12 March".split(" ")
        val ch = MyersDiff.diff(a, b).edits.filterIsInstance<Edit.Change>()
        assertEquals(1, ch.size)
        assertEquals(listOf("John", "Mwansa"), a.subList(ch[0].aFrom, ch[0].aTo))
        assertEquals(listOf("Joseph", "Mwanza"), b.subList(ch[0].bFrom, ch[0].bTo))
    }

    @Test fun hugeDifferenceIsReportedAsTruncatedNotHung() {
        val a = List(6000) { "a$it" }; val b = List(6000) { "b$it" }
        val r = MyersDiff.diff(a, b, maxD = 500)
        assertTrue(r.truncated)
    }

    // ---- visual diff ----------------------------------------------------------------------------------------

    private fun page(w: Int = 800, h: Int = 1100, draw: (ByteArray) -> Unit = {}): GrayImage {
        val d = ByteArray(w * h) { 255.toByte() }
        // text-like dark bars
        for (row in 0 until 20) for (y in 100 + row * 40 until 112 + row * 40) for (x in 80 until 600) if ((x / 7) % 3 != 0) d[y * w + x] = 20
        draw(d)
        return GrayImage(w, h, d)
    }
    private fun fill(d: ByteArray, w: Int, x0: Int, y0: Int, x1: Int, y1: Int, v: Int) { for (y in y0 until y1) for (x in x0 until x1) d[y * w + x] = v.toByte() }

    @Test fun identicalPagesHaveNoRegions() {
        val r = VisualDiff.compare(page(), page())
        assertEquals(0, r.regions.size)
    }

    @Test fun smallLocalEditIsFoundWhereItHappened() {
        val a = page()
        val b = page { fill(it, 800, 300, 500, 380, 514, 20) }   // an added dark bar (e.g. new digits)
        val r = VisualDiff.compare(a, b)
        assertEquals(1, r.regions.size)
        val reg = r.regions[0]
        assertTrue(reg.x0 <= 300 && reg.x1 >= 380 && reg.y0 <= 500 && reg.y1 >= 514)
        assertTrue("region should be small, not the page", reg.widthPx < 160 && reg.heightPx < 60)
    }

    @Test fun smallTranslationIsAlignedAway() {
        val a = page()
        val d = ByteArray(800 * 1100) { 255.toByte() }
        val src = a.data
        for (y in 0 until 1100) for (x in 0 until 800) { val sx = x - 6; val sy = y - 4; if (sx in 0 until 800 && sy in 0 until 1100) d[y * 800 + x] = src[sy * 800 + sx] }
        val r = VisualDiff.compare(a, GrayImage(800, 1100, d))
        assertEquals("scan offset must not create differences", 0, r.regions.size)
    }

    @Test fun compressionStyleNoiseIsSuppressed() {
        val rnd = Random(1)
        val a = page()
        val b = GrayImage(800, 1100, ByteArray(a.data.size) { i -> ((a.data[i].toInt() and 255) + rnd.nextInt(21) - 10).coerceIn(0, 255).toByte() })
        assertEquals(0, VisualDiff.compare(a, b).regions.size)
    }

    @Test fun differentAspectRatioIsFlaggedAsApproximate() {
        val r = VisualDiff.compare(page(800, 1100), page(800, 900))
        assertTrue(r.aspectMismatch)
    }

    // ---- image classification ------------------------------------------------------------------------------------

    /** A synthetic picture made of seeded blobs: different seeds give genuinely different compositions. */
    private fun photo(seed: Int, w: Int = 200, h: Int = 240, tweak: (Int, Int, Int) -> Int = { _, _, p -> p }): RasterImage {
        val rnd = Random(seed.toLong())
        val blobs = List(7) { intArrayOf(rnd.nextInt(w), rnd.nextInt(h), 20 + rnd.nextInt(35), 40 + rnd.nextInt(180)) }
        val px = IntArray(w * h)
        for (y in 0 until h) for (x in 0 until w) {
            var g = 70 + y * 60 / h
            for (b in blobs) if ((x - b[0]) * (x - b[0]) + (y - b[1]) * (y - b[1]) < b[2] * b[2]) g = b[3]
            val base = (0xFF shl 24) or (g.coerceIn(0, 255) shl 16) or ((g * 3 / 4).coerceIn(0, 255) shl 8) or (g / 2).coerceIn(0, 255)
            px[y * w + x] = tweak(x, y, base)
        }
        return RasterImage(w, h, px)
    }

    private fun classify(a: RasterImage, b: RasterImage, sameBytes: Boolean = false): ImageVerdict {
        val d = PerceptualHash.distance(PerceptualHash.dhash(a.gray()), PerceptualHash.dhash(b.gray()))
        return ImageCompare.classify(sameBytes, d, a, b)
    }

    @Test fun imageClassification() {
        val a = photo(1)
        assertEquals(ImageVerdict.IDENTICAL, classify(a, a, sameBytes = true))
        val rnd = Random(3)
        val noisy = photo(1) { _, _, p -> val n = rnd.nextInt(7) - 3; (0xFF shl 24) or (((p shr 16 and 255) + n).coerceIn(0, 255) shl 16) or (((p shr 8 and 255) + n).coerceIn(0, 255) shl 8) or ((p and 255) + n).coerceIn(0, 255) }
        assertEquals("re-encoding noise = same picture", ImageVerdict.SAME_PICTURE, classify(a, noisy))
        val patched = photo(1) { x, y, p -> if (x in 90..130 && y in 150..170) 0xFF000000.toInt() else p }
        assertEquals("a local patch = local difference", ImageVerdict.LOCALLY_DIFFERENT, classify(a, patched))
        assertEquals("a different composition = different picture", ImageVerdict.DIFFERENT, classify(a, photo(99)))
        val inverted = photo(1) { _, _, p -> (0xFF shl 24) or (0xFFFFFF - (p and 0xFFFFFF)) }
        assertEquals("inverted colours are never 'same'", ImageVerdict.DIFFERENT, classify(a, inverted))
    }
}
