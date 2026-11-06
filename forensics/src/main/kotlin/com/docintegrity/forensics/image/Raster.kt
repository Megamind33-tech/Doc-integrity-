package com.docintegrity.forensics.image

/** 8-bit grayscale raster, row-major. */
class GrayImage(val w: Int, val h: Int, val data: ByteArray) {
    init { require(data.size == w * h) { "bad gray buffer" } }
    operator fun get(x: Int, y: Int): Int = data[y * w + x].toInt() and 0xFF

    /** Area-average resample (box filter) to [nw] x [nh]. */
    fun resize(nw: Int, nh: Int): GrayImage {
        if (nw == w && nh == h) return this
        val out = ByteArray(nw * nh)
        for (y in 0 until nh) {
            val y0 = y * h / nh; val y1 = maxOf(y0 + 1, (y + 1) * h / nh)
            for (x in 0 until nw) {
                val x0 = x * w / nw; val x1 = maxOf(x0 + 1, (x + 1) * w / nw)
                var sum = 0L; var n = 0
                for (yy in y0 until y1) for (xx in x0 until x1) { sum += data[yy * w + xx].toInt() and 0xFF; n++ }
                out[y * nw + x] = (sum / n).toInt().toByte()
            }
        }
        return GrayImage(nw, nh, out)
    }
}

/** Decoded colour raster (ARGB, row-major), downscaled so that neither side exceeds the decoder's limit. */
class RasterImage(val w: Int, val h: Int, val argb: IntArray) {
    /** n x n colour thumbnail (area-averaged), 3 ints (R,G,B) per cell, for colour-difference checks. */
    fun thumbnail(n: Int = 32): IntArray {
        val out = IntArray(n * n * 3)
        for (y in 0 until n) {
            val y0 = y * h / n; val y1 = maxOf(y0 + 1, (y + 1) * h / n)
            for (x in 0 until n) {
                val x0 = x * w / n; val x1 = maxOf(x0 + 1, (x + 1) * w / n)
                var r = 0L; var g = 0L; var b = 0L; var c = 0
                for (yy in y0 until y1) for (xx in x0 until x1) { val p = argb[yy * w + xx]; r += (p shr 16) and 255; g += (p shr 8) and 255; b += p and 255; c++ }
                val i = (y * n + x) * 3
                out[i] = (r / c).toInt(); out[i + 1] = (g / c).toInt(); out[i + 2] = (b / c).toInt()
            }
        }
        return out
    }

    /** Rec.601 luma. */
    fun gray(): GrayImage {
        val g = ByteArray(w * h)
        for (i in g.indices) {
            val p = argb[i]
            g[i] = ((((p shr 16) and 255) * 299 + ((p shr 8) and 255) * 587 + (p and 255) * 114) / 1000).toByte()
        }
        return GrayImage(w, h, g)
    }
}

/**
 * Decodes encoded image bytes (JPEG, PNG, ...) into pixels. The Android implementation uses the platform decoder;
 * unit tests on the JVM install an ImageIO-based one. Analysis code depends only on this interface.
 */
interface ImageDecoder {
    fun decode(bytes: ByteArray, maxDim: Int = 2400): RasterImage?
}

object ImageDecoders {
    @Volatile var default: ImageDecoder? = null
    fun decode(bytes: ByteArray, maxDim: Int = 2400): RasterImage? = default?.decode(bytes, maxDim)
}

/** 64-bit difference hash (dHash) and Hamming distance. */
object PerceptualHash {
    fun dhash(img: GrayImage): Long {
        val s = img.resize(9, 8)
        var bits = 0L
        for (y in 0 until 8) for (x in 0 until 8) {
            bits = (bits shl 1) or (if (s[x, y] > s[x + 1, y]) 1L else 0L)
        }
        return bits
    }
    fun distance(a: Long, b: Long): Int = java.lang.Long.bitCount(a xor b)
}
