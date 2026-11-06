package com.docintegrity.forensics.image

class JpegInfo(
    val width: Int,
    val height: Int,
    val progressive: Boolean,
    val components: Int,
    /** e.g. "4:2:0"; null if not a 3-component image. */
    val subsampling: String?,
    /** Quantisation tables in natural (not zig-zag) order, by table id. */
    val quantTables: Map<Int, IntArray>,
    /** Quality implied by the luminance table if it equals an IJG-standard table scaled to that quality. */
    val ijgQuality: Int?,
    val appMarkers: List<String>,
    val exifSoftware: String?,
    val exifDateTime: String?,
    val exifDateTimeOriginal: String?,
    val exifMake: String?,
    val exifModel: String?,
    val comments: List<String>,
    val photoshopResources: Boolean,
    val adobeMarker: Boolean,
    /** Bytes after the end-of-image marker (beyond trailing whitespace/zero padding). */
    val trailingBytes: Int,
    val scans: Int,
    val restartInterval: Int,
)

/**
 * Reads the JPEG container structure without decoding pixels. Everything reported is a fact about how the file was
 * written (tables, markers, metadata); what it implies about editing is stated by the caller, with caution.
 */
object JpegInspector {
    private val ZIGZAG = intArrayOf(
        0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
        35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
    )
    private val STD_LUMA = intArrayOf(
        16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
        18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
    )

    fun looksLikeJpeg(b: ByteArray) = b.size > 4 && (b[0].toInt() and 0xFF) == 0xFF && (b[1].toInt() and 0xFF) == 0xD8

    fun inspect(b: ByteArray): JpegInfo? {
        if (!looksLikeJpeg(b)) return null
        var p = 2
        var w = 0; var h = 0; var prog = false; var comps = 0; var sub: String? = null
        val qt = LinkedHashMap<Int, IntArray>()
        val apps = ArrayList<String>(); val comments = ArrayList<String>()
        var exif: Map<String, String> = emptyMap()
        var photoshop = false; var adobe = false; var scans = 0; var dri = 0
        var eoi = -1
        while (p + 1 < b.size) {
            if ((b[p].toInt() and 0xFF) != 0xFF) { p++; continue }
            var m = b[p + 1].toInt() and 0xFF
            if (m == 0xFF) { p++; continue }       // fill byte
            if (m == 0x00 || (m in 0xD0..0xD7) || m == 0x01) { p += 2; continue }
            if (m == 0xD8) { p += 2; continue }
            if (m == 0xD9) { eoi = p + 2; break }
            if (p + 3 >= b.size) break
            val len = ((b[p + 2].toInt() and 0xFF) shl 8) or (b[p + 3].toInt() and 0xFF)
            val segStart = p + 4; val segEnd = minOf(b.size, p + 2 + len)
            if (len < 2) { p += 2; continue }
            when (m) {
                0xDB -> { // DQT
                    var q = segStart
                    while (q < segEnd) {
                        val pq = (b[q].toInt() and 0xFF) shr 4; val tq = b[q].toInt() and 0x0F; q++
                        val t = IntArray(64)
                        for (i in 0 until 64) {
                            if (q >= segEnd) break
                            val v = if (pq == 0) (b[q++].toInt() and 0xFF) else { val x = ((b[q].toInt() and 0xFF) shl 8) or (b[q + 1].toInt() and 0xFF); q += 2; x }
                            t[ZIGZAG[i]] = v
                        }
                        qt[tq] = t
                    }
                }
                0xC0, 0xC1, 0xC2 -> {
                    prog = m == 0xC2
                    h = ((b[segStart + 1].toInt() and 0xFF) shl 8) or (b[segStart + 2].toInt() and 0xFF)
                    w = ((b[segStart + 3].toInt() and 0xFF) shl 8) or (b[segStart + 4].toInt() and 0xFF)
                    comps = b[segStart + 5].toInt() and 0xFF
                    if (comps == 3) {
                        val hv = IntArray(3) { b[segStart + 6 + it * 3 + 1].toInt() and 0xFF }
                        sub = when (hv[0]) { 0x22 -> "4:2:0"; 0x21 -> "4:2:2"; 0x11 -> "4:4:4"; 0x12 -> "4:4:0"; 0x41 -> "4:1:1"; else -> "other" }
                        if (hv[1] != 0x11 || hv[2] != 0x11) sub = (sub ?: "") + " (unusual chroma sampling)"
                    }
                }
                0xDD -> dri = ((b[segStart].toInt() and 0xFF) shl 8) or (b[segStart + 1].toInt() and 0xFF)
                0xFE -> comments.add(String(b, segStart, segEnd - segStart, Charsets.ISO_8859_1).trim { it <= ' ' || it == '\u0000' })
                in 0xE0..0xEF -> {
                    val id = readCString(b, segStart, segEnd)
                    apps.add("APP${m - 0xE0}${if (id.isNotEmpty()) " ($id)" else ""}")
                    if (m == 0xE1 && id.startsWith("Exif")) exif = parseExif(b, segStart + 6, segEnd)
                    if (m == 0xED && id.startsWith("Photoshop")) photoshop = true
                    if (m == 0xEE && id.startsWith("Adobe")) adobe = true
                }
                0xDA -> { // SOS: skip header, then entropy-coded data until the next real marker
                    scans++
                    var q = segEnd
                    while (q + 1 < b.size) {
                        if ((b[q].toInt() and 0xFF) == 0xFF) {
                            val n = b[q + 1].toInt() and 0xFF
                            if (n != 0x00 && n !in 0xD0..0xD7 && n != 0xFF) break
                            q += 2
                        } else q++
                    }
                    p = q; continue
                }
            }
            p = segEnd
        }
        var trailing = 0
        if (eoi >= 0) for (i in eoi until b.size) if (b[i].toInt() != 0 && b[i].toInt() != 10 && b[i].toInt() != 13 && b[i].toInt() != 32) trailing++
        val luma = qt[0]
        return JpegInfo(
            w, h, prog, comps, sub, qt, luma?.let { ijgQuality(it) }, apps,
            exif["Software"], exif["DateTime"], exif["DateTimeOriginal"], exif["Make"], exif["Model"],
            comments.filter { it.isNotEmpty() }, photoshop, adobe, trailing, scans, dri,
        )
    }

    /** Returns q (1..100) if [luma] equals the IJG standard luminance table scaled to q, else null. */
    fun ijgQuality(luma: IntArray): Int? {
        var best = -1; var bestD = Int.MAX_VALUE
        for (q in 1..100) {
            val scale = if (q < 50) 5000 / q else 200 - 2 * q
            var d = 0
            for (i in 0 until 64) d += Math.abs(luma[i] - ((STD_LUMA[i] * scale + 50) / 100).coerceIn(1, 255))
            if (d < bestD) { bestD = d; best = q }
        }
        return if (bestD <= 4) best else null
    }

    private fun readCString(b: ByteArray, from: Int, to: Int): String {
        val sb = StringBuilder()
        var i = from
        while (i < to && i < from + 40 && b[i].toInt() != 0) { sb.append((b[i].toInt() and 0xFF).toChar()); i++ }
        return sb.toString()
    }

    /** Minimal TIFF/Exif reader: ASCII tags of IFD0 and the Exif sub-IFD. */
    private fun parseExif(b: ByteArray, tiff: Int, end: Int): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        try {
            if (tiff + 8 > end) return out
            val le = b[tiff].toInt() == 'I'.code
            fun u16(o: Int) = if (le) (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) else ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
            fun u32(o: Int) = if (le) (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) or ((b[o + 2].toInt() and 0xFF) shl 16) or ((b[o + 3].toInt() and 0xFF) shl 24)
            else ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)
            fun ifd(off: Int, exifSub: Boolean) {
                var o = tiff + off
                if (o + 2 > end) return
                val n = u16(o); o += 2
                for (i in 0 until minOf(n, 64)) {
                    val e = o + i * 12
                    if (e + 12 > end) break
                    val tag = u16(e); val type = u16(e + 2); val count = u32(e + 4)
                    if (type == 2 && count in 1..200) {
                        val vo = if (count <= 4) e + 8 else tiff + u32(e + 8)
                        if (vo + count <= end) {
                            val s = String(b, vo, count - 1, Charsets.ISO_8859_1).trim { it <= ' ' }
                            when (tag) { 0x010F -> out["Make"] = s; 0x0110 -> out["Model"] = s; 0x0131 -> out["Software"] = s; 0x0132 -> out["DateTime"] = s; 0x9003 -> out["DateTimeOriginal"] = s }
                        }
                    }
                    if (tag == 0x8769 && !exifSub) ifd(u32(e + 8), true)
                }
            }
            ifd(u32(tiff + 4), false)
        } catch (e: Exception) { /* partial metadata is fine */ }
        return out
    }
}
