package com.docintegrity.forensics.pdf.raw

import java.io.ByteArrayOutputStream
import java.util.zip.Inflater

/** Result of decoding a stream through its filter chain. */
class DecodedStream(
    val bytes: ByteArray,
    /** Filters that were applied successfully. */
    val applied: List<String>,
    /** First filter that this decoder does not implement (e.g. DCTDecode); [bytes] are the data as it was at that point. */
    val stoppedAt: String?,
    val truncated: Boolean = false,
)

object StreamDecoder {
    const val MAX_OUTPUT = 128 * 1024 * 1024

    fun filtersOf(dict: PdfDict): List<String> = when (val f = dict["Filter"] ?: dict["F"].takeIf { it is PdfName || it is PdfArray }) {
        is PdfName -> listOf(f.value)
        is PdfArray -> f.items.mapNotNull { (it as? PdfName)?.value }
        else -> emptyList()
    }

    private fun paramsOf(dict: PdfDict, index: Int): PdfDict? {
        val p = dict["DecodeParms"] ?: dict["DP"]
        return when (p) {
            is PdfDict -> if (index == 0) p else null
            is PdfArray -> p[index] as? PdfDict
            else -> null
        }
    }

    fun decode(stream: PdfStream, maxOutput: Int = MAX_OUTPUT): DecodedStream {
        var data = stream.rawBytes()
        val applied = ArrayList<String>()
        var truncated = false
        val filters = filtersOf(stream.dict)
        for ((i, name) in filters.withIndex()) {
            val parms = paramsOf(stream.dict, i)
            val out: ByteArray = when (name) {
                "FlateDecode", "Fl" -> {
                    val r = inflate(data, maxOutput)
                    truncated = truncated || r.second
                    applyPredictor(r.first, parms)
                }
                "ASCIIHexDecode", "AHx" -> asciiHex(data)
                "ASCII85Decode", "A85" -> ascii85(data)
                "RunLengthDecode", "RL" -> runLength(data, maxOutput)
                "LZWDecode", "LZW" -> applyPredictor(lzw(data, parms?.int("EarlyChange") ?: 1L, maxOutput), parms)
                "Crypt" -> data
                else -> return DecodedStream(data, applied, name, truncated)
            }
            data = out
            applied.add(name)
        }
        return DecodedStream(data, applied, null, truncated)
    }

    /** Returns (output, truncatedOrCorrupt). Tolerates corrupt/truncated Flate data by returning what was inflated. */
    fun inflate(input: ByteArray, maxOutput: Int): Pair<ByteArray, Boolean> {
        val inf = Inflater()
        val out = ByteArrayOutputStream(maxOf(input.size * 3, 256))
        var bad = false
        try {
            inf.setInput(input)
            val chunk = ByteArray(16 * 1024)
            while (!inf.finished()) {
                val n = try { inf.inflate(chunk) } catch (e: java.util.zip.DataFormatException) { bad = true; 0 }
                if (n > 0) {
                    out.write(chunk, 0, n)
                    if (out.size() > maxOutput) { bad = true; break }
                }
                if (bad) break
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) { bad = !inf.finished(); break }
            }
        } finally {
            inf.end()
        }
        return out.toByteArray() to bad
    }

    private fun applyPredictor(data: ByteArray, parms: PdfDict?): ByteArray {
        val predictor = parms?.int("Predictor")?.toInt() ?: 1
        if (predictor <= 1) return data
        val colors = (parms?.int("Colors") ?: 1L).toInt().coerceAtLeast(1)
        val bpc = (parms?.int("BitsPerComponent") ?: 8L).toInt().coerceAtLeast(1)
        val columns = (parms?.int("Columns") ?: 1L).toInt().coerceAtLeast(1)
        val rowBytes = (colors * bpc * columns + 7) / 8
        val bpp = maxOf(1, (colors * bpc + 7) / 8)
        if (predictor == 2) {
            if (bpc != 8) return data // 16/1/2/4-bit TIFF predictor unsupported (not needed for structural tables)
            val out = data.copyOf()
            var rowStart = 0
            while (rowStart + rowBytes <= out.size) {
                for (i in bpp until rowBytes) {
                    out[rowStart + i] = (out[rowStart + i] + out[rowStart + i - bpp]).toByte()
                }
                rowStart += rowBytes
            }
            return out
        }
        // PNG predictors: each row prefixed by a filter-type byte.
        val stride = rowBytes + 1
        val rows = data.size / stride
        val out = ByteArray(rows * rowBytes)
        val prior = ByteArray(rowBytes)
        val cur = ByteArray(rowBytes)
        for (r in 0 until rows) {
            val type = data[r * stride].toInt() and 0xFF
            System.arraycopy(data, r * stride + 1, cur, 0, rowBytes)
            when (type) {
                0 -> {}
                1 -> for (i in bpp until rowBytes) cur[i] = (cur[i] + cur[i - bpp]).toByte()
                2 -> for (i in 0 until rowBytes) cur[i] = (cur[i] + prior[i]).toByte()
                3 -> for (i in 0 until rowBytes) {
                    val left = if (i >= bpp) cur[i - bpp].toInt() and 0xFF else 0
                    cur[i] = (cur[i] + ((left + (prior[i].toInt() and 0xFF)) / 2)).toByte()
                }
                4 -> for (i in 0 until rowBytes) {
                    val a = if (i >= bpp) cur[i - bpp].toInt() and 0xFF else 0
                    val b = prior[i].toInt() and 0xFF
                    val c = if (i >= bpp) prior[i - bpp].toInt() and 0xFF else 0
                    val p = a + b - c
                    val pa = Math.abs(p - a); val pb = Math.abs(p - b); val pc = Math.abs(p - c)
                    val pr = if (pa <= pb && pa <= pc) a else if (pb <= pc) b else c
                    cur[i] = (cur[i] + pr).toByte()
                }
            }
            System.arraycopy(cur, 0, out, r * rowBytes, rowBytes)
            System.arraycopy(cur, 0, prior, 0, rowBytes)
        }
        return out
    }

    private fun asciiHex(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        var hi = -1
        for (b in data) {
            val c = b.toInt() and 0xFF
            if (c == '>'.code) break
            val h = Character.digit(c, 16)
            if (h < 0) continue
            if (hi < 0) hi = h else { out.write((hi shl 4) or h); hi = -1 }
        }
        if (hi >= 0) out.write(hi shl 4)
        return out.toByteArray()
    }

    private fun ascii85(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val group = IntArray(5)
        var n = 0
        var i = 0
        if (data.size >= 2 && data[0].toInt() == '<'.code && data[1].toInt() == '~'.code) i = 2
        while (i < data.size) {
            val c = data[i++].toInt() and 0xFF
            if (PdfLexer.isWhite(c)) continue
            if (c == '~'.code) break
            if (c == 'z'.code && n == 0) { out.write(0); out.write(0); out.write(0); out.write(0); continue }
            if (c < '!'.code || c > 'u'.code) continue
            group[n++] = c - '!'.code
            if (n == 5) {
                var v = 0L
                for (k in 0 until 5) v = v * 85 + group[k]
                out.write((v shr 24).toInt() and 0xFF); out.write((v shr 16).toInt() and 0xFF)
                out.write((v shr 8).toInt() and 0xFF); out.write(v.toInt() and 0xFF)
                n = 0
            }
        }
        if (n > 1) {
            for (k in n until 5) group[k] = 84
            var v = 0L
            for (k in 0 until 5) v = v * 85 + group[k]
            val bytes = intArrayOf((v shr 24).toInt() and 0xFF, (v shr 16).toInt() and 0xFF, (v shr 8).toInt() and 0xFF, v.toInt() and 0xFF)
            for (k in 0 until n - 1) out.write(bytes[k])
        }
        return out.toByteArray()
    }

    private fun runLength(data: ByteArray, maxOutput: Int): ByteArray {
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < data.size) {
            val l = data[i++].toInt() and 0xFF
            if (l == 128) break
            if (l < 128) {
                val n = l + 1
                val end = minOf(i + n, data.size)
                out.write(data, i, end - i); i = end
            } else if (i < data.size) {
                val n = 257 - l
                val v = data[i++].toInt()
                repeat(n) { out.write(v) }
            }
            if (out.size() > maxOutput) break
        }
        return out.toByteArray()
    }

    private fun lzw(data: ByteArray, earlyChange: Long, maxOutput: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val table = arrayOfNulls<ByteArray>(4096)
        for (i in 0 until 256) table[i] = byteArrayOf(i.toByte())
        var next = 258
        var bits = 9
        var buffer = 0
        var bufBits = 0
        var prev: ByteArray? = null
        var idx = 0
        val early = if (earlyChange == 0L) 0 else 1
        while (true) {
            while (bufBits < bits && idx < data.size) { buffer = (buffer shl 8) or (data[idx++].toInt() and 0xFF); bufBits += 8 }
            if (bufBits < bits) break
            val code = (buffer shr (bufBits - bits)) and ((1 shl bits) - 1)
            bufBits -= bits
            buffer = buffer and ((1 shl bufBits) - 1)
            if (code == 256) { next = 258; bits = 9; prev = null; continue }
            if (code == 257) break
            val entry: ByteArray = if (code < next && table[code] != null) table[code]!!
            else if (prev != null) prev + prev[0] else break
            out.write(entry)
            if (prev != null && next < 4096) { table[next++] = prev + entry[0] }
            prev = entry
            bits = when { next + early >= 2048 -> 12; next + early >= 1024 -> 11; next + early >= 512 -> 10; else -> 9 }
            if (out.size() > maxOutput) break
        }
        return out.toByteArray()
    }
}
