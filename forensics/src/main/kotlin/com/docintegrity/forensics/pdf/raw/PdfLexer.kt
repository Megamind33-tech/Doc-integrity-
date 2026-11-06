package com.docintegrity.forensics.pdf.raw

/** Thrown for structurally unparseable input. Analysers catch this and report a limitation instead of crashing. */
class PdfSyntaxException(message: String, val offset: Int = -1) : Exception(message)

/**
 * Tolerant PDF tokenizer / object parser operating directly on the original, unmodified file bytes.
 * Forensic input is frequently damaged or hand-edited, so every routine here prefers "parse what is there and
 * report" over "reject".
 */
class PdfLexer(val buf: ByteArray, var pos: Int = 0, val limit: Int = buf.size) {

    companion object {
        fun isWhite(b: Int) = b == 0 || b == 9 || b == 10 || b == 12 || b == 13 || b == 32
        fun isDelim(b: Int) = b == '('.code || b == ')'.code || b == '<'.code || b == '>'.code ||
            b == '['.code || b == ']'.code || b == '{'.code || b == '}'.code || b == '/'.code || b == '%'.code
        fun isRegular(b: Int) = !isWhite(b) && !isDelim(b)
        fun isDigit(b: Int) = b >= '0'.code && b <= '9'.code

        private const val MAX_DEPTH = 64
    }

    fun peek(): Int = if (pos < limit) buf[pos].toInt() and 0xFF else -1

    fun skipWs() {
        while (pos < limit) {
            val b = buf[pos].toInt() and 0xFF
            if (isWhite(b)) {
                pos++
            } else if (b == '%'.code) {
                while (pos < limit && buf[pos].toInt() != 10 && buf[pos].toInt() != 13) pos++
            } else break
        }
    }

    /** Reads a run of regular characters (a keyword or number token) without interpreting it. */
    fun readRegularToken(): String {
        skipWs()
        val s = pos
        while (pos < limit && isRegular(buf[pos].toInt() and 0xFF)) pos++
        return String(buf, s, pos - s, Charsets.ISO_8859_1)
    }

    fun startsWithKeyword(kw: String): Boolean {
        if (pos + kw.length > limit) return false
        for (i in kw.indices) if (buf[pos + i].toInt() != kw[i].code) return false
        val after = if (pos + kw.length < limit) buf[pos + kw.length].toInt() and 0xFF else -1
        return after == -1 || !isRegular(after)
    }

    /**
     * Parses one direct object (which may be an `N G R` reference). [lengthResolver] is used to resolve an indirect
     * /Length when a stream follows; it is only consulted by [parseIndirectAt].
     */
    fun parseObject(depth: Int = 0): PdfObj {
        if (depth > MAX_DEPTH) throw PdfSyntaxException("object nesting too deep", pos)
        skipWs()
        if (pos >= limit) throw PdfSyntaxException("unexpected end of data", pos)
        val b = buf[pos].toInt() and 0xFF
        return when {
            b == '/'.code -> parseName()
            b == '('.code -> parseLiteralString()
            b == '<'.code -> if (pos + 1 < limit && buf[pos + 1].toInt() == '<'.code) parseDict(depth) else parseHexString()
            b == '['.code -> parseArray(depth)
            isDigit(b) || b == '+'.code || b == '-'.code || b == '.'.code -> parseNumberOrRef()
            else -> parseKeyword()
        }
    }

    private fun parseKeyword(): PdfObj {
        val start = pos
        val tok = readRegularToken()
        return when (tok) {
            "true" -> PdfBool(true)
            "false" -> PdfBool(false)
            "null" -> PdfNull
            "" -> {
                pos = start + 1
                throw PdfSyntaxException("unexpected byte 0x%02X".format(buf[start].toInt() and 0xFF), start)
            }
            else -> throw PdfSyntaxException("unexpected keyword '$tok'", start)
        }
    }

    private fun parseNumberOrRef(): PdfObj {
        val start = pos
        val tok = readRegularToken()
        val num = parseNumber(tok) ?: throw PdfSyntaxException("bad number '$tok'", start)
        if (num is PdfInt && num.value >= 0 && tok.all { it.isDigit() }) {
            // lookahead for "G R"
            val save = pos
            skipWs()
            val gStart = pos
            if (gStart < limit && isDigit(buf[gStart].toInt() and 0xFF)) {
                val gTok = readRegularToken()
                if (gTok.all { it.isDigit() } && gTok.length <= 5) {
                    skipWs()
                    if (pos < limit && buf[pos].toInt() == 'R'.code &&
                        (pos + 1 >= limit || !isRegular(buf[pos + 1].toInt() and 0xFF))
                    ) {
                        pos++
                        if (num.value <= Int.MAX_VALUE) return PdfRef(num.value.toInt(), gTok.toInt())
                    }
                }
            }
            pos = save
        }
        return num
    }

    private fun parseNumber(tok: String): PdfObj? {
        if (tok.isEmpty()) return null
        var t = tok
        // Tolerate "--5" and "+5" produced by sloppy writers.
        var neg = false
        while (t.startsWith("-") || t.startsWith("+")) {
            if (t[0] == '-') neg = !neg
            t = t.substring(1)
        }
        if (t.isEmpty()) return null
        return if (t.all { it.isDigit() }) {
            val v = t.toLongOrNull() ?: return PdfReal(t.toDoubleOrNull()?.let { if (neg) -it else it } ?: return null)
            PdfInt(if (neg) -v else v)
        } else {
            val cleaned = if (t.count { it == '.' } > 1) t.substringBeforeLast('.') else t
            val d = cleaned.toDoubleOrNull() ?: return null
            PdfReal(if (neg) -d else d)
        }
    }

    private fun parseName(): PdfName {
        pos++ // '/'
        val sb = StringBuilder()
        while (pos < limit) {
            val b = buf[pos].toInt() and 0xFF
            if (!isRegular(b)) break
            if (b == '#'.code && pos + 2 < limit + 0 && hex(buf[pos + 1].toInt()) >= 0 && hex(buf[pos + 2].toInt()) >= 0) {
                sb.append(((hex(buf[pos + 1].toInt()) shl 4) or hex(buf[pos + 2].toInt())).toChar())
                pos += 3
            } else {
                sb.append(b.toChar())
                pos++
            }
        }
        return PdfName(sb.toString())
    }

    private fun hex(c: Int): Int = when (c) {
        in '0'.code..'9'.code -> c - '0'.code
        in 'a'.code..'f'.code -> c - 'a'.code + 10
        in 'A'.code..'F'.code -> c - 'A'.code + 10
        else -> -1
    }

    private fun parseLiteralString(): PdfString {
        pos++ // '('
        val out = java.io.ByteArrayOutputStream()
        var depth = 1
        while (pos < limit) {
            val b = buf[pos++].toInt() and 0xFF
            when (b) {
                '('.code -> { depth++; out.write(b) }
                ')'.code -> { depth--; if (depth == 0) return PdfString(out.toByteArray(), false) else out.write(b) }
                '\\'.code -> {
                    if (pos >= limit) break
                    val e = buf[pos++].toInt() and 0xFF
                    when (e) {
                        'n'.code -> out.write(10)
                        'r'.code -> out.write(13)
                        't'.code -> out.write(9)
                        'b'.code -> out.write(8)
                        'f'.code -> out.write(12)
                        '('.code, ')'.code, '\\'.code -> out.write(e)
                        13 -> if (pos < limit && buf[pos].toInt() == 10) pos++
                        10 -> {}
                        in '0'.code..'7'.code -> {
                            var v = e - '0'.code
                            var n = 1
                            while (n < 3 && pos < limit && buf[pos].toInt() in '0'.code..'7'.code) {
                                v = v * 8 + (buf[pos].toInt() - '0'.code); pos++; n++
                            }
                            out.write(v and 0xFF)
                        }
                        else -> out.write(e)
                    }
                }
                else -> out.write(b)
            }
        }
        return PdfString(out.toByteArray(), false) // unterminated; keep what we have
    }

    private fun parseHexString(): PdfString {
        pos++ // '<'
        val out = java.io.ByteArrayOutputStream()
        var hi = -1
        while (pos < limit) {
            val b = buf[pos++].toInt() and 0xFF
            if (b == '>'.code) break
            val h = hex(b)
            if (h < 0) continue
            if (hi < 0) hi = h else { out.write((hi shl 4) or h); hi = -1 }
        }
        if (hi >= 0) out.write(hi shl 4)
        return PdfString(out.toByteArray(), true)
    }

    private fun parseArray(depth: Int): PdfArray {
        pos++ // '['
        val items = ArrayList<PdfObj>()
        while (true) {
            skipWs()
            if (pos >= limit) throw PdfSyntaxException("unterminated array", pos)
            if (buf[pos].toInt() == ']'.code) { pos++; break }
            items.add(parseObject(depth + 1))
        }
        return PdfArray(items)
    }

    private fun parseDict(depth: Int): PdfDict {
        pos += 2 // '<<'
        val map = LinkedHashMap<String, PdfObj>()
        while (true) {
            skipWs()
            if (pos >= limit) throw PdfSyntaxException("unterminated dictionary", pos)
            if (buf[pos].toInt() == '>'.code && pos + 1 < limit && buf[pos + 1].toInt() == '>'.code) { pos += 2; break }
            if (buf[pos].toInt() != '/'.code) {
                // Garbage inside a dictionary: skip one token so we can resynchronise.
                try { parseObject(depth + 1) } catch (e: PdfSyntaxException) { pos++ }
                continue
            }
            val key = parseName().value
            skipWs()
            if (pos < limit && buf[pos].toInt() == '>'.code) { map[key] = PdfNull; continue }
            val value = parseObject(depth + 1)
            map[key] = value
        }
        return PdfDict(map)
    }

    /**
     * Parses `N G obj <value> [stream ... endstream] endobj` starting at [offset]. Returns null if no indirect
     * object header is found at that position.
     */
    fun parseIndirectAt(offset: Int, lengthResolver: ((PdfRef) -> Long?)? = null): PdfIndirect? {
        pos = offset
        skipWs()
        val start = pos
        if (pos >= limit || !isDigit(buf[pos].toInt() and 0xFF)) return null
        val numTok = readRegularToken()
        val genTok = readRegularToken()
        val objTok = readRegularToken()
        if (objTok != "obj" && !objTok.startsWith("obj")) return null
        if (!numTok.all { it.isDigit() } || !genTok.all { it.isDigit() } || numTok.isEmpty() || genTok.isEmpty()) return null
        if (objTok.length > 3) pos -= (objTok.length - 3) // "objxyz" with no whitespace; resume after "obj"
        val num = numTok.toIntOrNull() ?: return null
        val gen = genTok.toIntOrNull() ?: return null

        val value = parseObject()
        var result: PdfObj = value
        skipWs()
        if (value is PdfDict && startsWithKeyword("stream")) {
            pos += 6
            // single EOL after 'stream' (CRLF, LF, or lone CR)
            if (pos < limit && buf[pos].toInt() == 13) { pos++; if (pos < limit && buf[pos].toInt() == 10) pos++ }
            else if (pos < limit && buf[pos].toInt() == 10) pos++
            val dataStart = pos
            val declared: Long? = when (val l = value["Length"]) {
                is PdfInt -> l.value
                is PdfRef -> lengthResolver?.invoke(l)
                else -> null
            }
            var length = -1
            var mismatch = false
            if (declared != null && declared >= 0 && dataStart + declared <= limit) {
                val e = (dataStart + declared).toInt()
                val save = pos
                pos = e
                skipWs()
                if (startsWithKeyword("endstream")) length = declared.toInt()
                pos = save
            }
            if (length < 0) {
                val e = indexOf("endstream", dataStart)
                if (e < 0) {
                    length = limit - dataStart
                } else {
                    var end = e
                    // strip one EOL preceding endstream
                    if (end > dataStart && buf[end - 1].toInt() == 10) end--
                    if (end > dataStart && buf[end - 1].toInt() == 13) end--
                    length = end - dataStart
                }
                mismatch = declared == null || declared != length.toLong()
            }
            result = PdfStream(value, buf, dataStart, length, mismatch)
            pos = dataStart + length
            skipWs()
            if (startsWithKeyword("endstream")) pos += 9
        }
        skipWs()
        if (startsWithKeyword("endobj")) pos += 6
        return PdfIndirect(num, gen, result, start, pos)
    }

    fun indexOf(needle: String, from: Int, to: Int = limit): Int {
        val n = needle.toByteArray(Charsets.ISO_8859_1)
        var i = maxOf(from, 0)
        val last = to - n.size
        outer@ while (i <= last) {
            for (j in n.indices) if (buf[i + j] != n[j]) { i++; continue@outer }
            return i
        }
        return -1
    }
}
