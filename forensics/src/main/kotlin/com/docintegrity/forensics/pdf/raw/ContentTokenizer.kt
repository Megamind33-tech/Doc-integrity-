package com.docintegrity.forensics.pdf.raw

/** One content-stream token: either an operand object or an operator keyword (with inline-image data for BI). */
sealed class ContentToken {
    class Operand(val obj: PdfObj) : ContentToken()
    class Operator(val name: String, val inlineImageDict: PdfDict? = null, val inlineImageData: ByteArray? = null) : ContentToken()
}

/**
 * Splits a decoded content stream into operands and operators. Used for orphan-content recovery and for
 * lightweight stream statistics where a full graphics engine is unnecessary.
 */
object ContentTokenizer {
    fun tokens(data: ByteArray, maxTokens: Int = 2_000_000): Sequence<ContentToken> = sequence {
        val lx = PdfLexer(data)
        var count = 0
        while (count++ < maxTokens) {
            lx.skipWs()
            if (lx.pos >= lx.limit) break
            val b = lx.peek()
            val startsObject = b == '/'.code || b == '('.code || b == '<'.code || b == '['.code ||
                PdfLexer.isDigit(b) || b == '+'.code || b == '-'.code || b == '.'.code
            if (startsObject) {
                val o = try { lx.parseObject() } catch (e: PdfSyntaxException) { lx.pos = minOf(lx.pos + 1, lx.limit); continue }
                yield(ContentToken.Operand(o))
            } else if (b == ']'.code || b == '>'.code || b == '{'.code || b == '}'.code || b == ')'.code) {
                lx.pos++
            } else {
                val tok = lx.readRegularToken()
                if (tok.isEmpty()) { lx.pos++; continue }
                when (tok) {
                    "true" -> yield(ContentToken.Operand(PdfBool(true)))
                    "false" -> yield(ContentToken.Operand(PdfBool(false)))
                    "null" -> yield(ContentToken.Operand(PdfNull))
                    "BI" -> {
                        val m = LinkedHashMap<String, PdfObj>()
                        while (true) {
                            lx.skipWs()
                            if (lx.pos >= lx.limit || lx.startsWithKeyword("ID")) break
                            if (lx.peek() != '/'.code) { lx.pos++; continue }
                            val k = try { lx.parseObject() as? PdfName } catch (e: PdfSyntaxException) { null } ?: break
                            val v = try { lx.parseObject() } catch (e: PdfSyntaxException) { break }
                            m[k.value] = v
                        }
                        if (lx.startsWithKeyword("ID")) lx.pos += 2
                        if (lx.pos < lx.limit && PdfLexer.isWhite(lx.peek())) lx.pos++
                        val dataStart = lx.pos
                        var e = dataStart
                        var found = -1
                        while (e + 1 < lx.limit) {
                            if (data[e].toInt() == 'E'.code && data[e + 1].toInt() == 'I'.code &&
                                (e == dataStart || PdfLexer.isWhite(data[e - 1].toInt() and 0xFF)) &&
                                (e + 2 >= lx.limit || PdfLexer.isWhite(data[e + 2].toInt() and 0xFF))
                            ) { found = e; break }
                            e++
                        }
                        val end = if (found < 0) lx.limit else found
                        lx.pos = if (found < 0) lx.limit else found + 2
                        yield(ContentToken.Operator("BI", PdfDict(m), data.copyOfRange(dataStart, end)))
                    }
                    else -> yield(ContentToken.Operator(tok))
                }
            }
        }
    }

    /** Printable strings shown by Tj/TJ/'/" operators, assuming single-byte codes (a preview only; subset fonts may not decode). */
    fun shownStrings(data: ByteArray): List<String> {
        val out = ArrayList<String>()
        val operands = ArrayList<PdfObj>()
        for (t in tokens(data)) {
            when (t) {
                is ContentToken.Operand -> { operands.add(t.obj); if (operands.size > 64) operands.removeAt(0) }
                is ContentToken.Operator -> {
                    when (t.name) {
                        "Tj", "'", "\"" -> (operands.lastOrNull() as? PdfString)?.let { out.add(printable(it.bytes)) }
                        "TJ" -> (operands.lastOrNull() as? PdfArray)?.let { arr ->
                            out.add(arr.items.filterIsInstance<PdfString>().joinToString("") { printable(it.bytes) })
                        }
                    }
                    operands.clear()
                }
            }
        }
        return out
    }

    private fun printable(b: ByteArray): String {
        val sb = StringBuilder()
        for (x in b) { val c = x.toInt() and 0xFF; if (c in 32..126) sb.append(c.toChar()) }
        return sb.toString()
    }
}
