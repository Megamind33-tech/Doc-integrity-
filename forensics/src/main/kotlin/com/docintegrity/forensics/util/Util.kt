package com.docintegrity.forensics.util

import java.security.MessageDigest
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** File fingerprints computed in one pass over the (unmodified) bytes. */
data class FileHashes(
    val sha256: String,
    val sha512: String,
    val sha1: String,
    val md5: String,
    val size: Long,
)

object Hashing {
    fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) { sb.append("0123456789abcdef"[(x.toInt() shr 4) and 15]); sb.append("0123456789abcdef"[x.toInt() and 15]) }
        return sb.toString()
    }

    fun sha256(data: ByteArray, off: Int = 0, len: Int = data.size - off): String = digest("SHA-256", data, off, len)

    fun digest(alg: String, data: ByteArray, off: Int = 0, len: Int = data.size - off): String {
        val md = MessageDigest.getInstance(alg)
        md.update(data, off, len)
        return hex(md.digest())
    }

    fun all(data: ByteArray): FileHashes {
        val s256 = MessageDigest.getInstance("SHA-256")
        val s512 = MessageDigest.getInstance("SHA-512")
        val s1 = MessageDigest.getInstance("SHA-1")
        val m5 = MessageDigest.getInstance("MD5")
        val step = 1 shl 16
        var p = 0
        while (p < data.size) {
            val n = minOf(step, data.size - p)
            s256.update(data, p, n); s512.update(data, p, n); s1.update(data, p, n); m5.update(data, p, n)
            p += n
        }
        return FileHashes(hex(s256.digest()), hex(s512.digest()), hex(s1.digest()), hex(m5.digest()), data.size.toLong())
    }

    /** Normalises a user-typed hash (spaces, colons, "sha256:" prefix, upper case). */
    fun normaliseHexHash(input: String): String {
        var s = input.trim().lowercase()
        val idx = s.indexOf(':')
        if (idx in 1..10 && (s.startsWith("sha") || s.startsWith("md5"))) s = s.substring(idx + 1)
        return s.filter { it in '0'..'9' || it in 'a'..'f' }
    }

    fun algorithmForHexLength(len: Int): String? = when (len) {
        32 -> "MD5"
        40 -> "SHA-1"
        64 -> "SHA-256"
        128 -> "SHA-512"
        else -> null
    }
}

/** A date parsed from a PDF Info dictionary or an XMP packet. */
data class ParsedDate(
    val raw: String,
    val local: LocalDateTime?,
    /** Offset when the source stated one. */
    val offset: ZoneOffset?,
) {
    val valid get() = local != null
    /** Best-effort instant; assumes UTC when the source did not state an offset. */
    fun instant(): OffsetDateTime? = local?.atOffset(offset ?: ZoneOffset.UTC)
    fun display(): String = local?.let {
        it.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + (offset?.let { o -> " " + o.id.replace("Z", "UTC") } ?: " (no time zone stated)")
    } ?: "$raw (unparseable)"
}

object PdfDates {
    /** `D:YYYYMMDDHHmmSSOHH'mm'` with every part after the year optional. */
    fun parsePdf(raw: String?): ParsedDate? {
        if (raw == null) return null
        var s = raw.trim()
        if (s.startsWith("D:")) s = s.substring(2)
        val m = Regex("^(\\d{4})(\\d{2})?(\\d{2})?(\\d{2})?(\\d{2})?(\\d{2})?\\s*(Z|[+\\-]\\d{2}(?:'?\\d{2}'?)?)?.*$").find(s)
            ?: return ParsedDate(raw, null, null)
        return try {
            val g = m.groupValues
            val dt = LocalDateTime.of(
                g[1].toInt(), g[2].ifEmpty { "1" }.toInt(), g[3].ifEmpty { "1" }.toInt(),
                g[4].ifEmpty { "0" }.toInt(), g[5].ifEmpty { "0" }.toInt(), g[6].ifEmpty { "0" }.toInt(),
            )
            ParsedDate(raw, dt, parseOffset(g[7]))
        } catch (e: Exception) { ParsedDate(raw, null, null) }
    }

    private fun parseOffset(t: String): ZoneOffset? {
        if (t.isEmpty()) return null
        if (t == "Z") return ZoneOffset.UTC
        val sign = if (t[0] == '-') -1 else 1
        val digits = t.substring(1).filter { it.isDigit() }
        val h = digits.take(2).toIntOrNull() ?: return null
        val mi = digits.drop(2).take(2).toIntOrNull() ?: 0
        return try { ZoneOffset.ofTotalSeconds(sign * (h * 3600 + mi * 60)) } catch (e: Exception) { null }
    }

    /** ISO-8601 forms used by XMP. */
    fun parseIso(raw: String?): ParsedDate? {
        if (raw == null) return null
        val s = raw.trim()
        val m = Regex("^(\\d{4})(?:-(\\d{2}))?(?:-(\\d{2}))?(?:[T ](\\d{2}):(\\d{2})(?::(\\d{2})(?:\\.\\d+)?)?)?\\s*(Z|[+\\-]\\d{2}:?\\d{2})?$").find(s)
            ?: return ParsedDate(raw, null, null)
        return try {
            val g = m.groupValues
            val dt = LocalDateTime.of(
                g[1].toInt(), g[2].ifEmpty { "1" }.toInt(), g[3].ifEmpty { "1" }.toInt(),
                g[4].ifEmpty { "0" }.toInt(), g[5].ifEmpty { "0" }.toInt(), g[6].ifEmpty { "0" }.toInt(),
            )
            ParsedDate(raw, dt, parseOffset(g[7]))
        } catch (e: Exception) { ParsedDate(raw, null, null) }
    }

    /** Difference in seconds, comparing instants when both carry an offset, otherwise the local clock readings. */
    fun diffSeconds(a: ParsedDate, b: ParsedDate): Long? {
        val la = a.local ?: return null
        val lb = b.local ?: return null
        return if (a.offset != null && b.offset != null) {
            java.time.Duration.between(a.instant(), b.instant()).seconds
        } else {
            java.time.Duration.between(la, lb).seconds
        }
    }
}

/** Minimal deterministic JSON writer (stable key order) used for the reproducible export. */
class Json private constructor(private val sb: StringBuilder = StringBuilder()) {
    private var needComma = ArrayDeque<Boolean>().apply { addLast(false) }

    companion object {
        fun obj(block: Json.() -> Unit): String { val j = Json(); j.beginObj(); j.block(); j.endObj(); return j.sb.toString() }
        fun escape(s: String): String {
            val out = StringBuilder("\"")
            for (c in s) when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c < ' ' -> out.append("\\u%04x".format(c.code))
                else -> out.append(c)
            }
            return out.append('"').toString()
        }
    }

    private fun sep() { if (needComma.last()) sb.append(','); needComma[needComma.size - 1] = true }
    private fun beginObj() { sb.append('{'); needComma.addLast(false) }
    private fun endObj() { sb.append('}'); needComma.removeLast() }

    fun str(key: String, v: String?) { sep(); sb.append(escape(key)).append(':'); sb.append(if (v == null) "null" else escape(v)) }
    fun num(key: String, v: Number?) { sep(); sb.append(escape(key)).append(':').append(v?.toString() ?: "null") }
    fun bool(key: String, v: Boolean?) { sep(); sb.append(escape(key)).append(':').append(v?.toString() ?: "null") }
    fun obj(key: String, block: Json.() -> Unit) { sep(); sb.append(escape(key)).append(':'); beginObj(); block(); endObj() }
    fun strs(key: String, v: List<String>) { sep(); sb.append(escape(key)).append(':').append(v.joinToString(",", "[", "]") { escape(it) }) }
    fun <T> arr(key: String, items: List<T>, block: Json.(T) -> Unit) {
        sep(); sb.append(escape(key)).append(':').append('[')
        needComma.addLast(false)
        for (it in items) { sepItem(); beginObj(); block(it); endObj() }
        needComma.removeLast()
        sb.append(']')
    }
    private fun sepItem() { if (needComma.last()) sb.append(','); needComma[needComma.size - 1] = true }
}
