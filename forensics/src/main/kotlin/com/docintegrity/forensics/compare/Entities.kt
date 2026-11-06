package com.docintegrity.forensics.compare

import java.math.BigDecimal

enum class EntityType(val label: String) { NAME("Name"), DATE("Date"), AMOUNT("Amount"), DOC_NUMBER("Document number") }

/**
 * A recognised value. [key] is the normalised form used for comparison; [altKeys] holds the other readings of an
 * ambiguous value (e.g. 03/04/2024 may be 3 April or 4 March).
 */
class Entity(
    val type: EntityType,
    val raw: String,
    val key: String,
    val altKeys: Set<String>,
    val label: String?,
    val line: Int,
    /** For amounts: ISO code or symbol if present. */
    val currency: String? = null,
) {
    fun matches(o: Entity): Boolean {
        if (type != o.type) return false
        if (key == o.key || key in o.altKeys || o.key in altKeys) return true
        if (altKeys.isNotEmpty() && o.altKeys.isNotEmpty() && altKeys.intersect(o.altKeys).isNotEmpty()) return true
        if (type == EntityType.AMOUNT) {
            // same numeric value; tolerate a missing currency marker on one side
            val a = key.substringAfter('|'); val b = o.key.substringAfter('|')
            if (a == b && (currency == null || o.currency == null || currency == o.currency)) return true
        }
        return false
    }
}

/**
 * Heuristic extraction of names, dates, amounts and document numbers from plain text lines.
 *
 * This is pattern matching, not language understanding: names are only recognised after labels such as
 * "Received from:", and numbers are only treated as amounts when they carry a currency marker, a decimal part, a
 * thousands separator or an amount-like label. The report states this limitation next to every entity finding.
 */
object EntityExtractor {

    private val MONTHS = mapOf(
        "jan" to 1, "feb" to 2, "mar" to 3, "apr" to 4, "may" to 5, "jun" to 6, "jul" to 7, "aug" to 8, "sep" to 9, "sept" to 9,
        "oct" to 10, "nov" to 11, "dec" to 12,
    )
    private const val MONTH_RE = "(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"

    private val DMY_TEXT = Regex("""\b(\d{1,2})(?:st|nd|rd|th)?[\s\-/.]+($MONTH_RE)\.?,?[\s\-/.]+(\d{4})\b""", RegexOption.IGNORE_CASE)
    private val MDY_TEXT = Regex("""\b($MONTH_RE)\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b""", RegexOption.IGNORE_CASE)
    private val ISO = Regex("""\b(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})\b""")
    private val NUMERIC = Regex("""\b(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4}|\d{2})\b""")

    private const val CUR = "USD|EUR|GBP|ZMW|ZMK|ZAR|KES|NGN|INR|CAD|AUD|JPY|CNY|CHF|UGX|TZS|GHS|BWP|MWK"
    private val AMOUNT = Regex("""(?<![A-Za-z0-9])((?:$CUR)|\$|€|£|¥|₦|₹|K(?=\s?\d))?\s?(\d{1,3}(?:[,.\u202F\u00A0 ]\d{3})+(?:[.,]\d{1,2})?|\d+(?:[.,]\d{1,2})?)(?![\d])""")
    private val AMOUNT_WORDS = Regex("""(?i)\b(total|amount|balance|price|fee|fees|cost|paid|payment|due|tax|vat|subtotal|salary|wage|net|gross|sum|charge|deposit|refund|rent|loan|credit|debit)\b""")

    private val DOC_LABELLED = Regex(
        """(?i:\b(receipt|invoice|certificate|reference|ref|policy|account|serial|licen[cs]e|passport|document|case|order|transaction|cheque|check|registration|student|employee|claim|tracking|customer|member|nrc|tin|vat|po|id)\b)\s*(?i:(?:no\.?|number|num\.?|nr\.?|#|id)?)\s*[:#\-]?\s*([A-Za-z0-9][A-Za-z0-9\-/._]{3,})""",
    )
    private val DOC_PATTERN = Regex("""\b[A-Z]{1,6}[-/]\d{2,}(?:[-/][A-Z0-9]+)*\b""")

    private val NAME_LABELLED = Regex(
        """(?i:\b(name|received from|received by|issued to|issued by|bill(?:ed)? to|paid by|paid to|pay to|payee|payer|student|employee|patient|customer|client|holder|beneficiary|applicant|owner|tenant|landlord|seller|buyer|signed by|prepared by|approved by|authori[sz]ed by|certify that|awarded to|presented to|dear)\b)\s*[:\-]?\s*(?:(?:Mr|Mrs|Ms|Miss|Dr|Prof|Hon)\.?\s+)?(\p{Lu}[\p{L}'’\-.]+(?:\s+\p{Lu}[\p{L}'’\-.]+){0,3})""",
    )
    private val NAME_STOP = setOf("date", "no", "number", "ref", "reference", "amount", "total", "signature", "address", "phone", "tel", "email", "id", "dob", "age", "sex", "gender", "class", "grade", "course", "invoice", "receipt", "payment", "description", "qty", "balance", "page")

    fun extract(lines: List<String>): List<Entity> {
        val out = ArrayList<Entity>()
        for ((li, line) in lines.withIndex()) {
            val masked = StringBuilder(line)
            fun mask(r: IntRange) { for (i in r) if (i < masked.length) masked.setCharAt(i, ' ') }

            // document numbers
            for (m in DOC_LABELLED.findAll(line)) {
                val v = m.groupValues[2].trimEnd('.', ',', ';', ':')
                if (v.any { it.isDigit() } && v.length >= 4) {
                    out.add(Entity(EntityType.DOC_NUMBER, v, docKey(v), emptySet(), m.groupValues[1].lowercase(), li))
                    mask(m.groups[2]!!.range)
                }
            }
            for (m in DOC_PATTERN.findAll(masked.toString())) {
                val v = m.value
                if (out.none { it.line == li && it.type == EntityType.DOC_NUMBER && it.key == docKey(v) }) out.add(Entity(EntityType.DOC_NUMBER, v, docKey(v), emptySet(), labelBefore(line, m.range.first), li))
                mask(m.range)
            }
            // dates
            for ((re, kind) in listOf(DMY_TEXT to "dmy", MDY_TEXT to "mdy")) {
                for (m in re.findAll(masked.toString())) {
                    val g = m.groupValues
                    val (d, mo, y) = if (kind == "dmy") Triple(g[1].toInt(), monthNo(g[2]), g[3].toInt()) else Triple(g[2].toInt(), monthNo(g[1]), g[3].toInt())
                    isoOrNull(y, mo, d)?.let { out.add(Entity(EntityType.DATE, m.value, it, emptySet(), labelBefore(line, m.range.first), li)); mask(m.range) }
                }
            }
            for (m in ISO.findAll(masked.toString())) {
                val g = m.groupValues
                isoOrNull(g[1].toInt(), g[2].toInt(), g[3].toInt())?.let { out.add(Entity(EntityType.DATE, m.value, it, emptySet(), labelBefore(line, m.range.first), li)); mask(m.range) }
            }
            for (m in NUMERIC.findAll(masked.toString())) {
                val g = m.groupValues
                val a = g[1].toInt(); val b = g[2].toInt(); var y = g[3].toInt(); if (g[3].length == 2) y += 2000
                val dm = isoOrNull(y, b, a); val md = isoOrNull(y, a, b)
                val keys = setOfNotNull(dm, md)
                if (keys.isEmpty()) continue
                val primary = when { a > 12 -> dm; b > 12 -> md; else -> dm ?: md }!!
                out.add(Entity(EntityType.DATE, m.value, primary, if (a <= 12 && b <= 12 && dm != md) keys else emptySet(), labelBefore(line, m.range.first), li))
                mask(m.range)
            }
            // amounts
            val rest = masked.toString()
            for (m in AMOUNT.findAll(rest)) {
                val cur = m.groups[1]?.value?.trim()?.ifEmpty { null }
                val num = m.groupValues[2]
                val value = parseNumber(num) ?: continue
                val hasDecimals = Regex("[.,]\\d{1,2}$").containsMatchIn(num) && value.scale() > 0
                val hasThousands = Regex("\\d[,.\\u202F\\u00A0 ]\\d{3}").containsMatchIn(num)
                val label = labelBefore(line, m.range.first)
                val wordy = AMOUNT_WORDS.containsMatchIn(label ?: "")
                if (cur == null && !hasDecimals && !hasThousands && !wordy) continue
                if (cur == null && !hasDecimals && !hasThousands && value < BigDecimal(10)) continue
                out.add(Entity(EntityType.AMOUNT, m.value.trim(), (cur ?: "") + "|" + value.stripTrailingZeros().toPlainString(), emptySet(), label, li, cur))
            }
            // names
            for (m in NAME_LABELLED.findAll(line)) {
                val tokens = m.groupValues[2].trim().split(Regex("\\s+")).takeWhile { it.lowercase().trimEnd('.', ':') !in NAME_STOP }
                if (tokens.isEmpty()) continue
                var name = tokens.joinToString(" ").trimEnd('.', ',', ';')
                // A name that wraps onto the next line ("Received from: Joseph" / "Mwanza") is rejoined when that next
                // line is only one or two capitalised words.
                if (m.range.last >= line.trimEnd().length - 1 && tokens.size == m.groupValues[2].trim().split(Regex("\\s+")).size) {
                    val next = lines.getOrNull(li + 1)?.trim()?.split(Regex("\\s+"))?.filter { it.isNotEmpty() }
                    if (next != null && next.size in 1..2 && next.all { it.first().isUpperCase() && it.none { c -> c.isDigit() } && it.lowercase().trimEnd('.', ':') !in NAME_STOP }) name += " " + next.joinToString(" ").trimEnd('.', ',', ';')
                }
                out.add(Entity(EntityType.NAME, name, name.lowercase().replace(Regex("\\s+"), " "), emptySet(), m.groupValues[1].lowercase(), li))
            }
        }
        return out
    }

    private fun docKey(v: String) = v.uppercase().filter { it.isLetterOrDigit() }

    /** Up to four words preceding [pos] on the line, lower-cased, without trailing punctuation: the entity's "label". */
    private fun labelBefore(line: String, pos: Int): String? {
        val before = line.substring(0, pos).trim().trimEnd(':', '-', '–').trim()
        if (before.isEmpty()) return null
        val words = before.split(Regex("\\s+")).takeLast(4)
        return words.joinToString(" ").lowercase().trim(':', ' ').ifEmpty { null }
    }

    private fun monthNo(s: String) = MONTHS[s.lowercase().take(if (s.lowercase().startsWith("sept")) 4 else 3)] ?: 0

    private fun isoOrNull(y: Int, m: Int, d: Int): String? {
        if (y !in 1900..2100 || m !in 1..12 || d !in 1..31) return null
        return try { java.time.LocalDate.of(y, m, d).toString() } catch (e: Exception) { null }
    }

    /** Parses "1,250.50", "1.250,50", "1 250", "12.5". Single separator + exactly 3 digits is a thousands separator. */
    fun parseNumber(s: String): BigDecimal? {
        val t = s.replace('\u202F', ' ').replace('\u00A0', ' ').trim()
        val lastDot = t.lastIndexOf('.'); val lastComma = t.lastIndexOf(',')
        val clean: String = when {
            lastDot >= 0 && lastComma >= 0 -> {
                val dec = maxOf(lastDot, lastComma)
                t.substring(0, dec).replace(Regex("[.,\\s]"), "") + "." + t.substring(dec + 1)
            }
            lastDot >= 0 || lastComma >= 0 -> {
                val sep = if (lastDot >= 0) '.' else ','
                val idx = t.lastIndexOf(sep)
                val after = t.length - idx - 1
                val count = t.count { it == sep }
                if (after == 3 || count > 1) t.replace(Regex("[.,\\s]"), "") else t.replace(" ", "").replace(sep, '.')
            }
            else -> t.replace(" ", "")
        }
        return clean.toBigDecimalOrNull()
    }
}
