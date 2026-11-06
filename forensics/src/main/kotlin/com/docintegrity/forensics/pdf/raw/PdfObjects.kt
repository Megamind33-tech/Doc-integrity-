package com.docintegrity.forensics.pdf.raw

/**
 * Minimal, read-only PDF object model used by the structural (byte-level) analyser.
 *
 * This model deliberately does NOT try to be a full PDF library: it exists so that the forensic engine can
 * inspect cross-reference sections, incremental updates and individual objects exactly as they are stored in the
 * file, without any normalisation or rewriting. The input byte array is never modified.
 */
sealed class PdfObj

object PdfNull : PdfObj() {
    override fun toString() = "null"
}

data class PdfBool(val value: Boolean) : PdfObj()

data class PdfInt(val value: Long) : PdfObj()

data class PdfReal(val value: Double) : PdfObj()

data class PdfName(val value: String) : PdfObj() {
    override fun toString() = "/$value"
}

class PdfString(val bytes: ByteArray, val isHex: Boolean) : PdfObj() {
    /** Decodes per PDF text-string rules: UTF-16BE (BOM), UTF-8 (BOM) or PDFDocEncoding (approximated by Latin-1). */
    fun text(): String = when {
        bytes.size >= 2 && bytes[0] == 0xFE.toByte() && bytes[1] == 0xFF.toByte() ->
            String(bytes, 2, bytes.size - 2, Charsets.UTF_16BE)
        bytes.size >= 2 && bytes[0] == 0xFF.toByte() && bytes[1] == 0xFE.toByte() ->
            String(bytes, 2, bytes.size - 2, Charsets.UTF_16LE)
        bytes.size >= 3 && bytes[0] == 0xEF.toByte() && bytes[1] == 0xBB.toByte() && bytes[2] == 0xBF.toByte() ->
            String(bytes, 3, bytes.size - 3, Charsets.UTF_8)
        else -> String(bytes, Charsets.ISO_8859_1)
    }

    override fun equals(other: Any?) = other is PdfString && bytes.contentEquals(other.bytes)
    override fun hashCode() = bytes.contentHashCode()
    override fun toString() = "(${text()})"
}

class PdfArray(val items: List<PdfObj>) : PdfObj() {
    override fun equals(other: Any?) = other is PdfArray && items == other.items
    override fun hashCode() = items.hashCode()
    operator fun get(i: Int): PdfObj? = items.getOrNull(i)
    val size get() = items.size
}

class PdfDict(val map: Map<String, PdfObj>) : PdfObj() {
    operator fun get(key: String): PdfObj? = map[key]
    fun has(key: String) = map.containsKey(key)
    fun name(key: String): String? = (map[key] as? PdfName)?.value
    fun int(key: String): Long? = when (val v = map[key]) {
        is PdfInt -> v.value
        is PdfReal -> v.value.toLong()
        else -> null
    }
    fun str(key: String): PdfString? = map[key] as? PdfString
    fun dict(key: String): PdfDict? = map[key] as? PdfDict
    fun array(key: String): PdfArray? = map[key] as? PdfArray
    fun ref(key: String): PdfRef? = map[key] as? PdfRef
    override fun equals(other: Any?) = other is PdfDict && map == other.map
    override fun hashCode() = map.hashCode()
    override fun toString() = map.entries.joinToString(" ", "<<", ">>") { "/${it.key} ${it.value}" }
}

data class PdfRef(val num: Int, val gen: Int) : PdfObj() {
    override fun toString() = "$num $gen R"
}

/**
 * A stream object. [buf] is the full file buffer (shared, never copied or mutated); [dataStart]/[dataLength]
 * delimit the raw (still filter-encoded) stream bytes.
 */
class PdfStream(
    val dict: PdfDict,
    internal val buf: ByteArray,
    val dataStart: Int,
    val dataLength: Int,
    /** True when the declared /Length did not match the position of `endstream`. */
    val lengthMismatch: Boolean = false,
) : PdfObj() {
    fun rawBytes(): ByteArray = buf.copyOfRange(dataStart, dataStart + dataLength)

    /** Semantic equality: same dictionary (ignoring /Length) and identical raw bytes. */
    fun sameContentAs(other: PdfStream): Boolean {
        if (dataLength != other.dataLength) return false
        if (stripLength(dict) != stripLength(other.dict)) return false
        for (i in 0 until dataLength) if (buf[dataStart + i] != other.buf[other.dataStart + i]) return false
        return true
    }

    private fun stripLength(d: PdfDict) = PdfDict(d.map.filterKeys { it != "Length" })
    override fun toString() = "stream(len=$dataLength,$dict)"
}

/** Result of parsing "N G obj ... endobj". */
class PdfIndirect(val num: Int, val gen: Int, val value: PdfObj, val startOffset: Int, val endOffset: Int)
