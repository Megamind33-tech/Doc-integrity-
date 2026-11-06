package com.docintegrity.forensics.pdf.images

import com.docintegrity.forensics.image.RasterImage
import com.docintegrity.forensics.pdf.analysis.DocView
import com.docintegrity.forensics.pdf.raw.PdfArray
import com.docintegrity.forensics.pdf.raw.PdfDict
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.pdf.raw.PdfName
import com.docintegrity.forensics.pdf.raw.PdfObj
import com.docintegrity.forensics.pdf.raw.PdfRef
import com.docintegrity.forensics.pdf.raw.PdfStream
import com.docintegrity.forensics.pdf.raw.StreamDecoder
import com.docintegrity.forensics.util.Hashing

enum class ImageKind { JPEG, RAW_PIXELS, OTHER_ENCODING }

/** An image XObject as stored in the file. [encoded] is the stream data after undoing only non-image filters. */
class ExtractedImage(
    val objNum: Int,
    val pages: Set<Int>,
    val width: Int,
    val height: Int,
    val bitsPerComponent: Int,
    val colorSpace: String,
    val filters: List<String>,
    val kind: ImageKind,
    /** JPEG file bytes (kind=JPEG) or decoded raw samples (kind=RAW_PIXELS) or the raw stream (OTHER). */
    val data: ByteArray,
    val hasSoftMask: Boolean,
    val storedBytes: Int,
) {
    val sha256: String by lazy { Hashing.sha256(data) }

    /** Decodes to pixels where the encoding is supported. JPEG goes through the platform decoder. */
    fun toRaster(decode: (ByteArray) -> RasterImage?): RasterImage? = when (kind) {
        ImageKind.JPEG -> decode(data)
        ImageKind.RAW_PIXELS -> rawToRaster()
        ImageKind.OTHER_ENCODING -> null
    }

    private fun rawToRaster(): RasterImage? {
        if (bitsPerComponent != 8) return null
        val n = when (colorSpace) { "DeviceGray", "CalGray" -> 1; "DeviceRGB", "CalRGB" -> 3; else -> return null }
        if (data.size < width * height * n) return null
        val px = IntArray(width * height)
        for (i in px.indices) {
            px[i] = if (n == 1) { val g = data[i].toInt() and 255; (0xFF shl 24) or (g shl 16) or (g shl 8) or g }
            else (0xFF shl 24) or ((data[i * 3].toInt() and 255) shl 16) or ((data[i * 3 + 1].toInt() and 255) shl 8) or (data[i * 3 + 2].toInt() and 255)
        }
        return RasterImage(width, height, px)
    }
}

/**
 * Finds image XObjects through the page resources (as of the last revision) and returns their stored data.
 * Pure byte-level: no Bitmap/Android classes involved. Unsupported encodings are listed, not hidden.
 */
object PdfImageExtractor {

    class Result(val images: List<ExtractedImage>, val unsupported: List<String>)

    fun extract(file: PdfFile, rev: Int = file.lastRevision): Result {
        val view = DocView(file, rev)
        val out = LinkedHashMap<Int, ExtractedImage>()
        val unsupported = ArrayList<String>()
        for (p in view.pages) {
            val xo = file.resolve(p.resources?.get("XObject"), rev) as? PdfDict ?: continue
            walk(file, rev, xo, p.index, out, unsupported, 0)
        }
        return Result(out.values.toList(), unsupported)
    }

    private fun walk(file: PdfFile, rev: Int, xobjects: PdfDict, page: Int, out: MutableMap<Int, ExtractedImage>, unsupported: MutableList<String>, depth: Int) {
        if (depth > 4) return
        for ((name, ref) in xobjects.map) {
            val num = (ref as? PdfRef)?.num ?: continue
            val st = file.resolve(ref, rev) as? PdfStream ?: continue
            when (st.dict.name("Subtype")) {
                "Image" -> {
                    val existing = out[num]
                    if (existing != null) { out[num] = existing.withPage(page); continue }
                    val img = describe(file, rev, num, st, page)
                    if (img != null) out[num] = img else unsupported.add("obj $num ($name): unsupported image encoding")
                }
                "Form" -> (file.resolve(st.dict["Resources"], rev) as? PdfDict)?.let { r -> (file.resolve(r["XObject"], rev) as? PdfDict)?.let { walk(file, rev, it, page, out, unsupported, depth + 1) } }
            }
        }
    }

    private fun ExtractedImage.withPage(p: Int) = ExtractedImage(objNum, pages + p, width, height, bitsPerComponent, colorSpace, filters, kind, data, hasSoftMask, storedBytes)

    private fun describe(file: PdfFile, rev: Int, num: Int, st: PdfStream, page: Int): ExtractedImage? {
        val d = st.dict
        val w = d.int("Width")?.toInt() ?: return null
        val h = d.int("Height")?.toInt() ?: return null
        val bpc = (d.int("BitsPerComponent") ?: 8L).toInt()
        val cs = colorSpaceName(file, rev, d["ColorSpace"])
        val filters = StreamDecoder.filtersOf(d)
        val soft = d.has("SMask") || d.has("Mask")
        val dec = StreamDecoder.decode(st)
        return when {
            dec.stoppedAt == "DCTDecode" || dec.stoppedAt == "DCT" -> ExtractedImage(num, setOf(page), w, h, bpc, cs, filters, ImageKind.JPEG, dec.bytes, soft, st.dataLength)
            dec.stoppedAt == null -> ExtractedImage(num, setOf(page), w, h, bpc, cs, filters, ImageKind.RAW_PIXELS, dec.bytes, soft, st.dataLength)
            else -> ExtractedImage(num, setOf(page), w, h, bpc, cs, filters, ImageKind.OTHER_ENCODING, dec.bytes, soft, st.dataLength)
        }
    }

    private fun colorSpaceName(file: PdfFile, rev: Int, o: PdfObj?): String = when (val r = file.resolve(o, rev)) {
        is PdfName -> r.value
        is PdfArray -> (r[0] as? PdfName)?.value ?: "Unknown"
        else -> "Unknown"
    }
}
