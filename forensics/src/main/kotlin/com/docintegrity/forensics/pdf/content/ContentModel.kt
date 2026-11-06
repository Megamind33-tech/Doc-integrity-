package com.docintegrity.forensics.pdf.content

import com.docintegrity.forensics.model.Region
import com.docintegrity.forensics.model.Side

/** Axis-aligned rectangle in DISPLAY space: PDF points, origin at the top-left of the page as shown (rotation applied). */
data class RectD(val x0: Double, val y0: Double, val x1: Double, val y1: Double) {
    val w get() = x1 - x0
    val h get() = y1 - y0
    val area get() = maxOf(0.0, w) * maxOf(0.0, h)

    fun intersectionArea(o: RectD): Double {
        val ix = minOf(x1, o.x1) - maxOf(x0, o.x0)
        val iy = minOf(y1, o.y1) - maxOf(y0, o.y0)
        return if (ix > 0 && iy > 0) ix * iy else 0.0
    }

    fun union(o: RectD) = RectD(minOf(x0, o.x0), minOf(y0, o.y0), maxOf(x1, o.x1), maxOf(y1, o.y1))

    fun toRegion(page: Int, pw: Double, ph: Double, side: Side = Side.SUBMITTED, label: String = "") =
        Region(page, x0, y0, w, h, pw, ph, side, label)
}

class CharFont(val ch: String, val face: String)

/** One word as the text extractor reconstructed it, with its position and the font of every character. */
class WordInfo(
    val page: Int,
    val line: Int,
    val text: String,
    val rect: RectD,
    val fontSize: Float,
    val chars: List<CharFont>,
) {
    val faces: Set<String> get() = chars.map { it.face }.toSet()
}

sealed class PaintOp(val order: Int, val rect: RectD)

class GlyphBox(val ch: String, val rect: RectD, val baseline: Double = rect.y1)

class TextOp(
    order: Int, rect: RectD,
    val text: String,
    val face: String?,
    val fontSize: Float,
    /** PDF text rendering mode: 0 = fill (visible), 3 = invisible, etc. */
    val renderMode: Int,
    /** 0xRRGGBB of the fill colour when determinable. */
    val rgb: Int?,
    /** Baseline y in display space. */
    val baselineY: Double,
    val glyphs: List<GlyphBox> = emptyList(),
) : PaintOp(order, rect)

class FillOp(
    order: Int, rect: RectD,
    val rgb: Int?,
    /** True when constant alpha is 1 and no soft mask / non-normal blend mode could make the fill see-through. */
    val opaque: Boolean,
    /** True when the filled path was one or more plain rectangles. */
    val pureRect: Boolean,
) : PaintOp(order, rect)

class ImageOp(
    order: Int, rect: RectD,
    val widthPx: Int, val heightPx: Int,
    val stencil: Boolean,
    val suffix: String?,
) : PaintOp(order, rect) {
    /** Effective resolution of the image as placed on the page. */
    val dpiX: Double get() = if (rect.w > 0) widthPx / (rect.w / 72.0) else 0.0
    val dpiY: Double get() = if (rect.h > 0) heightPx / (rect.h / 72.0) else 0.0
}

class PageContent(
    val index: Int,
    val width: Double,
    val height: Double,
    val rotation: Int,
    val words: List<WordInfo>,
    val ops: List<PaintOp>,
    val errors: List<String>,
) {
    /** Reading-order text: words separated by spaces, lines by newlines. */
    val text: String by lazy {
        val sb = StringBuilder()
        var lastLine = -1
        for (w in words) {
            if (lastLine != -1) sb.append(if (w.line != lastLine) '\n' else ' ')
            sb.append(w.text)
            lastLine = w.line
        }
        sb.toString()
    }
    val images get() = ops.filterIsInstance<ImageOp>()
    val textOps get() = ops.filterIsInstance<TextOp>()
}

class DocumentContent(val pages: List<PageContent>, val errors: List<String>, val encryptedButReadable: Boolean) {
    val text: String get() = pages.joinToString("\n\n") { it.text }
    val wordCount: Int get() = pages.sumOf { it.words.size }
}
