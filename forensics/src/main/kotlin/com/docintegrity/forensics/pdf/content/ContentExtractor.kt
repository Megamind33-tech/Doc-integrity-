package com.docintegrity.forensics.pdf.content

import android.graphics.Path
import android.graphics.PointF
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import com.tom_roush.pdfbox.contentstream.PDFGraphicsStreamEngine
import com.tom_roush.pdfbox.cos.COSName
import com.tom_roush.pdfbox.pdmodel.PDDocument
import com.tom_roush.pdfbox.pdmodel.PDPage
import com.tom_roush.pdfbox.pdmodel.font.PDFont
import com.tom_roush.pdfbox.pdmodel.graphics.blend.BlendMode
import com.tom_roush.pdfbox.pdmodel.graphics.image.PDImage
import com.tom_roush.pdfbox.util.Matrix
import com.tom_roush.pdfbox.util.Vector

/**
 * Reads text (with positions and per-character fonts) and paint-ordered drawing operations from a PDF using
 * PdfBox-Android. The input bytes are only read.
 *
 * PdfBox-Android must have been initialised once per process with `PDFBoxResourceLoader.init(context)`.
 */
object ContentExtractor {

    val isAvailable: Boolean get() = PDFBoxResourceLoader.isReady()

    /** Strips the "ABCDEF+" subset prefix. */
    fun face(name: String?): String? = name?.replace(Regex("^[A-Z]{6}\\+"), "")

    fun extract(bytes: ByteArray, password: String = ""): DocumentContent {
        val doc = try { PDDocument.load(bytes, password) } catch (e: Exception) {
            return DocumentContent(emptyList(), listOf("PDF library could not open the file: ${e.javaClass.simpleName}: ${e.message}"), false)
        }
        doc.use {
            val pages = ArrayList<PageContent>()
            val docErrors = ArrayList<String>()
            for (i in 0 until it.numberOfPages) {
                val errs = ArrayList<String>()
                val page = it.getPage(i)
                val geom = Geometry(page)
                val words = ArrayList<WordInfo>()
                val ops = ArrayList<PaintOp>()
                try {
                    PaintScanner(page, geom, ops).processPage(page)
                } catch (e: Throwable) { errs.add("drawing scan failed on page ${i + 1}: ${e.javaClass.simpleName}") }
                // Words are rebuilt from the painted glyphs. Text hidden under a later opaque shape is not what a
                // reader sees: it is dropped here (one glyph for one covered glyph) and reported separately.
                words.addAll(GlyphWords.build(i, ops))
                pages.add(PageContent(i, geom.width, geom.height, geom.rotation, words, ops, errs))
            }
            return DocumentContent(pages, docErrors, it.isEncrypted)
        }
    }

    // ------------------------------------------------------------------------------------------------------------

    /** Maps PDF user space to top-left display space for one page (crop box origin + /Rotate). */
    class Geometry(page: PDPage) {
        private val box = page.cropBox
        private val bw = box.width.toDouble()
        private val bh = box.height.toDouble()
        val rotation = ((page.rotation % 360) + 360) % 360
        val width = if (rotation == 90 || rotation == 270) bh else bw
        val height = if (rotation == 90 || rotation == 270) bw else bh

        fun point(xu: Double, yu: Double): Pair<Double, Double> {
            val x = xu - box.lowerLeftX
            val y = yu - box.lowerLeftY
            return when (rotation) {
                90 -> y to x
                180 -> (bw - x) to y
                270 -> (bh - y) to (bw - x)
                else -> x to (bh - y)
            }
        }

        fun rect(pts: List<Pair<Double, Double>>): RectD {
            val d = pts.map { point(it.first, it.second) }
            return RectD(d.minOf { it.first }, d.minOf { it.second }, d.maxOf { it.first }, d.maxOf { it.second })
        }
    }

    /** Records drawing operations in PAINT ORDER so that "what was drawn on top of what" can be reasoned about. */
    private class PaintScanner(page: PDPage, private val geom: Geometry, private val out: MutableList<PaintOp>) : PDFGraphicsStreamEngine(page) {
        private var order = 0
        private val pathPts = ArrayList<Pair<Double, Double>>()
        private val pathRects = ArrayList<RectD>()
        private var onlyRects = true
        private var current = PointF(0f, 0f)

        private var runText = StringBuilder()
        private var runPts = ArrayList<Pair<Double, Double>>()
        private var runGlyphs = ArrayList<GlyphBox>()
        private var runFont: PDFont? = null
        private var runSize = 0f
        private var runBase = 0.0

        override fun showText(string: ByteArray) {
            runText = StringBuilder(); runPts = ArrayList(); runGlyphs = ArrayList(); runFont = null
            try { super.showText(string) } finally { flushRun() }
        }

        private fun flushRun() {
            if (runPts.isEmpty() || runText.isBlank()) return
            val gs = graphicsState
            val rgb = try { gs.nonStrokingColor.toRGB() and 0xFFFFFF } catch (e: Exception) { null }
            val mode = try { gs.textState.renderingMode.intValue() } catch (e: Exception) { 0 }
            out.add(TextOp(order++, geom.rect(runPts), runText.toString(), face(runFont?.name), runSize, mode, rgb, runBase, runGlyphs))
            runPts = ArrayList(); runText = StringBuilder(); runGlyphs = ArrayList()
        }

        override fun showGlyph(trm: Matrix, font: PDFont, code: Int, unicode: String?, displacement: Vector) {
            super.showGlyph(trm, font, code, unicode, displacement)
            val sx = trm.scalingFactorX.toDouble()
            val sy = trm.scalingFactorY.toDouble()
            val x = trm.translateX.toDouble()
            val y = trm.translateY.toDouble()
            val adv = displacement.x.toDouble() * sx
            val size = Math.abs(sy)
            val gp = listOf(x to (y - 0.2 * size), (x + adv) to (y + 0.8 * size))
            runPts.addAll(gp)
            runGlyphs.add(GlyphBox(unicode ?: "", geom.rect(gp), geom.point(x, y).second))
            runText.append(unicode ?: "")
            runFont = font; runSize = size.toFloat(); runBase = geom.point(x, y).second
        }

        // ---- paths ----------------------------------------------------------------------------------------------
        override fun appendRectangle(p0: PointF, p1: PointF, p2: PointF, p3: PointF) {
            val pts = listOf(p0, p1, p2, p3).map { it.x.toDouble() to it.y.toDouble() }
            pathRects.add(geom.rect(pts))
            pathPts.addAll(pts)
        }
        override fun moveTo(x: Float, y: Float) { onlyRects = false; pathPts.add(x.toDouble() to y.toDouble()); current = PointF(x, y) }
        override fun lineTo(x: Float, y: Float) { onlyRects = false; pathPts.add(x.toDouble() to y.toDouble()); current = PointF(x, y) }
        override fun curveTo(x1: Float, y1: Float, x2: Float, y2: Float, x3: Float, y3: Float) {
            onlyRects = false
            pathPts.add(x1.toDouble() to y1.toDouble()); pathPts.add(x2.toDouble() to y2.toDouble()); pathPts.add(x3.toDouble() to y3.toDouble())
            current = PointF(x3, y3)
        }
        override fun getCurrentPoint(): PointF = current
        override fun closePath() {}
        override fun clip(windingRule: Path.FillType) {}
        override fun endPath() = resetPath()
        override fun strokePath() = resetPath()
        override fun shadingFill(shadingName: COSName) {}

        override fun fillPath(windingRule: Path.FillType) { recordFill(); resetPath() }
        override fun fillAndStrokePath(windingRule: Path.FillType) { recordFill(); resetPath() }

        private fun recordFill() {
            if (pathPts.isEmpty()) return
            val gs = graphicsState
            val rgb = try { gs.nonStrokingColor.toRGB() and 0xFFFFFF } catch (e: Exception) { null }
            val opaque = gs.nonStrokeAlphaConstant >= 0.999 && gs.softMask == null && (gs.blendMode == BlendMode.NORMAL || gs.blendMode == BlendMode.COMPATIBLE || gs.blendMode == null)
            if (onlyRects && pathRects.isNotEmpty()) {
                for (r in pathRects) out.add(FillOp(order++, r, rgb, opaque, true))
            } else {
                out.add(FillOp(order++, geom.rect(pathPts), rgb, opaque, false))
            }
        }

        private fun resetPath() { pathPts.clear(); pathRects.clear(); onlyRects = true }

        // ---- images ---------------------------------------------------------------------------------------------
        override fun drawImage(image: PDImage) {
            val m = graphicsState.currentTransformationMatrix
            val a = m.getValue(0, 0).toDouble(); val b = m.getValue(0, 1).toDouble()
            val c = m.getValue(1, 0).toDouble(); val d = m.getValue(1, 1).toDouble()
            val e = m.getValue(2, 0).toDouble(); val f = m.getValue(2, 1).toDouble()
            val pts = listOf(0.0 to 0.0, 1.0 to 0.0, 1.0 to 1.0, 0.0 to 1.0).map { (x, y) -> (a * x + c * y + e) to (b * x + d * y + f) }
            out.add(ImageOp(order++, geom.rect(pts), image.width, image.height, image.isStencil, try { image.suffix } catch (e: Exception) { null }))
        }
    }
}
