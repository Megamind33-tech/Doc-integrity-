package com.docintegrity.forensics.image

import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.model.Region
import com.docintegrity.forensics.pdf.content.DocumentContent
import com.docintegrity.forensics.pdf.content.ImageOp
import com.docintegrity.forensics.pdf.images.ExtractedImage
import com.docintegrity.forensics.pdf.images.ImageKind
import com.docintegrity.forensics.pdf.images.PdfImageExtractor
import com.docintegrity.forensics.pdf.raw.PdfFile

class ImageForensicsResult(val findings: List<Finding>, val imagesExamined: Int)

/**
 * Traditional (non-learning) image checks on the pictures embedded in a PDF. Every output is an INDICATOR or
 * INFORMATION: none of these methods can prove that an image was edited, and each has documented blind spots
 * (see docs/DETECTION.md). No machine-learning model is used. Error-level analysis was evaluated and REJECTED: on the
 * scan fixtures it flagged 28-34 regions on every page including unedited controls (see docs/BENCHMARK.md).
 */
object ImageForensics {
    private const val MAX_PIXELS = 14_000_000L
    private const val MIN_ANALYSIS_SIDE = 400
    private const val QUALITY_GAP = 15
    private const val DPI_RATIO = 1.5

    private val EDITORS = Regex(
        "photoshop|gimp|paint\\.net|pixelmator|affinity|snapseed|lightroom|canva|picsart|illustrator|corel|paintshop|acorn|krita|" +
            "imagemagick|graphicsmagick|gd-jpeg|photoscape|fotor|photopea|microsoft photo|windows photo|picmonkey",
        RegexOption.IGNORE_CASE,
    )

    fun analyze(file: PdfFile, content: DocumentContent?): ImageForensicsResult {
        val findings = ArrayList<Finding>()
        val images = PdfImageExtractor.extract(file).images
        if (images.isEmpty()) return ImageForensicsResult(emptyList(), 0)

        // ---- 1. container facts for every JPEG -------------------------------------------------------------------
        val infos = images.filter { it.kind == ImageKind.JPEG }.mapNotNull { img -> JpegInspector.inspect(img.data)?.let { img to it } }
        if (infos.isNotEmpty()) {
            findings.add(
                Finding(
                    id = "IMG_JPEG_FACTS", area = Area.IMAGE, evidence = EvidenceClass.INFO,
                    title = "${infos.size} embedded JPEG image(s) inspected",
                    detected = infos.joinToString("\n") { (img, j) -> "obj ${img.objNum} (page ${img.pages.min() + 1}): ${j.width}×${j.height}, ${j.subsampling ?: "${j.components} component(s)"}, ${if (j.progressive) "progressive" else "baseline"}, " +
                        (j.ijgQuality?.let { "standard tables ≈ quality $it" } ?: "non-standard quantisation tables") + (j.exifSoftware?.let { ", software “$it”" } ?: "") },
                    establishes = "How each JPEG was written: compression tables, sampling and metadata.",
                    unknown = "Tables show the LAST compression only. Non-standard tables are normal for cameras, phones and some scanners.",
                ),
            )
            val traces = infos.filter { (_, j) -> j.photoshopResources || j.exifSoftware?.let { EDITORS.containsMatchIn(it) } == true || j.comments.any { EDITORS.containsMatchIn(it) } }
            if (traces.isNotEmpty()) {
                findings.add(
                    Finding(
                        id = "IMG_EDITOR_TRACE", area = Area.IMAGE, evidence = EvidenceClass.INFO,
                        title = "Image carries traces of an image-editing program",
                        detected = traces.joinToString("; ") { (img, j) -> "obj ${img.objNum}: " + listOfNotNull(j.exifSoftware?.let { "software “$it”" }, j.comments.firstOrNull { EDITORS.containsMatchIn(it) }?.let { "comment “${it.take(60)}”" }, if (j.photoshopResources) "Photoshop resource block" else null).joinToString(", ") },
                        establishes = "The image file records that an image editor or library handled it.",
                        unknown = "Editors are also used for cropping, resizing and compressing. Metadata can be edited or removed, so absence proves nothing.",
                    ),
                )
            }
            val trailing = infos.filter { (_, j) -> j.trailingBytes > 0 }
            if (trailing.isNotEmpty()) {
                findings.add(
                    Finding(
                        id = "IMG_TRAILING_DATA", area = Area.IMAGE, evidence = EvidenceClass.INDICATOR,
                        title = "Data after the end of a JPEG image",
                        detected = trailing.joinToString("; ") { (img, j) -> "obj ${img.objNum}: ${j.trailingBytes} byte(s) after the end-of-image marker" },
                        establishes = "The image stream contains bytes beyond the JPEG's end that no image viewer displays.",
                        unknown = "Some cameras append thumbnails or maker data; data can also be hidden there. The bytes were not interpreted.",
                    ),
                )
            }
            // consistency between images that share a page
            val byPage = infos.flatMap { (img, j) -> img.pages.map { it to (img to j) } }.groupBy({ it.first }, { it.second })
            val mismatches = ArrayList<String>()
            for ((pg, list) in byPage) {
                if (list.size < 2) continue
                val q = list.mapNotNull { (_, j) -> j.ijgQuality?.let { qq -> qq } }
                val diffQ = q.size >= 2 && (q.max() - q.min()) >= QUALITY_GAP
                val diffSub = list.map { (_, j) -> j.subsampling }.distinct().size > 1
                val mixStd = list.map { (_, j) -> j.ijgQuality != null }.distinct().size > 1
                if (diffQ || diffSub || mixStd) mismatches.add("page ${pg + 1}: " + list.joinToString(" vs ") { (img, j) -> "obj ${img.objNum} (${j.ijgQuality?.let { "q≈$it" } ?: "custom tables"}, ${j.subsampling ?: "?"})" })
            }
            if (mismatches.isNotEmpty()) {
                findings.add(
                    Finding(
                        id = "IMG_COMPRESSION_MISMATCH", area = Area.IMAGE, evidence = EvidenceClass.INFO,
                        title = "Images on one page were compressed differently",
                        detected = mismatches.joinToString("; "),
                        establishes = "Pictures on the same page carry different JPEG settings, i.e. they come from different sources or save operations.",
                        unknown = "A scan plus a separately photographed signature, logo or photo has exactly this pattern legitimately. It is context for the review of the page, not evidence of editing.",
                    ),
                )
            }
        }

        // ---- 2. images placed over a scan: resolution and stacking -----------------------------------------------------
        if (content != null) {
            val over = ArrayList<String>(); val regions = ArrayList<Region>()
            for (p in content.pages) {
                val area = p.width * p.height
                val scans = p.images.filter { !it.stencil && area > 0 && it.rect.area / area >= 0.6 }
                if (scans.isEmpty()) continue
                val base = scans.minBy { it.order }
                for (im in p.images) {
                    if (im === base || im.stencil || im.order < base.order || im.rect.area / area >= 0.6 || im.rect.area <= 0) continue
                    if (base.rect.intersectionArea(im.rect) / im.rect.area < 0.8) continue
                    val ratio = if (base.dpiX > 0) im.dpiX / base.dpiX else 1.0
                    val different = ratio > DPI_RATIO || ratio < 1 / DPI_RATIO
                    over.add("page ${p.index + 1}: a ${im.widthPx}×${im.heightPx} image at ${"%.0f".format(im.dpiX)} dpi lies on a scan at ${"%.0f".format(base.dpiX)} dpi" + if (different) " (resolutions differ ${"%.1f".format(maxOf(ratio, 1 / ratio))}×)" else "")
                    regions.add(im.rect.toRegion(p.index, p.width, p.height, label = "image placed over scan"))
                }
            }
            if (over.isNotEmpty()) {
                findings.add(
                    Finding(
                        id = "IMG_OVER_SCAN", area = Area.IMAGE, evidence = EvidenceClass.INDICATOR,
                        title = "A separate image is placed on top of a scanned page",
                        detected = over.joinToString("; "),
                        establishes = "These pictures are separate PDF objects drawn over the page scan, not part of it. A plain scan has one image per page.",
                        unknown = "Stamps, signatures, logos and received-marks are added this way legitimately; so is patching over scanned text. Different resolution marks the picture as coming from another source. Review the outlined area.",
                        regions = regions,
                    ),
                )
            }
        }

        // ---- 3. pixel analyses (need the platform decoder / codec) ---------------------------------------------------------
        val decoder = ImageDecoders.default
        if (decoder == null) {
            findings.add(limitation("no image decoder is available, so noise analysis did not run"))
            return ImageForensicsResult(findings, images.size)
        }
        var skippedLarge = 0; var examined = 0
        val noisy = ArrayList<Pair<ExtractedImage, NoiseResult>>()
        val notInformative = ArrayList<String>()
        for (img in images) {
            if (img.width < MIN_ANALYSIS_SIDE || img.height < MIN_ANALYSIS_SIDE) continue
            if (img.width.toLong() * img.height > MAX_PIXELS) { skippedLarge++; continue }
            val raster = img.toRaster { decoder.decode(it, maxOf(img.width, img.height)) } ?: continue
            examined++
            val nr = NoiseAnalysis.analyze(raster.gray())
            if (!nr.informative) notInformative.add("obj ${img.objNum}: ${nr.note}") else if (nr.lowNoiseRegions.isNotEmpty()) noisy.add(img to nr)
        }
        if (noisy.isNotEmpty()) {
            val regs = noisy.flatMap { (img, nr) -> toPage(content, img, nr.lowNoiseRegions, "no scan grain") }
            findings.add(
                Finding(
                    id = "IMG_NOISE_PATCH", area = Area.IMAGE, evidence = EvidenceClass.INDICATOR,
                    title = "Region without scan grain inside a grainy scan",
                    detected = noisy.joinToString("; ") { (img, nr) -> "obj ${img.objNum}: ${nr.note}" },
                    establishes = "Paper and scanner grain is present across this page, but these compact regions are almost perfectly smooth. Content drawn or filled digitally after scanning looks like this.",
                    unknown = "Large blank areas, stamps printed in flat ink, and scanner clean-up can also be smooth. A forger can add matching noise, so absence of this indicator proves nothing. Review the outlined area.",
                    regions = regs,
                ),
            )
        }
        if (notInformative.isNotEmpty()) {
            findings.add(
                Finding(
                    id = "IMG_NOISE_NOT_INFORMATIVE", area = Area.IMAGE, evidence = EvidenceClass.INFO,
                    title = "Noise analysis could not say anything about some images",
                    detected = notInformative.joinToString("; "),
                    establishes = "The image has too little grain for a noise comparison to mean anything.",
                    unknown = "This is not a clean result: where scanner software removes grain, digitally added content cannot be separated from the background by noise.",
                ),
            )
        }
        if (skippedLarge > 0) findings.add(limitation("$skippedLarge image(s) larger than ${MAX_PIXELS / 1_000_000} megapixels were not analysed for noise, to bound memory on this device"))
        return ImageForensicsResult(findings, examined)
    }

    private fun limitation(msg: String) = Finding(
        id = "IMG_LIMITED", area = Area.IMAGE, evidence = EvidenceClass.LIMITATION,
        title = "Image analysis was limited", detected = msg, establishes = "Some image checks did not run.", unknown = "What those checks would have shown.",
    )

    /** Maps pixel rectangles of [img] to page regions through the image's placement on the page. */
    private fun toPage(content: DocumentContent?, img: ExtractedImage, rects: List<PxRect>, label: String): List<Region> {
        if (content == null) return emptyList()
        val out = ArrayList<Region>()
        for (pg in img.pages) {
            val p = content.pages.getOrNull(pg) ?: continue
            val op = p.ops.filterIsInstance<ImageOp>().firstOrNull { it.widthPx == img.width && it.heightPx == img.height } ?: continue
            for (r in rects) {
                val x = op.rect.x0 + r.x0.toDouble() / img.width * op.rect.w; val y = op.rect.y0 + r.y0.toDouble() / img.height * op.rect.h
                out.add(Region(pg, x, y, r.w.toDouble() / img.width * op.rect.w, r.h.toDouble() / img.height * op.rect.h, p.width, p.height, com.docintegrity.forensics.model.Side.SUBMITTED, label))
            }
        }
        return out
    }
}
