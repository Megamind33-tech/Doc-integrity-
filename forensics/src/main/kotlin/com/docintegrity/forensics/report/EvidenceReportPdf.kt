package com.docintegrity.forensics.report

import com.docintegrity.forensics.engine.ForensicReport
import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.model.Verdict
import com.tom_roush.pdfbox.pdmodel.PDDocument
import com.tom_roush.pdfbox.pdmodel.PDDocumentNameDictionary
import com.tom_roush.pdfbox.pdmodel.PDEmbeddedFilesNameTreeNode
import com.tom_roush.pdfbox.pdmodel.PDPage
import com.tom_roush.pdfbox.pdmodel.PDPageContentStream
import com.tom_roush.pdfbox.pdmodel.common.PDRectangle
import com.tom_roush.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification
import com.tom_roush.pdfbox.pdmodel.common.filespecification.PDEmbeddedFile
import com.tom_roush.pdfbox.pdmodel.font.PDFont
import com.tom_roush.pdfbox.pdmodel.font.PDType1Font
import com.tom_roush.pdfbox.pdmodel.graphics.image.PDImageXObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Calendar
import java.util.TimeZone

/** A rendered page with review regions already drawn on it (supplied by the platform layer). */
class PageSnapshot(val caption: String, val imageBytes: ByteArray)

/**
 * Builds the exportable PDF evidence report with PdfBox-Android (no platform PDF classes, so the output can be
 * re-opened and checked in tests). The report restates the category, every finding with its three statements, the
 * limitations and the reproducibility data, and embeds the machine-readable JSON as a file attachment.
 *
 * The report is deliberately titled and footed as NOT a certificate: it must not be usable to vouch for a document.
 */
object EvidenceReportPdf {
    private const val MARGIN = 48f
    private val REGULAR: PDFont get() = PDType1Font.HELVETICA
    private val BOLD: PDFont get() = PDType1Font.HELVETICA_BOLD
    private val MONO: PDFont get() = PDType1Font.COURIER

    /** PDF standard fonts use WinAnsi: map typographic characters to ASCII and replace what cannot be shown. */
    fun sanitize(s: String): String {
        val sb = StringBuilder(s.length)
        for (c in s) sb.append(
            when (c) {
                '→' -> "->"; '←' -> "<-"; '≠' -> "!="; '≈' -> "~"; '≤' -> "<="; '≥' -> ">="
                '…' -> "..."; '·' -> "-"; '−' -> "-"; '–', '—' -> "-"
                '“', '”', '„' -> "\""; '‘', '’' -> "'"; '×' -> "x"
                '•', '●' -> "*"; '\n', '\r', '\t' -> " "; ' ' -> " "
                else -> if (c.code in 32..126 || c.code in 0xA1..0xFF) c.toString() else "?"
            },
        )
        return sb.toString()
    }

    fun build(report: ForensicReport, json: String = ReportJson.toJson(report), snapshots: List<PageSnapshot> = emptyList()): ByteArray {
        PDDocument().use { doc ->
            val w = Writer(doc)
            writeBody(w, report, snapshots)
            w.finish(report)
            attachJson(doc, json, report)
            doc.documentInformation.apply {
                title = "Forensic analysis report - ${sanitize(report.fileName)}"
                subject = "Not a certificate of authenticity"
                producer = "${report.tool.name} ${report.tool.version}"
                creator = "${report.tool.name} (ruleset ${report.tool.rulesetVersion})"
                keywords = "sha256:${report.hashes.sha256}"
            }
            val bo = ByteArrayOutputStream()
            doc.save(bo)
            return bo.toByteArray()
        }
    }

    // ------------------------------------------------------------------------------------------------------------

    private fun verdictRgb(v: Verdict) = when (v) {
        Verdict.CONFIRMED_CHANGE -> intArrayOf(179, 38, 30)
        Verdict.SUSPICIOUS_INDICATORS -> intArrayOf(154, 91, 0)
        Verdict.NO_INDICATORS_DETECTED -> intArrayOf(63, 94, 125)
        Verdict.INCONCLUSIVE -> intArrayOf(94, 90, 117)
    }

    private fun writeBody(w: Writer, r: ForensicReport, snapshots: List<PageSnapshot>) {
        w.text("Forensic analysis report", BOLD, 22f)
        w.text("This is an analysis of what could be shown from the file. It is NOT a certificate of authenticity.", BOLD, 10.5f, rgb = intArrayOf(179, 38, 30))
        w.gap(6f)
        w.kv("File", r.fileName); w.kv("SHA-256", r.hashes.sha256, mono = true); w.kv("Analysed", "${r.tool.analysedAtIso} by ${r.tool.name} ${r.tool.version} (ruleset ${r.tool.rulesetVersion})")
        w.gap(8f)

        val rgb = verdictRgb(r.verdict.verdict)
        w.box(rgb) { b ->
            b.text("REPORT CATEGORY", BOLD, 8.5f, rgb)
            b.text(r.verdict.verdict.label, BOLD, 18f)
            b.text(r.verdict.verdict.summary, REGULAR, 10.5f)
            b.gap(4f)
            b.text("Why this category", BOLD, 9.5f, rgb)
            r.verdict.reasons.forEach { b.bullet(it, 9.5f) }
            b.gap(3f)
            b.text("No probability or confidence score is given: none of these checks has been statistically calibrated.", REGULAR, 8.5f)
        }

        w.section("1. Document overview")
        w.kv("Size", "${r.hashes.size} bytes"); w.kv("SHA-512", r.hashes.sha512, mono = true); w.kv("SHA-1", r.hashes.sha1, mono = true); w.kv("MD5", r.hashes.md5, mono = true)
        if (r.isPdf) {
            w.kv("PDF version", r.pdfVersion ?: "unknown"); w.kv("Pages", r.pageCount.toString())
            w.kv("Revisions", if (r.revisions.size <= 1) "1 (no incremental updates)" else "${r.revisions.size} (${r.revisions.size - 1} incremental update(s))")
            r.metadata?.let { m ->
                m.info["Creator"]?.let { w.kv("Creator", it) }; m.info["Producer"]?.let { w.kv("Producer", it) }
                m.creationDate?.let { w.kv("Created", it.display()) }; m.modDate?.let { w.kv("Modified", it.display()) }
            }
        } else w.para("The file is not a PDF; only fingerprints were computed.")
        r.revisions.filter { it.index > 0 || r.revisions.size > 1 }.forEach { v -> w.kv("Version ${v.index}", "bytes ${v.startOffset}-${v.endOffset}, SHA-256 ${v.prefixSha256}", mono = false) }

        findingsSection(w, "2. Creation-tool and metadata evidence", r.findings.filter { it.area == Area.CREATION_TOOL || it.area == Area.METADATA }, "Labels are self-asserted and can be edited or forged. Use of a tool is not evidence of falsification.")

        w.section("3. Signature information")
        if (r.signatures.isEmpty()) w.para("No digital signatures were found, so there is no cryptographic evidence to check integrity against.")
        for (s in r.signatures) {
            w.subheading((if (s.timestampOnly) "Document timestamp " else "Signature ") + (s.fieldName ?: "#${s.index + 1}") + (s.signerCn?.let { " - $it" } ?: ""))
            w.kv("1. Integrity", "${s.crypto.label}. ${s.cryptoDetail}")
            w.kv("2. Certificate", "${s.trustAtSigning?.status?.label ?: "not evaluated"}. Trust set: ${r.trust.description}")
            s.revocation?.let { w.kv("Revocation", "${it.status.label}. ${it.detail}") }
            w.kv("3. After signing", if (s.laterRevisions == 0 && s.bytesAfterSignature <= 2) "nothing appended" else s.laterChanges.groupBy { it.cls }.entries.joinToString("; ") { "${it.value.size} ${it.key.label}" }.ifEmpty { "${s.bytesAfterSignature} bytes appended" })
            s.claimedTime?.let { w.kv("Claimed time", "$it (the signer's own claim unless a verified timestamp is shown)") }
            s.timestampNote?.let { w.kv("Timestamp", it) }
            if (s.byteRangeProblems.isNotEmpty()) w.kv("Irregular range", s.byteRangeProblems.joinToString("; "))
        }
        w.para("A valid signature does not show that the signed information is true: a document made with false information and then signed still verifies.", italic = true)
        r.findings.filter { it.area == Area.SIGNATURE && it.evidence != EvidenceClass.INFO }.forEach { w.finding(it) }

        findingsSection(w, "4. Editing and revision indicators", r.findings.filter { it.area == Area.REVISIONS || it.area == Area.STRUCTURE || it.area == Area.CONTENT || it.area == Area.FONTS }, "Indicators are prompts for human review, not proof of manipulation.")

        w.section("5. File comparison (original versus submitted)")
        val c = r.comparison
        if (c?.referenceKind != null) {
            w.kv("Reference", "${c.referenceName ?: "supplied value"} (${c.referenceKind.label}); supplied by the examiner and unverified by this tool")
            w.kv("File bytes", when (c.bytesIdentical) { com.docintegrity.forensics.compare.Tri.YES -> "identical to the reference"; com.docintegrity.forensics.compare.Tri.NO -> "different from the reference"; else -> "not compared" })
            w.kv("Document meaning", when (c.meaningChanged) { com.docintegrity.forensics.compare.Tri.YES -> "differences found"; com.docintegrity.forensics.compare.Tri.NO -> "no difference found in text, names, dates, amounts, numbers or pictures"; else -> "not assessed" })
            c.sideBySide?.takeIf { c.textHunks.isNotEmpty() }?.let {
                w.subheading("Side-by-side differences")
                c.textHunks.take(30).forEach { h -> w.bullet("${if (h.page >= 0) "page ${h.page + 1}: " else ""}${h.referenceText.ifEmpty { "(nothing)" }}  ->  ${h.submittedText.ifEmpty { "(removed)" }}", 9.5f) }
            }
        } else w.para("No trusted original, hash or issuer record was supplied. The original contents of this document are therefore unknown to this tool, and no statement about them is made.")
        r.findings.filter { it.area == Area.COMPARISON }.forEach { w.finding(it) }

        findingsSection(w, "6. Images and scans", r.findings.filter { it.area == Area.IMAGE }, "Image indicators are never proof of editing; each method has documented blind spots.")

        val regions = r.findings.flatMap { f -> f.regions.map { f to it } }
        w.section("7. Highlighted regions requiring review")
        if (regions.isEmpty()) w.para("No regions were highlighted.")
        else regions.take(60).forEach { (f, g) -> w.bullet("page ${g.page + 1} (${g.side.name.lowercase()}): x ${"%.0f".format(g.x)}, y ${"%.0f".format(g.y)}, ${"%.0f".format(g.w)} x ${"%.0f".format(g.h)} pt - ${g.label.ifEmpty { f.title }}", 9.5f) }
        for (s in snapshots) { w.image(s.imageBytes, s.caption) }

        w.section("8. Limitations")
        r.standingLimitations.forEach { w.bullet(it, 9.5f) }
        val lim = r.findings.filter { it.evidence == EvidenceClass.LIMITATION }
        if (lim.isNotEmpty()) { w.subheading("Specific to this file"); lim.forEach { w.bullet("${it.title}: ${it.unknown}", 9.5f) } }

        w.section("9. Reproducibility")
        w.kv("Tool", "${r.tool.name} ${r.tool.version}"); w.kv("Ruleset", r.tool.rulesetVersion); w.kv("PDF library", r.tool.pdfboxAndroid); w.kv("Crypto library", r.tool.bouncyCastle)
        w.kv("Trust set", r.trust.description); w.kv("Checks run", r.checksRun.joinToString("; "))
        w.para("The complete findings are attached to this PDF as report.json (schema ${ReportJson.SCHEMA}). The examined document itself is not included.", italic = true)
    }

    private fun findingsSection(w: Writer, title: String, list: List<Finding>, caveat: String) {
        w.section(title)
        w.para(caveat, italic = true)
        if (list.isEmpty()) { w.para("Nothing to report in this area."); return }
        for (cls in listOf(EvidenceClass.ESTABLISHED, EvidenceClass.INDICATOR, EvidenceClass.LIMITATION, EvidenceClass.INFO)) {
            val items = list.filter { it.evidence == cls }
            if (items.isEmpty()) continue
            items.forEach { w.finding(it) }
        }
    }

    private fun attachJson(doc: PDDocument, json: String, r: ForensicReport) {
        val bytes = json.toByteArray(Charsets.UTF_8)
        val ef = PDEmbeddedFile(doc, ByteArrayInputStream(bytes))
        ef.subtype = "application/json"; ef.size = bytes.size
        ef.creationDate = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        val fs = PDComplexFileSpecification()
        fs.file = "report.json"; fs.embeddedFile = ef; fs.fileDescription = "Machine-readable findings (${ReportJson.SCHEMA})"
        val tree = PDEmbeddedFilesNameTreeNode()
        tree.names = mapOf("report.json" to fs)
        val names = PDDocumentNameDictionary(doc.documentCatalog)
        names.embeddedFiles = tree
        doc.documentCatalog.names = names
    }

    // ------------------------------------------------------------------------------------------------------------

    /** Minimal flowing-text writer with automatic page breaks and a footer on every page. */
    private class Writer(val doc: PDDocument) {
        val pageW = PDRectangle.A4.width; val pageH = PDRectangle.A4.height
        val width = pageW - 2 * MARGIN
        var page = PDPage(PDRectangle.A4); var cs: PDPageContentStream; var y = pageH - MARGIN
        private val pages = ArrayList<PDPage>()

        init { doc.addPage(page); pages.add(page); cs = PDPageContentStream(doc, page) }

        private fun newPage() {
            cs.close()
            page = PDPage(PDRectangle.A4); doc.addPage(page); pages.add(page); cs = PDPageContentStream(doc, page); y = pageH - MARGIN
        }

        fun ensure(h: Float) { if (y - h < MARGIN + 24f) newPage() }
        fun gap(h: Float) { y -= h }

        fun wrap(text: String, font: PDFont, size: Float, maxW: Float): List<String> {
            val clean = sanitize(text)
            val out = ArrayList<String>()
            var line = StringBuilder()
            fun widthOf(s: String) = font.getStringWidth(s) / 1000f * size
            for (word in clean.split(' ').filter { it.isNotEmpty() }) {
                var w = word
                while (widthOf(w) > maxW) {           // hard-break tokens (long hashes) that cannot fit on a line
                    if (line.isNotEmpty()) { out.add(line.toString()); line = StringBuilder() }
                    var n = w.length
                    while (n > 1 && widthOf(w.substring(0, n)) > maxW) n--
                    out.add(w.substring(0, n)); w = w.substring(n)
                }
                val cand = if (line.isEmpty()) w else "$line $w"
                if (widthOf(cand) <= maxW) { line = StringBuilder(cand) } else { out.add(line.toString()); line = StringBuilder(w) }
            }
            if (line.isNotEmpty()) out.add(line.toString())
            return out.ifEmpty { listOf("") }
        }

        fun text(s: String, font: PDFont, size: Float, rgb: IntArray = intArrayOf(25, 28, 32), indent: Float = 0f, maxW: Float = width - indent, x0: Float = MARGIN) {
            for (ln in wrap(s, font, size, maxW)) {
                ensure(size * 1.35f)
                y -= size * 1.2f
                cs.beginText(); cs.setFont(font, size); cs.setNonStrokingColor(rgb[0], rgb[1], rgb[2])
                cs.newLineAtOffset(x0 + indent, y); cs.showText(ln); cs.endText()
                y -= size * 0.15f
            }
        }

        fun para(s: String, italic: Boolean = false) { text(s, REGULAR, 9.5f, rgb = if (italic) intArrayOf(80, 86, 96) else intArrayOf(25, 28, 32)); gap(3f) }
        fun bullet(s: String, size: Float = 9.5f) { text("* $s", REGULAR, size, indent = 8f, maxW = width - 8f) }
        fun subheading(s: String) { gap(4f); text(s, BOLD, 10.5f); }
        fun section(s: String) {
            ensure(60f); gap(14f)
            text(s.uppercase(), BOLD, 11.5f, rgb = intArrayOf(31, 78, 140))
            ensure(6f)
            cs.setStrokingColor(31, 78, 140); cs.setLineWidth(0.8f); cs.moveTo(MARGIN, y - 2f); cs.lineTo(pageW - MARGIN, y - 2f); cs.stroke()
            gap(6f)
        }

        fun kv(k: String, v: String, mono: Boolean = false) {
            val keyW = 96f
            val lines = wrap(v, if (mono) MONO else REGULAR, if (mono) 8.5f else 9.5f, width - keyW - 6f)
            ensure(12f)
            val top = y
            cs.beginText(); cs.setFont(BOLD, 9f); cs.setNonStrokingColor(80, 86, 96); cs.newLineAtOffset(MARGIN, y - 10.5f); cs.showText(sanitize(k).take(24)); cs.endText()
            for (ln in lines) {
                ensure(12f)
                y -= 11.5f
                cs.beginText(); cs.setFont(if (mono) MONO else REGULAR, if (mono) 8.5f else 9.5f); cs.setNonStrokingColor(25, 28, 32)
                cs.newLineAtOffset(MARGIN + keyW + 6f, y); cs.showText(ln); cs.endText()
            }
            if (top == y) y -= 11.5f
            y -= 2.5f
        }

        fun finding(f: Finding) {
            ensure(70f)
            val rgb = when (f.evidence) { EvidenceClass.ESTABLISHED -> intArrayOf(179, 38, 30); EvidenceClass.INDICATOR -> intArrayOf(154, 91, 0); EvidenceClass.LIMITATION -> intArrayOf(94, 90, 117); EvidenceClass.INFO -> intArrayOf(92, 102, 112) }
            gap(5f)
            text("[${f.evidence.label.uppercase()}] ${f.title}", BOLD, 10f, rgb = rgb)
            labelled("Detected", f.detected); labelled("Establishes", f.establishes); labelled("Unknown", f.unknown)
            if (f.regions.isNotEmpty()) text("${f.regions.size} highlighted region(s) require review (section 7).", REGULAR, 9f, indent = 10f, rgb = rgb)
        }

        private fun labelled(label: String, body: String) {
            text("$label: ", BOLD, 9f, indent = 10f, rgb = intArrayOf(80, 86, 96))
            y += 1f
            text(body.lines().take(12).joinToString("  |  "), REGULAR, 9.5f, indent = 18f, maxW = width - 18f)
        }

        /** Draws a tinted panel around [content]: the content is measured first (dry run), then drawn on top of the panel. */
        fun box(rgb: IntArray, content: (Sink) -> Unit) {
            ensure(120f)
            val dry = DryRun(this)
            content(dry)
            val h = dry.height + 18f
            ensure(minOf(h, pageH - 2 * MARGIN - 40f))
            val top = y
            cs.setNonStrokingColor(rgb[0], rgb[1], rgb[2]); cs.addRect(MARGIN - 8f, top - h, 4f, h); cs.fill()
            cs.setNonStrokingColor(rgb[0] / 4 + 190, rgb[1] / 4 + 190, rgb[2] / 4 + 190)
            cs.addRect(MARGIN - 4f, top - h, width + 12f, h); cs.fill()
            y -= 9f
            content(object : Sink {
                override fun text(s: String, font: PDFont, size: Float, rgb: IntArray, indent: Float) = this@Writer.text(s, font, size, rgb, indent)
                override fun gap(h: Float) = this@Writer.gap(h)
                override fun bullet(s: String, size: Float) = this@Writer.bullet(s, size)
            })
            y = top - h - 6f
        }

        fun image(bytes: ByteArray, caption: String) {
            try {
                val img = PDImageXObject.createFromByteArray(doc, bytes, caption)
                val maxW = width; val scale = minOf(1f, maxW / img.width, 330f / img.height)
                val w = img.width * scale; val h = img.height * scale
                ensure(h + 24f)
                text(caption, BOLD, 9f)
                y -= h
                cs.drawImage(img, MARGIN, y, w, h)
                gap(8f)
            } catch (e: Exception) { text("(page image could not be embedded: $caption)", REGULAR, 9f) }
        }

        fun finish(r: ForensicReport) {
            cs.close()
            val total = pages.size
            for ((i, p) in pages.withIndex()) {
                PDPageContentStream(doc, p, PDPageContentStream.AppendMode.APPEND, true, true).use { f ->
                    f.beginText(); f.setFont(REGULAR, 7.5f); f.setNonStrokingColor(110, 116, 126)
                    f.newLineAtOffset(MARGIN, 26f)
                    f.showText(sanitize("Forensic analysis, not a certificate of authenticity. File SHA-256 ${r.hashes.sha256.take(16)}...  Page ${i + 1} of $total"))
                    f.endText()
                }
            }
        }
    }

    private interface Sink {
        fun text(s: String, font: PDFont, size: Float, rgb: IntArray = intArrayOf(25, 28, 32), indent: Float = 0f)
        fun gap(h: Float)
        fun bullet(s: String, size: Float = 9.5f)
    }

    /** Measures text height without drawing, mirroring the Writer's layout arithmetic (line = 1.35 x font size). */
    private class DryRun(val w: Writer) : Sink {
        var height = 0f
        override fun text(s: String, font: PDFont, size: Float, rgb: IntArray, indent: Float) { height += w.wrap(s, font, size, w.width - indent).size * size * 1.35f }
        override fun gap(h: Float) { height += h }
        override fun bullet(s: String, size: Float) = text("* $s", REGULAR, size, indent = 8f)
    }
}
