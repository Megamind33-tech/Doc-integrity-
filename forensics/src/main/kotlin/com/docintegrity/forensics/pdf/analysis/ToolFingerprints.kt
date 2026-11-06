package com.docintegrity.forensics.pdf.analysis

enum class ToolCategory(val label: String) {
    WORD_PROCESSOR("Word processor / typesetting"),
    PDF_EDITOR("PDF editor / manipulation tool"),
    PDF_GENERATOR("PDF generation library / print path"),
    CONVERTER("Document converter / optimiser"),
    SCANNER_OCR("Scanning / OCR software or device"),
    SIGNING("Signing / e-signature service"),
}

data class ToolClue(
    val category: ToolCategory,
    val tool: String,
    /** Which metadata field matched ("Info /Producer", "XMP xmp:CreatorTool", ...). */
    val field: String,
    val matchedText: String,
    /** Plain-language caveat for this specific clue. */
    val caution: String,
)

/**
 * Rule-based recognition of software names in Creator / Producer / CreatorTool strings.
 *
 * A match means the file *carries a label that is consistent with* that software. Labels are self-asserted and can
 * be edited or forged; they are context, not proof of anything. Every clue ships with a caution string that the UI
 * and the exported report print verbatim.
 */
object ToolFingerprints {

    private class Rule(val category: ToolCategory, val tool: String, val pattern: Regex, val caution: String)

    private const val BENIGN_WORD = "Documents exported from word processors are ordinary and very common; this label alone does not indicate alteration."
    private const val EDITOR_CAUTION = "PDF editors are used for many legitimate purposes (merging, compressing, signing, form filling). Use of an editor does not by itself show that content was changed."
    private const val LIB_CAUTION = "Libraries and print paths are how most PDFs are produced automatically; this label does not indicate alteration."
    private const val CONV_CAUTION = "Converters and optimisers rewrite files wholesale, which can remove earlier revision history. That is also what ordinary compression does; it is not evidence of manipulation."
    private const val SCAN_CAUTION = "Scanning software produces image-based PDFs. A scan reproduces whatever was on the paper; it says nothing about whether the paper's content was genuine."

    private fun r(c: ToolCategory, tool: String, re: String, caution: String) =
        Rule(c, tool, Regex(re, RegexOption.IGNORE_CASE), caution)

    private val rules: List<Rule> = listOf(
        // --- Word processors / typesetting -----------------------------------------------------------------
        r(ToolCategory.WORD_PROCESSOR, "Microsoft Word", """microsoft[®(r)\s:]*\s*(office\s+)?word|word\s+for\s+microsoft\s*365|\bmicrosoft\s*365\b.*word""", BENIGN_WORD),
        r(ToolCategory.WORD_PROCESSOR, "LibreOffice / OpenOffice Writer", """libreoffice|openoffice|\b(writer|impress|calc)\b""", BENIGN_WORD),
        r(ToolCategory.PDF_EDITOR, "LibreOffice Draw (also the usual free route for opening and re-exporting a PDF)", """\bdraw\b""", EDITOR_CAUTION),
        r(ToolCategory.WORD_PROCESSOR, "Apple Pages / Keynote / Numbers", """\b(pages|keynote|numbers)\b""", BENIGN_WORD),
        r(ToolCategory.WORD_PROCESSOR, "Google Docs", """google\s*docs""", BENIGN_WORD),
        r(ToolCategory.WORD_PROCESSOR, "WPS Office", """\bwps\b""", BENIGN_WORD),
        r(ToolCategory.WORD_PROCESSOR, "LaTeX / TeX", """pdftex|xetex|luatex|latex|dvipdfm""", BENIGN_WORD),
        r(ToolCategory.WORD_PROCESSOR, "Adobe InDesign / Illustrator / FrameMaker", """indesign|illustrator|framemaker""", BENIGN_WORD),
        r(ToolCategory.WORD_PROCESSOR, "Scribus / QuarkXPress", """scribus|quarkxpress""", BENIGN_WORD),
        // --- PDF editors / manipulation --------------------------------------------------------------------
        r(ToolCategory.PDF_EDITOR, "Adobe Acrobat", """adobe\s+acrobat|acrobat\s+(pro|reader|dc)|acrobat\s+pdfmaker""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "Adobe PDF Library (Acrobat/Distiller engine)", """adobe\s+pdf\s+library|acrobat\s+distiller""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "Foxit", """foxit""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "Nitro PDF", """nitro""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "PDF-XChange / Tracker Software", """pdf-xchange|tracker\s+software""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "PDFescape", """pdfescape""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "Sejda", """sejda""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "PDFelement / Wondershare", """pdfelement|wondershare""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "pdfFiller", """pdffiller""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "Soda PDF / Lulu Software", """soda\s*pdf|lulu\s+software""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "Master PDF Editor", """master\s*pdf""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "PDFsam", """pdfsam""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "pdftk", """pdftk""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "pdf-lib (JavaScript; used by many web editors)", """pdf-lib""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "PyMuPDF / MuPDF", """pymupdf|\bmupdf\b""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "pikepdf / qpdf", """pikepdf|\bqpdf\b""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "pypdf / PyPDF2", """pypdf2?|\bpdfrw\b""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "iText", """itext""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "Apache PDFBox", """pdfbox""", EDITOR_CAUTION),
        r(ToolCategory.PDF_EDITOR, "PDFtron / Apryse", """pdftron|apryse""", EDITOR_CAUTION),
        // --- Converters / online services / optimisers -----------------------------------------------------
        r(ToolCategory.CONVERTER, "iLovePDF", """ilovepdf""", CONV_CAUTION),
        r(ToolCategory.CONVERTER, "Smallpdf", """smallpdf""", CONV_CAUTION),
        r(ToolCategory.CONVERTER, "PDF24", """pdf24""", CONV_CAUTION),
        r(ToolCategory.CONVERTER, "Online2PDF / Zamzar / CloudConvert / Convertio", """online2pdf|zamzar|cloudconvert|convertio|pdfcandy|pdf2go""", CONV_CAUTION),
        r(ToolCategory.CONVERTER, "Ghostscript", """ghostscript|\bgs\s+\d""", CONV_CAUTION),
        r(ToolCategory.CONVERTER, "Adobe PDF Services / Express", """adobe\s+pdf\s+services|adobe\s+express""", CONV_CAUTION),
        r(ToolCategory.CONVERTER, "Generic converter", """\bconverter\b|\bconverted\b""", CONV_CAUTION),
        // --- Generation libraries / print paths ------------------------------------------------------------
        r(ToolCategory.PDF_GENERATOR, "Chrome / Chromium (Skia/PDF)", """skia/pdf|chrom(e|ium)""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "macOS Quartz PDFContext", """quartz\s+pdfcontext""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "Microsoft Print to PDF", """print\s+to\s+pdf""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "ReportLab", """reportlab""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "FPDF / TCPDF / Dompdf", """fpdf|tcpdf|dompdf""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "wkhtmltopdf / Qt", """wkhtmltopdf|\bqt\s+\d""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "Cairo", """\bcairo\b""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "Prince / WeasyPrint / Apache FOP", """prince|weasyprint|apache\s+fop""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "PDFCreator / Bullzip / CutePDF / doPDF", """pdfcreator|bullzip|cutepdf|dopdf|primopdf""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "jsPDF / PDFKit / pdfmake", """jspdf|pdfkit|pdfmake""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "Aspose / Syncfusion / IronPDF", """aspose|syncfusion|ironpdf""", LIB_CAUTION),
        r(ToolCategory.PDF_GENERATOR, "CUPS", """\bcups\b""", LIB_CAUTION),
        // --- Scanning / OCR ----------------------------------------------------------------------------------
        r(ToolCategory.SCANNER_OCR, "Adobe Scan", """adobe\s+scan""", SCAN_CAUTION),
        r(ToolCategory.SCANNER_OCR, "CamScanner / Genius Scan / Microsoft Lens", """camscanner|genius\s*scan|office\s+lens|microsoft\s+lens""", SCAN_CAUTION),
        r(ToolCategory.SCANNER_OCR, "ABBYY FineReader", """abbyy|finereader""", SCAN_CAUTION),
        r(ToolCategory.SCANNER_OCR, "Readiris / OmniPage / PaperPort / Kofax", """readiris|omnipage|paperport|kofax""", SCAN_CAUTION),
        r(ToolCategory.SCANNER_OCR, "Tesseract / OCRmyPDF", """tesseract|ocrmypdf""", SCAN_CAUTION),
        r(ToolCategory.SCANNER_OCR, "Scanner hardware vendor", """\b(canon|epson|ricoh|xerox|konica|kyocera|scansnap|fujitsu|brother|lexmark|samsung\s+(mfp|scan))\b""", SCAN_CAUTION),
        r(ToolCategory.SCANNER_OCR, "Generic scanning label", """\bscan(ner|ned|ning)?\b""", SCAN_CAUTION),
        // --- Signing services --------------------------------------------------------------------------------
        r(ToolCategory.SIGNING, "DocuSign / Dropbox Sign / Adobe Sign", """docusign|hellosign|dropbox\s+sign|adobe\s+sign|adobe\s+echosign""", EDITOR_CAUTION),
    )

    /** Returns all clues for one metadata field. A single tool is reported once per field (the first matching rule wins per category). */
    fun inspect(field: String, value: String?): List<ToolClue> {
        if (value.isNullOrBlank()) return emptyList()
        val out = ArrayList<ToolClue>()
        val seenTools = HashSet<String>()
        for (rule in rules) {
            if (!rule.pattern.containsMatchIn(value)) continue
            if (!seenTools.add(rule.tool)) continue
            out.add(ToolClue(rule.category, rule.tool, field, value, rule.caution))
        }
        // "Writer" / "Pages" style generic words are too ambiguous to stand next to a specific hit; drop
        // low-specificity matches when a more specific rule from the same category already matched.
        return out.filterNot { c ->
            (c.tool == "Generic converter" || c.tool == "Generic scanning label" || c.tool == "Apple Pages / Keynote / Numbers") &&
                out.any { o -> o !== c && o.category == c.category }
        }
    }
}
