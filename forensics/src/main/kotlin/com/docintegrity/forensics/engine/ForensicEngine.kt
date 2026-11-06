package com.docintegrity.forensics.engine

import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.model.ToolInfo
import com.docintegrity.forensics.model.VerdictResult
import com.docintegrity.forensics.compare.ComparisonEngine
import com.docintegrity.forensics.compare.ComparisonResult
import com.docintegrity.forensics.compare.PageRenderer
import com.docintegrity.forensics.compare.ReferenceInput
import com.docintegrity.forensics.pdf.analysis.MetadataAnalyzer
import com.docintegrity.forensics.pdf.analysis.MetadataResult
import com.docintegrity.forensics.pdf.analysis.RevisionAnalyzer
import com.docintegrity.forensics.pdf.analysis.RevisionInfo
import com.docintegrity.forensics.pdf.analysis.StructureAnalyzer
import com.docintegrity.forensics.pdf.analysis.StructureResult
import com.docintegrity.forensics.pdf.content.ContentAnalyzer
import com.docintegrity.forensics.pdf.content.ContentExtractor
import com.docintegrity.forensics.pdf.content.DocumentContent
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.util.FileHashes
import com.docintegrity.forensics.util.Hashing
import java.time.Instant

/** Everything the engine produced for one analysed file. */
class ForensicReport(
    val tool: ToolInfo,
    val fileName: String,
    val hashes: FileHashes,
    val isPdf: Boolean,
    val pdfVersion: String?,
    val pageCount: Int,
    val metadata: MetadataResult?,
    val revisions: List<RevisionInfo>,
    val structure: StructureResult?,
    val content: DocumentContent?,
    val pageKinds: List<ContentAnalyzer.PageKind>,
    val comparison: ComparisonResult?,
    val findings: List<Finding>,
    val checksRun: List<String>,
    val verdict: VerdictResult,
    val standingLimitations: List<String>,
)

object EngineInfo {
    const val NAME = "Doc Forensics Engine"
    const val VERSION = "0.1.0"
    /** Bump whenever a rule's meaning or threshold changes, so exported reports state which rules produced them. */
    const val RULESET = "2026.11-r1"
}

/**
 * Orchestrates the analysers. The engine only READS the supplied byte array; nothing is written, repaired or
 * normalised, so the evidence being examined is never altered by the examination.
 */
class ForensicEngine(private val now: () -> Instant = { Instant.now() }) {

    fun analyze(
        bytes: ByteArray,
        fileName: String,
        reference: ReferenceInput? = null,
        renderer: PageRenderer? = null,
    ): ForensicReport {
        val hashes = Hashing.all(bytes)
        val findings = ArrayList<Finding>()
        val checks = ArrayList<String>()
        val file = PdfFile.open(bytes)

        if (file == null) {
            findings.add(
                Finding(
                    id = "FILE_NOT_PDF", area = Area.FILE, evidence = EvidenceClass.LIMITATION, blocking = true,
                    title = "Not a PDF file",
                    detected = "No %PDF- header was found in the first 1024 bytes.",
                    establishes = "PDF structural, revision and metadata analysis do not apply to this input.",
                    unknown = "Everything about the content. File hashes were still computed.",
                ),
            )
            val cmp0 = ComparisonEngine.compare(bytes, hashes, null, null, reference ?: ReferenceInput(), renderer)
            findings += cmp0.findings
            return finish(fileName, hashes, false, null, 0, null, emptyList(), null, null, emptyList(), cmp0, findings, checks)
        }

        checks += "file fingerprints (SHA-256/512, SHA-1, MD5)"
        val metadata = MetadataAnalyzer.analyze(file, now())
        checks += "PDF metadata and creation-tool labels"
        findings += metadata.findings
        val rev = RevisionAnalyzer.analyze(file)
        checks += "revision / incremental-update history"
        findings += rev.findings
        val structure = StructureAnalyzer.analyze(file)
        checks += "cross-reference integrity, page structure, fonts, unreferenced objects"
        findings += structure.findings

        var content: DocumentContent? = null
        var kinds = emptyList<ContentAnalyzer.PageKind>()
        if (ContentExtractor.isAvailable) {
            content = ContentExtractor.extract(bytes)
            val ca = ContentAnalyzer.analyze(content)
            kinds = ca.pageKinds
            findings += ca.findings
            checks += "text, fonts and paint order (covered, hidden, overlaid content)"
        } else {
            findings.add(
                Finding(
                    id = "CONTENT_UNAVAILABLE", area = Area.CONTENT, evidence = EvidenceClass.LIMITATION,
                    title = "Content analysis did not run",
                    detected = "The PDF content library was not initialised.",
                    establishes = "Text, font-usage and paint-order checks were skipped.",
                    unknown = "Everything those checks would have shown.",
                ),
            )
        }

        val cmp = ComparisonEngine.compare(bytes, hashes, file, content, reference ?: ReferenceInput(), renderer)
        findings += cmp.findings
        checks += if (reference == null || reference.isEmpty) "comparison skipped: no trusted original supplied"
        else "comparison with the supplied reference (" + listOfNotNull(
            if (reference.hashes.isNotEmpty()) "hash" else null, reference.file?.let { "file" }, if (reference.issuerRecord.isNotEmpty()) "issuer record" else null,
        ).joinToString(", ") + ")"

        return finish(fileName, hashes, true, file.version, structure.pageCount, metadata, rev.revisions, structure, content, kinds, cmp, findings, checks)
    }

    private fun finish(
        fileName: String, hashes: FileHashes, isPdf: Boolean, version: String?, pages: Int,
        metadata: MetadataResult?, revisions: List<RevisionInfo>, structure: StructureResult?,
        content: DocumentContent?, kinds: List<ContentAnalyzer.PageKind>, comparison: ComparisonResult?,
        findings: List<Finding>, checks: List<String>,
    ): ForensicReport {
        val ordered = findings.sortedWith(compareBy({ order(it.evidence) }, { it.area.ordinal }))
        val verdict = VerdictEngine.decide(ordered, checks)
        return ForensicReport(
            tool = toolInfo(), fileName = fileName, hashes = hashes, isPdf = isPdf, pdfVersion = version, pageCount = pages,
            metadata = metadata, revisions = revisions, structure = structure, content = content, pageKinds = kinds, comparison = comparison, findings = ordered, checksRun = checks,
            verdict = verdict, standingLimitations = VerdictEngine.STANDING_LIMITATIONS,
        )
    }

    private fun order(e: EvidenceClass) = when (e) {
        EvidenceClass.ESTABLISHED -> 0
        EvidenceClass.INDICATOR -> 1
        EvidenceClass.LIMITATION -> 2
        EvidenceClass.INFO -> 3
    }

    private fun toolInfo() = ToolInfo(
        name = EngineInfo.NAME, version = EngineInfo.VERSION,
        pdfboxAndroid = "com.tom-roush:pdfbox-android:2.0.27.0", bouncyCastle = "org.bouncycastle:bcprov-jdk18on:1.83",
        analysedAtIso = now().toString(), rulesetVersion = EngineInfo.RULESET,
    )
}
