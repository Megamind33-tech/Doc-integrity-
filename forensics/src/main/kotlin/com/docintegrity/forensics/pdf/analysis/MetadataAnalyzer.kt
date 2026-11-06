package com.docintegrity.forensics.pdf.analysis

import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.util.ParsedDate
import com.docintegrity.forensics.util.PdfDates
import java.time.Duration
import java.time.Instant

class MetadataResult(
    val infoPresent: Boolean,
    val info: Map<String, String>,
    val xmp: XmpResult,
    val creationDate: ParsedDate?,
    val modDate: ParsedDate?,
    val xmpCreateDate: ParsedDate?,
    val xmpModifyDate: ParsedDate?,
    val xmpMetadataDate: ParsedDate?,
    val fileId: Pair<String, String>?,
    val clues: List<ToolClue>,
    val findings: List<Finding>,
)

object MetadataAnalyzer {

    /** Differences below this are normal clock skew between the Info dictionary and the XMP packet being written. */
    const val DATE_CONFLICT_SECONDS = 60L

    /** Dates this far beyond the analysis time are treated as impossible rather than clock skew. */
    private const val FUTURE_TOLERANCE_HOURS = 36L

    fun analyze(file: PdfFile, now: Instant): MetadataResult {
        val rev = file.lastRevision
        val findings = ArrayList<Finding>()

        if (file.encrypted) {
            findings.add(
                Finding(
                    id = "META_ENCRYPTED_UNREADABLE", area = Area.METADATA, evidence = EvidenceClass.LIMITATION,
                    title = "Metadata strings are encrypted",
                    detected = "The trailer contains /Encrypt, so Info and XMP strings/streams are stored encrypted.",
                    establishes = "The document uses PDF encryption.",
                    unknown = "Creator, producer, dates and XMP were not read by the structural parser, so no metadata comparison or tool recognition was possible.",
                    blocking = true,
                ),
            )
            return MetadataResult(false, emptyMap(), XmpResult(false, 0, null, null), null, null, null, null, null, null, emptyList(), findings)
        }

        val info = MetadataReader.readInfo(file, rev)
        val xmp = MetadataReader.readXmp(file, rev)
        val xd = xmp.data
        val fileId = MetadataReader.readFileId(file, rev)

        val created = PdfDates.parsePdf(info?.get("CreationDate"))
        val modified = PdfDates.parsePdf(info?.get("ModDate"))
        val xCreate = PdfDates.parseIso(xd?.props?.get("xmp:CreateDate"))
        val xModify = PdfDates.parseIso(xd?.props?.get("xmp:ModifyDate"))
        val xMeta = PdfDates.parseIso(xd?.props?.get("xmp:MetadataDate"))

        // ---- creation-tool clues --------------------------------------------------------------------------
        val clues = ArrayList<ToolClue>()
        clues += ToolFingerprints.inspect("Info /Creator", info?.get("Creator"))
        clues += ToolFingerprints.inspect("Info /Producer", info?.get("Producer"))
        clues += ToolFingerprints.inspect("XMP xmp:CreatorTool", xd?.props?.get("xmp:CreatorTool"))
        clues += ToolFingerprints.inspect("XMP pdf:Producer", xd?.props?.get("pdf:Producer"))
        xd?.history?.forEach { ev -> clues += ToolFingerprints.inspect("XMP history agent", ev.softwareAgent) }

        if (info == null && !xmp.present) {
            findings.add(
                Finding(
                    id = "META_NONE", area = Area.METADATA, evidence = EvidenceClass.INFO,
                    title = "No document metadata present",
                    detected = "The file has neither an Info dictionary nor an XMP packet.",
                    establishes = "No self-asserted creator, producer or date labels are available to examine.",
                    unknown = "Whether metadata was never written (some generators omit it) or was deliberately removed. The origin of the file cannot be assessed from metadata.",
                ),
            )
        }

        if (clues.isNotEmpty()) {
            val distinct = clues.distinctBy { it.tool + "|" + it.field }
            findings.add(
                Finding(
                    id = "TOOL_LABELS", area = Area.CREATION_TOOL, evidence = EvidenceClass.INFO,
                    title = "Software labels found in metadata",
                    detected = distinct.joinToString("; ") { "${it.field}: “${it.matchedText}” → ${it.tool} (${it.category.label})" },
                    establishes = "The file carries self-asserted labels that are consistent with the software named above having created or processed it.",
                    unknown = "Labels can be edited, stripped or forged, and they do not show what was done to the content. Use of any of these tools is not evidence that the document was falsified.",
                    details = distinct.map { it.tool to it.caution }.distinct(),
                ),
            )
        }

        // ---- tool chain ------------------------------------------------------------------------------------
        val creatorClues = clues.filter { it.field == "Info /Creator" || it.field == "XMP xmp:CreatorTool" }
        val producerClues = clues.filter { it.field == "Info /Producer" || it.field == "XMP pdf:Producer" }
        val creatorTools = creatorClues.map { it.tool }.toSet()
        val producerTools = producerClues.map { it.tool }.toSet()
        val chainDiffers = creatorTools.isNotEmpty() && producerTools.isNotEmpty() && creatorTools.intersect(producerTools).isEmpty()
        if (chainDiffers) {
            findings.add(
                Finding(
                    id = "TOOL_CHAIN", area = Area.CREATION_TOOL, evidence = EvidenceClass.INFO,
                    title = "More than one software stage recorded",
                    detected = "Creator: ${creatorTools.joinToString()} · Producer: ${producerTools.joinToString()}",
                    establishes = "The file records different software for authoring (Creator) and for writing the final PDF (Producer), i.e. it passed through at least two stages.",
                    unknown = "Whether the later stage changed the content or only re-saved, compressed, merged or signed the file. This is a very common, legitimate pattern.",
                ),
            )
        }
        val rewriters = producerClues.filter { it.category == ToolCategory.CONVERTER }
        if (rewriters.isNotEmpty() && info?.get("Creator")?.isNotBlank() == true && creatorTools.isNotEmpty() && chainDiffers) {
            findings.add(
                Finding(
                    id = "HISTORY_REWRITE_TOOL", area = Area.CREATION_TOOL, evidence = EvidenceClass.LIMITATION, blocking = true,
                    title = "Final stage is a whole-file rewriting tool",
                    detected = "Producer ${rewriters.joinToString { it.tool }} is a converter/optimiser, after an earlier authoring stage (${creatorTools.joinToString()}).",
                    establishes = "These tools write a brand-new file. Any incremental-update (revision) history that existed before this stage would not survive it, so it cannot be inspected here.",
                    unknown = "Whether earlier history existed, and whether content changed before or during this stage. Absence of revisions in this file is NOT evidence that none occurred. A comparison against a trusted original is the only way to test content.",
                ),
            )
        }

        // ---- date sanity -----------------------------------------------------------------------------------
        val dateFields = listOf(
            "Info /CreationDate" to created, "Info /ModDate" to modified,
            "XMP xmp:CreateDate" to xCreate, "XMP xmp:ModifyDate" to xModify, "XMP xmp:MetadataDate" to xMeta,
        )
        for ((label, d) in dateFields) {
            if (d != null && !d.valid) {
                findings.add(
                    Finding(
                        id = "META_DATE_UNPARSEABLE", area = Area.METADATA, evidence = EvidenceClass.INDICATOR,
                        title = "Malformed date in metadata",
                        detected = "$label has the value “${d.raw}”, which is not a valid PDF/ISO date.",
                        establishes = "The stored value does not follow the date format that standard writers produce.",
                        unknown = "Some tools write sloppy dates; manual metadata editing also produces this. The cause cannot be determined from the value.",
                        details = listOf(label to d.raw),
                    ),
                )
            }
        }
        if (created?.valid == true && modified?.valid == true) {
            val d = PdfDates.diffSeconds(created, modified)
            if (d != null && d < 0) {
                findings.add(
                    Finding(
                        id = "META_MOD_BEFORE_CREATION", area = Area.METADATA, evidence = EvidenceClass.INDICATOR,
                        title = "Modification date is earlier than creation date",
                        detected = "Info /CreationDate ${created.display()} is later than /ModDate ${modified.display()}.",
                        establishes = "The two date fields are mutually inconsistent; a document cannot be modified before it was created.",
                        unknown = "Could be an incorrect clock, a time-zone error, or edited metadata. The file alone cannot say which.",
                    ),
                )
            } else if (d != null && d > DATE_CONFLICT_SECONDS) {
                findings.add(
                    Finding(
                        id = "META_MODIFIED_AFTER_CREATION", area = Area.METADATA, evidence = EvidenceClass.INFO,
                        title = "Document modified after it was created",
                        detected = "Created ${created.display()}; modified ${modified.display()} (${humanDuration(Duration.ofSeconds(d))} later).",
                        establishes = "The metadata records at least one save after the original creation.",
                        unknown = "What was changed. Re-saving, signing, compressing or form-filling all update ModDate.",
                    ),
                )
            }
        }
        val future = dateFields.filter { (_, d) -> d?.valid == true && d.instant()!!.toInstant().isAfter(now.plus(Duration.ofHours(FUTURE_TOLERANCE_HOURS))) }
        if (future.isNotEmpty()) {
            findings.add(
                Finding(
                    id = "META_DATE_IN_FUTURE", area = Area.METADATA, evidence = EvidenceClass.INDICATOR,
                    title = "Metadata date lies in the future",
                    detected = future.joinToString("; ") { (l, d) -> "$l = ${d!!.display()}" } + " (analysis time: $now)",
                    establishes = "A date is later than the moment of this analysis, so it cannot be a genuine record of a past event.",
                    unknown = "A wrong device clock at creation time is a common benign cause; so is manual editing.",
                ),
            )
        }

        // ---- Info vs XMP conflicts -------------------------------------------------------------------------
        if (info != null && xd != null) {
            fun conflict(id: String, label: String, a: String?, aLabel: String, b: String?, bLabel: String) {
                if (a.isNullOrBlank() || b.isNullOrBlank()) return
                if (normalise(a) == normalise(b)) return
                findings.add(
                    Finding(
                        id = id, area = Area.METADATA, evidence = EvidenceClass.INDICATOR,
                        title = "$label differs between Info dictionary and XMP",
                        detected = "$aLabel = “$a”, but $bLabel = “$b”.",
                        establishes = "The two metadata stores disagree. Writers normally update both together.",
                        unknown = "Benign causes: a tool updated only one store. Concerning cause: one store was edited by hand or by a metadata editor. The file cannot distinguish them.",
                    ),
                )
            }
            conflict("META_CONFLICT_PRODUCER", "Producer", info["Producer"], "Info /Producer", xd.props["pdf:Producer"], "XMP pdf:Producer")
            conflict("META_CONFLICT_CREATOR", "Creator tool", info["Creator"], "Info /Creator", xd.props["xmp:CreatorTool"], "XMP xmp:CreatorTool")
            conflict("META_CONFLICT_TITLE", "Title", info["Title"], "Info /Title", xd.props["dc:title"], "XMP dc:title")
            conflict("META_CONFLICT_AUTHOR", "Author", info["Author"], "Info /Author", xd.props["dc:creator"], "XMP dc:creator")
            fun dateConflict(id: String, label: String, a: ParsedDate?, aLabel: String, b: ParsedDate?, bLabel: String) {
                if (a?.valid != true || b?.valid != true) return
                val d = PdfDates.diffSeconds(a, b) ?: return
                if (Math.abs(d) <= DATE_CONFLICT_SECONDS) return
                findings.add(
                    Finding(
                        id = id, area = Area.METADATA, evidence = EvidenceClass.INDICATOR,
                        title = "$label differs between Info dictionary and XMP",
                        detected = "$aLabel = ${a.display()}, $bLabel = ${b.display()} (${humanDuration(Duration.ofSeconds(Math.abs(d)))} apart; tolerance ${DATE_CONFLICT_SECONDS}s).",
                        establishes = "The two metadata stores record different instants for what should be the same event.",
                        unknown = "A tool updating only one store is a benign explanation; manual metadata editing is another. The file cannot distinguish them.",
                    ),
                )
            }
            dateConflict("META_CONFLICT_CREATE_DATE", "Creation date", created, "Info /CreationDate", xCreate, "XMP xmp:CreateDate")
            dateConflict("META_CONFLICT_MOD_DATE", "Modification date", modified, "Info /ModDate", xModify, "XMP xmp:ModifyDate")
        }
        if (xmp.note != null) {
            findings.add(
                Finding(
                    id = "META_XMP_NOT_PARSED", area = Area.METADATA, evidence = EvidenceClass.INDICATOR,
                    title = "XMP packet could not be read safely",
                    detected = xmp.note,
                    establishes = "An XMP stream exists but its content was not used for analysis.",
                    unknown = "Malformed XMP is produced by buggy writers and by manual tampering alike.",
                ),
            )
        }

        // ---- XMP provenance --------------------------------------------------------------------------------
        if (xd != null) {
            if (xd.history.isNotEmpty()) {
                val conv = xd.history.filter { (it.parameters ?: "").contains("from ") && (it.parameters ?: "").contains(" to ") }
                findings.add(
                    Finding(
                        id = "XMP_HISTORY", area = Area.CREATION_TOOL, evidence = EvidenceClass.INFO,
                        title = "XMP edit history recorded (${xd.history.size} event${if (xd.history.size == 1) "" else "s"})",
                        detected = xd.history.joinToString("\n") { ev ->
                            listOfNotNull(ev.whenIso, ev.action, ev.softwareAgent?.let { "by $it" }, ev.parameters?.let { "($it)" }, ev.changed?.let { "changed: $it" }).joinToString(" ")
                        },
                        establishes = "The XMP packet contains a self-reported list of save/convert events with software names" +
                            (if (conv.isNotEmpty()) ", including a recorded format conversion." else "."),
                        unknown = "XMP history is written by the application and is easily removed or edited. A missing history proves nothing; a present one is a claim by the file, not independent evidence.",
                    ),
                )
            }
            val docId = xd.props["xmpMM:DocumentID"]
            val origId = xd.props["xmpMM:OriginalDocumentID"]
            if (docId != null && origId != null && docId != origId) {
                findings.add(
                    Finding(
                        id = "XMP_DOCID_DIFFERS", area = Area.CREATION_TOOL, evidence = EvidenceClass.INFO,
                        title = "Document ID differs from original document ID",
                        detected = "xmpMM:DocumentID $docId ≠ xmpMM:OriginalDocumentID $origId.",
                        establishes = "The file declares that it is derived from a differently-identified source document (e.g. exported from another file).",
                        unknown = "Which source, and whether content was changed in between.",
                    ),
                )
            }
            if (xd.derivedFrom.isNotEmpty()) {
                findings.add(
                    Finding(
                        id = "XMP_DERIVED_FROM", area = Area.CREATION_TOOL, evidence = EvidenceClass.INFO,
                        title = "File declares a source document",
                        detected = xd.derivedFrom.entries.joinToString("; ") { "${it.key}=${it.value}" },
                        establishes = "XMP records a derivation relationship (xmpMM:DerivedFrom).",
                        unknown = "The referenced source is not available to this tool unless supplied as a trusted original.",
                    ),
                )
            }
        }

        // ---- permanent / instance ID --------------------------------------------------------------------------
        val ids = (0..file.lastRevision).map { MetadataReader.readFileId(file, it) }
        val firsts = ids.mapNotNull { it?.first }.distinct()
        if (firsts.size > 1) {
            findings.add(
                Finding(
                    id = "FILE_ID_CHANGED", area = Area.METADATA, evidence = EvidenceClass.INDICATOR,
                    title = "Permanent file ID changed between revisions",
                    detected = "The first element of the trailer /ID array differs between saves: ${firsts.joinToString(" → ") { it.take(12) + "…" }}.",
                    establishes = "The permanent identifier, which incremental saves normally preserve, was replaced by a later save.",
                    unknown = "Some editors regenerate the ID on every save. The change shows a different writer handled a later save; it does not show what changed.",
                ),
            )
        }

        return MetadataResult(info != null, info ?: emptyMap(), xmp, created, modified, xCreate, xModify, xMeta, fileId, clues, findings)
    }

    private fun normalise(s: String) = s.trim().lowercase().replace(Regex("\\s+"), " ")

    internal fun humanDuration(d: Duration): String {
        val s = d.seconds
        return when {
            s < 120 -> "$s seconds"
            s < 7200 -> "${s / 60} minutes"
            s < 172800 -> "${s / 3600} hours"
            else -> "${s / 86400} days"
        }
    }
}
