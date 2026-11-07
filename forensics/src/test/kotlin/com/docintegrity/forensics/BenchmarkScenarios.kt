package com.docintegrity.forensics

import com.docintegrity.forensics.compare.PageRenderer
import com.docintegrity.forensics.compare.ReferenceFile
import com.docintegrity.forensics.compare.ReferenceInput
import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.engine.ForensicReport
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Verdict
import java.time.Instant

/** Ground truth for a benchmark file. */
enum class Truth(val label: String) { UNALTERED("content unaltered"), ALTERED("content altered") }

/**
 * One benchmark row. [expectNoRef]/[expectWithRef] pin the engine's verdict so the generated document cannot drift
 * from real behaviour; [note] is the author's interpretation of false positives/negatives and unknowns.
 */
class Scenario(
    val id: String,
    val scenario: String,
    val file: String,
    val what: String,
    val truth: Truth,
    val reference: String?,
    val expectNoRef: Verdict,
    val expectWithRef: Verdict?,
    val note: String,
    val refKind: String = "trusted original file",
)

object BenchmarkScenarios {
    val FIXED_NOW: Instant = Instant.parse("2026-11-06T20:00:00Z")

    private val NI = Verdict.NO_INDICATORS_DETECTED
    private val SI = Verdict.SUSPICIOUS_INDICATORS
    private val CC = Verdict.CONFIRMED_CHANGE

    val all: List<Scenario> = listOf(
        Scenario("A", "A", "A_original.pdf", "Original receipt PDF (ReportLab), never edited.", Truth.UNALTERED, "A_original.pdf", NI, NI,
            "Control. Single revision, consistent metadata. The report states that no original is known and that authenticity is not established."),
        Scenario("N1", "A (control)", "N1_control_browser_print.pdf", "Same facts printed to PDF by a browser (Chromium Skia/PDF): a different generator, so a negative control for tool fingerprints.", Truth.UNALTERED, null, NI, null,
            "Control for false positives: a different PDF generator with different fonts and structure is not flagged."),
        Scenario("B", "B", "B_roundtrip_unchanged.pdf", "A converted to Word (.docx) by LibreOffice and exported to PDF again, no edit.", Truth.UNALTERED, "A_original.pdf", NI, NI,
            "Not labelled as altered: Producer/Creator show LibreOffice (informational). Against the original, every byte, font and layout differs but the wording does not, and the report says exactly that (bytes differ, meaning unchanged)."),
        Scenario("C", "C", "C_roundtrip_name_altered.pdf", "A → .docx → one NAME changed (John Mwansa → Joseph Mwanza) → PDF.", Truth.ALTERED, "A_original.pdf", NI, CC,
            "FALSE NEGATIVE without an original: the round trip leaves nothing in the file that shows a name was changed. A trusted original turns it into a confirmed, located, name-level difference."),
        Scenario("D", "D", "D_roundtrip_amount_altered.pdf", "A → .docx → AMOUNT changed (ZMW 4,250.00 → 42,500.00) → PDF.", Truth.ALTERED, "A_original.pdf", NI, CC,
            "FALSE NEGATIVE without an original, for the same reason as C. With one, the amount change is confirmed and highlighted on both pages."),
        Scenario("E", "E", "E_native_docx_export.pdf", "Receipt authored directly as a .docx (python-docx) and exported to PDF by LibreOffice (Microsoft Word was not available here).", Truth.UNALTERED, "E_source.docx", NI, NI,
            "Not labelled as altered. Against the authenticated .docx the extracted text matches exactly. Word-specific fingerprints are covered by string-level tests only, not by a real Word file."),
        Scenario("F", "F", "F_editor_incremental.pdf", "A edited with a PDF editor library (redact + insert new name), saved as an INCREMENTAL update.", Truth.ALTERED, "A_original.pdf", SI, CC,
            "Detected without an original: the earlier revision is still inside the file (byte-identical to A) and the edit shows as replaced content, a new font and a Redact annotation. The original makes it a confirmed name change."),
        Scenario("Fb", "F", "Fb_editor_full_rewrite.pdf", "Same edit saved as a FULL rewrite (Save As / optimise): revision history is gone.", Truth.ALTERED, "A_original.pdf", SI, CC,
            "Flagged only by a weak positional indicator (the inserted name sits 0.89 pt off the line's baseline). That is luck of this editor's placement: an editor that aligns exactly would be a FALSE NEGATIVE here. History is reported as unavailable, not as clean."),
        Scenario("Fw", "F", "Fw_whiteout_retype.pdf", "A with an opaque white rectangle painted over the name and new text typed over it.", Truth.ALTERED, "A_original.pdf", SI, CC,
            "Detected without an original: the covered text is still in the page and is recovered. The visible-text comparison ignores the covered text."),
        Scenario("G0", "G", "G0_scan_unedited.pdf", "Scan of A (JPEG q75 with paper grain), unedited.", Truth.UNALTERED, "G0_scan_unedited.pdf", NI, NI,
            "Control. The scan is too heavily compressed for a noise comparison to say anything, which the report states."),
        Scenario("G", "G", "G_scan_amount_edited.pdf", "Scan with the amount replaced as an image edit (flat patch + typed digits), page re-saved at q92.", Truth.ALTERED, "G0_scan_unedited.pdf", NI, SI,
            "FALSE NEGATIVE without an original. With the unedited scan as reference, the rendered comparison localises the edit, but pixel differences are only ever an indicator."),
        Scenario("Gb", "G", "Gb_scan_amount_edited_same_quality.pdf", "Same edit re-saved at the SAME JPEG quality as the scan.", Truth.ALTERED, "G0_scan_unedited.pdf", NI, SI,
            "FALSE NEGATIVE without an original: no compression trace survives a same-quality re-save. The reference comparison localises it."),
        Scenario("Gp", "G", "Gp_scan_patch_pasted.pdf", "Amount pasted from a different physical scan of the altered document, at an unaligned offset.", Truth.ALTERED, "G0_scan_unedited.pdf", NI, SI,
            "FALSE NEGATIVE without an original: grain and compression of the pasted patch are close to the page. Not detected by any single-file image check implemented here."),
        Scenario("Gs", "G", "Gs_scan_image_overlay.pdf", "A crisp separate image (digits) placed over the scan as its own PDF object.", Truth.ALTERED, "G0_scan_unedited.pdf", SI, SI,
            "Detected without an original: a separate image drawn over a page scan, at three times the scan's resolution."),
        Scenario("Gv", "G", "Gv_scan_vector_overlay.pdf", "Scan with a patch and new typed vector text drawn over it.", Truth.ALTERED, "G0_scan_unedited.pdf", SI, SI,
            "Detected without an original: visible vector text and an opaque rectangle on a scanned page."),
        Scenario("Gh0", "G", "Gh0_scan_hq_grainy_unedited.pdf", "Higher-quality grainy scan (q93), unedited.", Truth.UNALTERED, "Gh0_scan_hq_grainy_unedited.pdf", NI, NI,
            "Control for the noise check: informative page, no region flagged."),
        Scenario("Gh", "G", "Gh_scan_hq_grainy_amount_edited.pdf", "Same grainy scan with the amount replaced by a flat patch and typed digits.", Truth.ALTERED, "Gh0_scan_hq_grainy_unedited.pdf", SI, SI,
            "Detected without an original: a region without scan grain inside a grainy page, located on the edited amount. Only works because grain survived compression and the forger added none."),
        Scenario("Gn0", "G", "Gn0_scan_whitened_unedited.pdf", "Scan whose background the scanner software flattened to white.", Truth.UNALTERED, "Gn0_scan_whitened_unedited.pdf", NI, NI,
            "Control. Noise analysis reports itself not informative; it does not claim the page is clean."),
        Scenario("Gn", "G", "Gn_scan_whitened_amount_edited.pdf", "Whitened scan with the amount edited.", Truth.ALTERED, "Gn0_scan_whitened_unedited.pdf", NI, SI,
            "FALSE NEGATIVE without an original: on a flattened scan a digital patch is indistinguishable from the background."),
        Scenario("Gx", "G", "Gx_scan_editor_traces.pdf", "Unedited scan whose JPEG carries an Exif Software tag of an image editor.", Truth.UNALTERED, "G0_scan_unedited.pdf", NI, NI,
            "Reported as information only: image editors are used for innocent re-saving, so the trace is context and does not change the category."),
        Scenario("H0", "H", "H0_signed_valid.pdf", "A signed (pyHanko) by a test-CA certificate; nothing changed afterwards.", Truth.UNALTERED, "A_original.pdf", NI, NI,
            "Valid and trusted (against the test CA). Reported as: valid, NOT proof the content is true."),
        Scenario("H1", "H", "H1_signed_bytes_flipped.pdf", "H0 with one byte flipped inside the signed range.", Truth.ALTERED, "A_original.pdf", CC, CC,
            "Confirmed by cryptography alone: the signed bytes no longer match. Accidental corruption is equally possible; the report says so."),
        Scenario("H2", "H", "H2_signed_then_edited.pdf", "H0 followed by an incremental edit of the name.", Truth.ALTERED, "A_original.pdf", CC, CC,
            "Confirmed by cryptography alone: the signature is valid for the earlier revision and the later one changes page content. The signed version is reconstructed byte-for-byte."),
        Scenario("H3", "H", "H3_signed_then_cosigned.pdf", "H0 plus a legitimate second signature by another signer.", Truth.UNALTERED, "A_original.pdf", NI, NI,
            "Not flagged: further signatures, form-field and signature-widget additions are permitted changes (matches pyHanko's own analysis). An early development version of this classifier did flag it, because annotation resources and the AcroForm dictionary were treated as page content; that is fixed and pinned by a test."),
        Scenario("H4", "H", "H4_signed_self_signed.pdf", "A signed with a self-signed certificate.", Truth.UNALTERED, "A_original.pdf", NI, NI,
            "Valid but identity unproven: reported as self-signed, not as invalid."),
        Scenario("H5", "H", "H5_signed_timestamped.pdf", "A signed with an RFC 3161 signature timestamp.", Truth.UNALTERED, "A_original.pdf", NI, NI,
            "Timestamp verified (imprint and TSA signature), authenticating the signing time."),
        Scenario("H6", "H", "H6_certified_then_annotated.pdf", "A certified (DocMDP: no changes allowed), then a 'PAID IN FULL' annotation added.", Truth.ALTERED, "A_original.pdf", CC, CC,
            "Confirmed: the signature is valid for the certified revision and the later markup violates its own terms."),
        Scenario("H7", "H", "H7_signed_false_content.pdf", "D (altered amount) then validly signed.", Truth.ALTERED, "A_original.pdf", NI, CC,
            "FALSE NEGATIVE without an original, by design: a signature over false content verifies. The report says a valid signature is not proof of truth. The trusted original exposes the false amount."),
        Scenario("H8", "H", "H8_signed_cert_expired.pdf", "A signed with a certificate that had already expired at signing time.", Truth.UNALTERED, "A_original.pdf", SI, SI,
            "Verdict-level FALSE POSITIVE for content (content is unaltered) but an accurate finding about the certificate, whose validity is judged against the unauthenticated signing time. The signature itself is cryptographically valid."),
        Scenario("H9", "H", "H9_signed_then_doc_timestamp.pdf", "H0 plus an RFC 3161 document timestamp (long-term-validation append).", Truth.UNALTERED, "A_original.pdf", NI, NI,
            "Not flagged: a document timestamp is recognised as validation data, not a change."),
        Scenario("I", "I", "I_regenerated_no_history.pdf", "The edited F regenerated entirely by LibreOffice Draw: no revision history can survive.", Truth.ALTERED, "A_original.pdf", SI, CC,
            "History is unavailable and is reported as such. The verdict without an original comes from an inherited baseline offset, which is chance; do not read it as detection of regeneration."),
        Scenario("K", "A", "K_photo_swapped.pdf", "A with the embedded photograph replaced by a different picture.", Truth.ALTERED, "A_original.pdf", NI, CC,
            "FALSE NEGATIVE without an original (the image is small and unremarkable on its own). With one, the picture is shown to be different."),
    )

    // ---- J: other forms of trusted reference ------------------------------------------------------------------------
    class RefRow(val id: String, val title: String, val file: String, val reference: ReferenceInput, val truth: Truth, val expect: Verdict, val note: String)

    fun referenceRows(): List<RefRow> {
        val a = Fixtures.bytes("A_original.pdf")
        val record = mapOf("Receipt number" to "RC-2024-004217", "Name" to "John Mwansa", "Total amount" to "ZMW 4,250.00", "Date of issue" to "12 March 2024")
        return listOf(
            RefRow("J1", "D vs the SHA-256 published for A (hash only)", "D_roundtrip_amount_altered.pdf", ReferenceInput(hashes = listOf(com.docintegrity.forensics.util.Hashing.sha256(a))), Truth.ALTERED, CC,
                "Confirmed at BYTE level only: the file is not the published file. Meaning is not assessed without the original, and the report says a re-save would also change the hash."),
            RefRow("J2", "A vs the SHA-256 published for A", "A_original.pdf", ReferenceInput(hashes = listOf(com.docintegrity.forensics.util.Hashing.sha256(a))), Truth.UNALTERED, NI,
                "Byte-identical to the published file. Reported as information, with the note that this says nothing about whether the content is true."),
            RefRow("J3", "D vs a verified issuer record", "D_roundtrip_amount_altered.pdf", ReferenceInput(issuerRecord = record), Truth.ALTERED, CC,
                "The Total amount field disagrees with the record; the other three fields agree."),
            RefRow("J4", "C vs a verified issuer record", "C_roundtrip_name_altered.pdf", ReferenceInput(issuerRecord = record), Truth.ALTERED, CC,
                "The Name field disagrees with the record."),
            RefRow("J5", "A vs a verified issuer record", "A_original.pdf", ReferenceInput(issuerRecord = record), Truth.UNALTERED, NI,
                "All four fields agree."),
            RefRow("J6", "D vs the authenticated .docx of a different document (E)", "D_roundtrip_amount_altered.pdf", ReferenceInput(file = ReferenceFile("E_source.docx", Fixtures.bytes("E_source.docx"))), Truth.ALTERED, CC,
                "A .docx original is accepted as a trusted reference; the amount differs."),
        )
    }

    fun run(file: String, ref: ReferenceInput?, renderer: PageRenderer?): ForensicReport =
        ForensicEngine({ FIXED_NOW }).analyze(Fixtures.bytes(file), file, ref, renderer, TestTrust.testRoots)

    fun refFor(s: Scenario): ReferenceInput? = s.reference?.let { ReferenceInput(file = ReferenceFile(it, Fixtures.bytes(it))) }

    fun flagged(v: Verdict) = v == Verdict.CONFIRMED_CHANGE || v == Verdict.SUSPICIOUS_INDICATORS

    fun outcome(truth: Truth, v: Verdict): String = when {
        truth == Truth.ALTERED && flagged(v) -> "TP"
        truth == Truth.ALTERED -> "FN"
        flagged(v) -> "FP"
        else -> "TN"
    }

    fun key(f: com.docintegrity.forensics.model.Finding) = f.evidence != EvidenceClass.INFO
}
