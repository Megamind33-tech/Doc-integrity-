package com.docintegrity.forensics.engine

import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.model.Verdict
import com.docintegrity.forensics.model.VerdictResult

/**
 * Maps findings to one of the four required report categories. The rule set is intentionally tiny and fully
 * visible so that a reader can audit why a category was assigned:
 *
 *  1. any ESTABLISHED finding            → Confirmed change
 *  2. else any INDICATOR                 → Suspicious indicators
 *  3. else any blocking LIMITATION       → Inconclusive
 *  4. else                               → No indicators detected (authenticity is still NOT established)
 *
 * No numeric score is computed anywhere. There is no "genuine"/"authentic"/"verified" outcome by design: the engine
 * cannot certify a document, only report what it could and could not show.
 */
object VerdictEngine {

    fun decide(findings: List<Finding>, checksRun: List<String>): VerdictResult {
        val established = findings.filter { it.evidence == EvidenceClass.ESTABLISHED }
        val indicators = findings.filter { it.evidence == EvidenceClass.INDICATOR }
        val blocking = findings.filter { it.evidence == EvidenceClass.LIMITATION && it.blocking }
        val limitations = findings.filter { it.evidence == EvidenceClass.LIMITATION }.map { "${it.title}: ${it.unknown}" }

        return when {
            established.isNotEmpty() -> VerdictResult(
                Verdict.CONFIRMED_CHANGE,
                established.map { "${it.title} — ${it.establishes}" } +
                    (if (indicators.isNotEmpty()) listOf("${indicators.size} further indicator(s) are also listed for review.") else emptyList()),
                limitations,
            )
            indicators.isNotEmpty() -> VerdictResult(
                Verdict.SUSPICIOUS_INDICATORS,
                indicators.map { "${it.title}: ${it.detected.lineSequence().first()}" } +
                    listOf("These are anomalies that need human review. None of them is proof that the document was altered."),
                limitations,
            )
            blocking.isNotEmpty() -> VerdictResult(
                Verdict.INCONCLUSIVE,
                blocking.map { "${it.title}: ${it.unknown}" },
                limitations,
            )
            else -> VerdictResult(
                Verdict.NO_INDICATORS_DETECTED,
                listOf(
                    "Checks that ran: ${checksRun.joinToString(", ")}.",
                    "None of them found a supported sign of change. That is not evidence that the document is genuine: it does not exclude a document that was created or regenerated with false information, nor edits that leave no trace in the file.",
                ),
                limitations,
            )
        }
    }

    /** Statements printed in every report, whatever the category. */
    val STANDING_LIMITATIONS: List<String> = listOf(
        "This tool reports what could be demonstrated from the supplied bytes. It cannot certify a document as genuine.",
        "Metadata, tool labels, XMP history and dates are self-asserted by the file and can be edited or forged.",
        "Without a trusted original, the document's original contents are unknown; indicators compare the file only against itself.",
        "A PDF that was fully regenerated (printed to PDF, converted, optimised) carries no recoverable history of earlier versions. This is a limit of the evidence, not a sign of innocence or guilt.",
        "A valid digital signature shows the signed bytes are unchanged since signing; it does not show that what was signed is true.",
        "Indicators are prompts for human review and are not accuracy-rated: none of the checks has been statistically calibrated, so no probability or confidence percentage is given.",
    )
}
