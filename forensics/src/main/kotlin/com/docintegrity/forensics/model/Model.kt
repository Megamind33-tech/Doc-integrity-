package com.docintegrity.forensics.model

/**
 * How strong a piece of evidence is. This is a *class*, never a numeric score: the engine does not produce
 * probabilities or confidence percentages because none of its checks has been statistically calibrated.
 */
enum class EvidenceClass(val label: String) {
    /** Demonstrable: supported by a trusted original or by valid cryptographic evidence. */
    ESTABLISHED("Established"),
    /** An anomaly that warrants human review. NOT proof of manipulation. */
    INDICATOR("Indicator"),
    /** Neutral context (e.g. which software produced the file). */
    INFO("Information"),
    /** Something that could not be examined, or evidence that is unavailable. */
    LIMITATION("Limitation"),
}

enum class Area(val title: String) {
    FILE("File"),
    CREATION_TOOL("Creation tool"),
    METADATA("Metadata"),
    REVISIONS("Revisions"),
    STRUCTURE("Structure"),
    FONTS("Fonts"),
    CONTENT("Content"),
    SIGNATURE("Signatures"),
    COMPARISON("Comparison"),
    IMAGE("Images and scans"),
}

enum class Side { SUBMITTED, REFERENCE }

/** A region on a page that needs review. Coordinates are PDF points with a TOP-LEFT origin. */
data class Region(
    val page: Int,
    val x: Double,
    val y: Double,
    val w: Double,
    val h: Double,
    val pageWidth: Double,
    val pageHeight: Double,
    val side: Side = Side.SUBMITTED,
    val label: String = "",
)

/**
 * One analysed observation. The three prose fields are mandatory by design: every finding has to state what was
 * seen, what that actually establishes, and what it leaves open.
 */
data class Finding(
    val id: String,
    val area: Area,
    val evidence: EvidenceClass,
    val title: String,
    val detected: String,
    val establishes: String,
    val unknown: String,
    val details: List<Pair<String, String>> = emptyList(),
    val regions: List<Region> = emptyList(),
    /**
     * Only meaningful for LIMITATION findings: true when the limitation prevents the engine from honestly saying
     * "no indicators detected" (e.g. the file is encrypted or its history is known to have been discarded).
     */
    val blocking: Boolean = false,
)

/** The four report categories required by the product specification. */
enum class Verdict(val label: String, val summary: String) {
    CONFIRMED_CHANGE(
        "Confirmed change",
        "A change is demonstrated by a trusted original or by cryptographic evidence.",
    ),
    SUSPICIOUS_INDICATORS(
        "Suspicious indicators",
        "Anomalies were found that require review. They are not proof of fraud.",
    ),
    NO_INDICATORS_DETECTED(
        "No indicators detected",
        "No supported signs of change were found. Authenticity is NOT established.",
    ),
    INCONCLUSIVE(
        "Inconclusive",
        "Evidence was insufficient or unavailable to reach any of the other categories.",
    ),
}

data class VerdictResult(
    val verdict: Verdict,
    /** Plain-language reasons for this category, each tied to finding ids. */
    val reasons: List<String>,
    val limitations: List<String>,
)

data class ToolInfo(
    val name: String,
    val version: String,
    val pdfboxAndroid: String,
    val bouncyCastle: String,
    val analysedAtIso: String,
    val rulesetVersion: String,
)
