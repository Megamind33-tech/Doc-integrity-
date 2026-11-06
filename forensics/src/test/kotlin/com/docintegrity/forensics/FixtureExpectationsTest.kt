package com.docintegrity.forensics

import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.engine.ForensicReport
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Verdict
import com.docintegrity.forensics.pdf.raw.PdfFile
import com.docintegrity.forensics.util.Hashing
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Real-tool fixtures (see tools/fixtures). These assertions are the factual basis of docs/BENCHMARK.md:
 * they pin what the engine DOES and DOES NOT detect for each scenario, including the misses.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class FixtureExpectationsTest {
    @Before fun init() = RobolectricSupport.initPdfBox()

    private fun run(n: String): ForensicReport = ForensicEngine().analyze(Fixtures.bytes(n), n)
    private fun ForensicReport.ids() = findings.map { it.id }.toSet()
    private fun ForensicReport.indicators() = findings.filter { it.evidence == EvidenceClass.INDICATOR }.map { it.id }

    // ---- negative controls: ordinary, unedited documents from different generators must NOT be flagged ----------

    @Test fun ordinaryDocumentsFromDifferentGeneratorsRaiseNoIndicators() {
        for (n in listOf("A_original.pdf", "B_roundtrip_unchanged.pdf", "E_native_docx_export.pdf", "N1_control_browser_print.pdf", "K_photo_swapped.pdf", "G0_scan_unedited.pdf")) {
            val r = run(n)
            assertEquals("$n should have no indicators but has ${r.indicators()}", emptyList<String>(), r.indicators())
            assertEquals(n, Verdict.NO_INDICATORS_DETECTED, r.verdict.verdict)
        }
    }

    @Test fun noIndicatorsVerdictNeverClaimsAuthenticity() {
        val r = run("A_original.pdf")
        val text = (r.verdict.reasons + r.verdict.verdict.summary).joinToString(" ").lowercase()
        assertTrue(text.contains("not established") || text.contains("not evidence"))
        for (bad in listOf("genuine", "authentic document", "verified", "valid document", "safe")) {
            assertFalse("verdict text must not contain '$bad'", text.replace("not evidence that the document is genuine", "").contains(bad))
        }
    }

    @Test fun wordProcessorOutputIsNotLabelledAltered() {
        // Scenario E: a legitimately authored document exported to PDF.
        val r = run("E_native_docx_export.pdf")
        assertTrue("TOOL_LABELS" in r.ids())
        assertEquals(emptyList<String>(), r.indicators())
    }

    // ---- scenario F: editor, incremental save -----------------------------------------------------------------

    @Test fun incrementalEditIsDetectedAndOriginalRevisionIsRecoverableByteForByte() {
        val f = run("F_editor_incremental.pdf")
        assertEquals(2, f.revisions.size)
        assertTrue("REV_UPDATE_1" in f.indicators())
        assertEquals(Verdict.SUSPICIOUS_INDICATORS, f.verdict.verdict)
        val file = PdfFile.open(Fixtures.bytes("F_editor_incremental.pdf"))!!
        // The first revision reconstructed from the edited file is byte-identical to the true original (A).
        assertEquals(Hashing.sha256(Fixtures.bytes("A_original.pdf")), Hashing.sha256(file.prefix(0)))
        assertEquals(f.revisions[0].prefixSha256, Hashing.sha256(Fixtures.bytes("A_original.pdf")))
    }

    @Test fun fullRewriteAfterEditLeavesNoRevisionHistory() {
        // Scenario Fb: same edit, but saved as a whole new file. History is gone; this is reported as unavailable.
        val r = run("Fb_editor_full_rewrite.pdf")
        assertEquals(1, r.revisions.size)
        assertTrue("REV_SINGLE" in r.ids())
        assertTrue(r.findings.first { it.id == "REV_SINGLE" }.unknown.contains("regenerated"))
    }

    // ---- white-out + retype and scans ---------------------------------------------------------------------------

    @Test fun whiteOutOverTextIsDetectedAndCoveredTextIsRecovered() {
        val r = run("Fw_whiteout_retype.pdf")
        val f = r.findings.first { it.id == "CONTENT_COVERED_TEXT" }
        assertTrue(f.detected.contains("Mwansa"))
        assertTrue(f.regions.isNotEmpty())
        assertEquals(Verdict.SUSPICIOUS_INDICATORS, r.verdict.verdict)
    }

    @Test fun vectorTextTypedOverScanIsDetected() {
        val r = run("Gv_scan_vector_overlay.pdf")
        val f = r.findings.first { it.id == "CONTENT_SCAN_OVERLAY" }
        assertTrue(f.detected.contains("42,500.00"))
        assertEquals(2, f.regions.size)
    }

    // ---- honest misses (documented false negatives) --------------------------------------------------------------

    @Test fun conversionRoundTripEditsAreNotDetectableWithoutAnOriginal() {
        // Scenarios C and D: PDF -> DOCX -> edit -> PDF. Without a trusted original there is no internal evidence.
        for (n in listOf("C_roundtrip_name_altered.pdf", "D_roundtrip_amount_altered.pdf")) {
            val r = run(n)
            assertEquals("$n: documented false negative", Verdict.NO_INDICATORS_DETECTED, r.verdict.verdict)
        }
    }

    @Test fun imageEditedScansAreNotYetDetectedByStageOneChecks() {
        // Scenarios G / Gb: raster edit. Structural checks cannot see it; image forensics is a later stage.
        for (n in listOf("G_scan_amount_edited.pdf", "Gb_scan_amount_edited_same_quality.pdf")) {
            assertEquals(n, Verdict.NO_INDICATORS_DETECTED, run(n).verdict.verdict)
        }
    }

    @Test fun reportsStateStandingLimitationsAndToolVersions() {
        val r = run("A_original.pdf")
        assertTrue(r.standingLimitations.any { it.contains("cannot certify") })
        assertEquals("2026.11-r1", r.tool.rulesetVersion)
        assertEquals(64, r.hashes.sha256.length)
    }

    @Test fun analysisNeverModifiesTheInputBytes() {
        val b = Fixtures.bytes("F_editor_incremental.pdf")
        val before = Hashing.sha256(b)
        ForensicEngine().analyze(b, "F")
        assertEquals(before, Hashing.sha256(b))
    }
}
