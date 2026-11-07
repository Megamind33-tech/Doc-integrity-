package com.docintegrity.forensics

import com.docintegrity.forensics.image.AndroidImageDecoder
import com.docintegrity.forensics.image.ImageDecoders
import org.junit.Assert.*
import org.junit.Assume
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class BenchmarkTest {
    @Before fun init() { RobolectricSupport.initPdfBox(); ImageDecoders.default = AndroidImageDecoder() }

    private val renderer get() = PdftoppmRenderer()

    private fun rows() = BenchmarkScenarios.all.map { s ->
        BenchmarkGenerator.Row(s, BenchmarkScenarios.run(s.file, null, renderer), BenchmarkScenarios.refFor(s)?.let { BenchmarkScenarios.run(s.file, it, renderer) })
    }
    private fun refs() = BenchmarkScenarios.referenceRows().map { BenchmarkGenerator.RefResult(it, BenchmarkScenarios.run(it.file, it.reference, renderer)) }

    @Test fun everyScenarioMatchesItsPinnedVerdict() {
        Assume.assumeTrue("pdftoppm is needed for the rendered comparison", PdftoppmRenderer.available)
        val problems = ArrayList<String>()
        for (r in rows()) {
            if (r.none.verdict.verdict != r.s.expectNoRef) problems.add("${r.s.id} without original: expected ${r.s.expectNoRef} but was ${r.none.verdict.verdict}")
            if (r.s.expectWithRef != null && r.with!!.verdict.verdict != r.s.expectWithRef) problems.add("${r.s.id} with original: expected ${r.s.expectWithRef} but was ${r.with.verdict.verdict}")
        }
        for (x in refs()) if (x.report.verdict.verdict != x.r.expect) problems.add("${x.r.id}: expected ${x.r.expect} but was ${x.report.verdict.verdict}")
        assertTrue(problems.joinToString("\n"), problems.isEmpty())
    }

    @Test fun neverCertifiesAnyBenchmarkFile() {
        Assume.assumeTrue(PdftoppmRenderer.available)
        // Claims of authenticity. Negations the report is required to print ("not evidence that the document is genuine",
        // "authenticity is not established", "no verified timestamp") are removed first.
        val allowedNegations = listOf("not evidence that the document is genuine", "authenticity is not established", "no verified timestamp")
        val banned = listOf("is genuine", "genuine document", "authentic document", "document is authentic", "verified document", "document is verified", "trustworthy", "safe to rely", "legitimate document", "document is valid")
        for (r in rows()) {
            var text = (r.none.verdict.reasons + r.none.verdict.verdict.summary + r.none.findings.map { it.title }).joinToString(" ").lowercase()
            for (n in allowedNegations) text = text.replace(n, "")
            for (bad in banned) assertFalse("${r.s.id}: report text contains '$bad'", text.contains(bad))
        }
    }

    @Test fun benchmarkDocumentsAreUpToDate() {
        Assume.assumeTrue(PdftoppmRenderer.available)
        val rows = rows(); val refs = refs()
        val md = BenchmarkGenerator.markdown(rows, refs)
        val json = BenchmarkGenerator.json(rows, refs)
        val docs = File(System.getProperty("user.dir"), "../docs").canonicalFile
        val mdFile = File(docs, "BENCHMARK.md"); val jsonFile = File(docs, "benchmark-results.json")
        if (System.getProperty("benchmark.write") == "true") {
            docs.mkdirs(); mdFile.writeText(md); jsonFile.writeText(json + "\n")
            return
        }
        assertTrue("docs/BENCHMARK.md is missing: regenerate with -Dbenchmark.write=true", mdFile.exists())
        assertEquals("docs/BENCHMARK.md is stale: regenerate with ./gradlew :forensics:testDebugUnitTest --tests '*BenchmarkTest*' -Dbenchmark.write=true", md.trim(), mdFile.readText().trim())
        assertEquals("docs/benchmark-results.json is stale", json.trim(), jsonFile.readText().trim())
    }
}
