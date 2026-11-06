package com.docintegrity.forensics

import androidx.test.core.app.ApplicationProvider
import com.docintegrity.forensics.engine.ForensicEngine
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Stage1DumpTest {
    @Test
    fun dumpAll() {
        PDFBoxResourceLoader.init(ApplicationProvider.getApplicationContext())
        for (n in Fixtures.names()) {
            val r = ForensicEngine().analyze(Fixtures.bytes(n), n)
            println("##### $n  -> ${r.verdict.verdict.label}  (pages=${r.pageCount}, revisions=${r.revisions.size}, words=${r.content?.wordCount})")
            for (f in r.findings.filter { it.evidence != com.docintegrity.forensics.model.EvidenceClass.INFO || it.id.startsWith("CONTENT") }) println("   [${f.evidence.label}] ${f.id}: ${f.detected.lineSequence().first().take(230)}")
        }
    }
}
