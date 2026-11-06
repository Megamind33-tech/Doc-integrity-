package com.docintegrity.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.test.core.app.ApplicationProvider
import com.docintegrity.app.ui.ForensicsTheme
import com.docintegrity.app.ui.ReportScreen
import com.docintegrity.app.ui.SetupScreen
import com.docintegrity.forensics.compare.ReferenceFile
import com.docintegrity.forensics.compare.ReferenceInput
import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.image.AndroidImageDecoder
import com.docintegrity.forensics.image.ImageDecoders
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class ComparisonScreenTest {
    @get:Rule val rule = createComposeRule()

    @Before fun init() { PDFBoxResourceLoader.init(ApplicationProvider.getApplicationContext()); ImageDecoders.default = AndroidImageDecoder() }

    private fun bytes(n: String) = javaClass.classLoader!!.getResourceAsStream("fixtures/$n")!!.use { it.readBytes() }

    @Test fun confirmedChangeReportSeparatesBytesFromMeaning() {
        val r = ForensicEngine().analyze(bytes("D_roundtrip_amount_altered.pdf"), "D.pdf", ReferenceInput(file = ReferenceFile("A_original.pdf", bytes("A_original.pdf"))))
        rule.setContent { ForensicsTheme { ReportScreen(r, {}) } }
        rule.onNodeWithText("Confirmed change").assertIsDisplayed()
        rule.onNodeWithTag("report").performScrollToNode(hasText("File bytes"))
        rule.onNodeWithText("File bytes").assertIsDisplayed()
        rule.onNodeWithText("Different from the reference").assertIsDisplayed()
        rule.onNodeWithText("Document meaning").assertIsDisplayed()
        rule.onNodeWithText("Differences found", substring = true).assertIsDisplayed()
        rule.onNodeWithTag("report").performScrollToNode(hasText("Side-by-side text"))
        rule.onNodeWithText("Side-by-side text").assertIsDisplayed()
    }

    @Test fun reExportReportSaysBytesDifferButNoMeaningChange() {
        val r = ForensicEngine().analyze(bytes("B_roundtrip_unchanged.pdf"), "B.pdf", ReferenceInput(file = ReferenceFile("A_original.pdf", bytes("A_original.pdf"))))
        rule.setContent { ForensicsTheme { ReportScreen(r, {}) } }
        rule.onNodeWithTag("report").performScrollToNode(hasText("File bytes"))
        rule.onNodeWithText("Different from the reference").assertIsDisplayed()
        rule.onNodeWithText("No difference found in text", substring = true).assertIsDisplayed()
        rule.onNodeWithText("Confirmed change").let { assertTrue(runCatching { it.assertIsDisplayed() }.isFailure) }
    }

    @Test fun reportWithoutReferenceStatesTheOriginalIsUnknown() {
        val r = ForensicEngine().analyze(bytes("A_original.pdf"), "A.pdf")
        rule.setContent { ForensicsTheme { ReportScreen(r, {}) } }
        rule.onNodeWithTag("report").performScrollToNode(hasText("No trusted original supplied"))
        rule.onNodeWithText("No trusted original supplied").assertIsDisplayed()
    }

    @Test fun setupScreenOffersAllThreeKindsOfTrustedReference() {
        var picked = false
        rule.setContent { ForensicsTheme { SetupScreen("A.pdf", 7836, ReferenceDraft(), { picked = true }, {}, {}, {}, {}) } }
        rule.onNodeWithText("Authenticated original").assertIsDisplayed()
        rule.onNodeWithText("Trusted reference hash").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Verified issuer record").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("cannot verify that what you supply", substring = true).performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("Choose original file").performScrollTo().performClick()
        assertTrue(picked)
    }
}
