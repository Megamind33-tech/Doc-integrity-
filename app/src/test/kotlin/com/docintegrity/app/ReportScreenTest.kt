package com.docintegrity.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.core.app.ApplicationProvider
import com.docintegrity.app.ui.ForensicsTheme
import com.docintegrity.app.ui.ReportScreen
import com.docintegrity.forensics.engine.ForensicEngine
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ReportScreenTest {
    @get:Rule val rule = createComposeRule()

    @Before fun init() = PDFBoxResourceLoader.init(ApplicationProvider.getApplicationContext())

    private fun report(name: String) = ForensicEngine().analyze(
        javaClass.classLoader!!.getResourceAsStream("fixtures/$name")!!.use { it.readBytes() }, name,
    )

    @Test fun suspiciousReportShowsCategoryReasonsAndNoCertification() {
        val r = report("F_editor_incremental.pdf")
        rule.setContent { ForensicsTheme { ReportScreen(r, onClose = {}) } }
        rule.onNodeWithText("Suspicious indicators").assertIsDisplayed()
        rule.onNodeWithText("Why this category").assertIsDisplayed()
        rule.onNodeWithText("It does not certify the document as genuine", substring = true).assertIsDisplayed()
        rule.onNodeWithText("F_editor_incremental.pdf").assertIsDisplayed()
    }

    @Test fun noIndicatorsReportNeverUsesCertifyingLanguage() {
        val r = report("A_original.pdf")
        rule.setContent { ForensicsTheme { ReportScreen(r, onClose = {}) } }
        rule.onNodeWithText("No indicators detected").assertIsDisplayed()
        rule.onNodeWithText("Authenticity is NOT established", substring = true).assertIsDisplayed()
    }
}
