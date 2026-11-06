package com.docintegrity.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performScrollToNode
import androidx.test.core.app.ApplicationProvider
import com.docintegrity.app.ui.ForensicsTheme
import com.docintegrity.app.ui.ReportScreen
import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.engine.TrustSet
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SignatureScreenTest {
    @get:Rule val rule = createComposeRule()
    @Before fun init() = PDFBoxResourceLoader.init(ApplicationProvider.getApplicationContext())

    private fun bytes(n: String) = javaClass.classLoader!!.getResourceAsStream("fixtures/$n")!!.use { it.readBytes() }
    private val trust by lazy {
        TrustSet(listOf(CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(bytes("test_root_ca.pem"))) as X509Certificate), "test root CA")
    }
    private fun report(n: String) = ForensicEngine().analyze(bytes(n), n, null, null, trust)

    @Test fun validSignatureCardKeepsIntegrityTrustAndTruthSeparate() {
        val r = report("H0_signed_valid.pdf")
        rule.setContent { ForensicsTheme { ReportScreen(r, onClose = {}) } }
        rule.onNodeWithTag("report").performScrollToNode(hasText("1 · Integrity", substring = true))
        rule.onNodeWithText("1 · Integrity: Cryptographically valid").assertIsDisplayed()
        rule.onNodeWithText("2 · Certificate: Chains to a trusted root").assertIsDisplayed()
        rule.onNodeWithTag("report").performScrollToNode(hasText("does not show that the signed information is true", substring = true))
        rule.onNodeWithText("does not show that the signed information is true", substring = true).assertIsDisplayed()
    }

    @Test fun tamperedSignatureCardIsShownAsBrokenAndReportIsConfirmedChange() {
        val r = report("H1_signed_bytes_flipped.pdf")
        rule.setContent { ForensicsTheme { ReportScreen(r, onClose = {}) } }
        rule.onNodeWithText("Confirmed change").assertIsDisplayed()
        rule.onNodeWithTag("report").performScrollToNode(hasText("1 · Integrity", substring = true))
        rule.onNodeWithText("1 · Integrity: Signed bytes do not match the signature").assertIsDisplayed()
    }

    @Test fun contentAddedAfterSigningIsShownOnTheCard() {
        val r = report("H2_signed_then_edited.pdf")
        rule.setContent { ForensicsTheme { ReportScreen(r, onClose = {}) } }
        rule.onNodeWithTag("report").performScrollToNode(hasText("3 · After signing", substring = true))
        rule.onNodeWithText("3 · After signing", substring = true).assertIsDisplayed()
    }
}
