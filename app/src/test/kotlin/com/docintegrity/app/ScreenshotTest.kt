package com.docintegrity.app

import androidx.test.core.app.ApplicationProvider
import com.docintegrity.app.ui.ForensicsTheme
import com.docintegrity.app.ui.ReportScreen
import com.docintegrity.app.ui.SetupScreen
import com.docintegrity.forensics.compare.ReferenceFile
import com.docintegrity.forensics.compare.ReferenceInput
import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.engine.TrustSet
import com.docintegrity.forensics.image.AndroidImageDecoder
import com.docintegrity.forensics.image.ImageDecoders
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Renders the real Compose screens to PNG (Robolectric native graphics) so layout can be reviewed without a device. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h900dp-xxhdpi")
class ScreenshotTest {
    @get:Rule val rule = androidx.compose.ui.test.junit4.createAndroidComposeRule<androidx.activity.ComponentActivity>()
    @Before fun init() { PDFBoxResourceLoader.init(ApplicationProvider.getApplicationContext()); ImageDecoders.default = AndroidImageDecoder() }

    private fun bytes(n: String) = javaClass.classLoader!!.getResourceAsStream("fixtures/$n")!!.use { it.readBytes() }
    private val trust by lazy { TrustSet(listOf(CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(bytes("test_root_ca.pem"))) as X509Certificate), "test root CA") }
    private val out = File(System.getProperty("user.dir"), "build/reports/screens").apply { mkdirs() }

    private fun shot(name: String) {
        rule.waitForIdle()
        val view = rule.activity.window.decorView
        val dm = rule.activity.resources.displayMetrics
        val w = dm.widthPixels; val h = dm.heightPixels
        view.measure(android.view.View.MeasureSpec.makeMeasureSpec(w, android.view.View.MeasureSpec.EXACTLY), android.view.View.MeasureSpec.makeMeasureSpec(h, android.view.View.MeasureSpec.EXACTLY))
        view.layout(0, 0, w, h)
        val bmp = android.graphics.Bitmap.createBitmap(w, h, android.graphics.Bitmap.Config.ARGB_8888)
        bmp.eraseColor(android.graphics.Color.WHITE)
        view.draw(android.graphics.Canvas(bmp))
        File(out, "$name.png").outputStream().use { bmp.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
    }

    @Test fun reportConfirmedChange() {
        val r = ForensicEngine().analyze(bytes("D_roundtrip_amount_altered.pdf"), "D_roundtrip_amount_altered.pdf", ReferenceInput(file = ReferenceFile("A_original.pdf", bytes("A_original.pdf"))))
        rule.setContent { ForensicsTheme { ReportScreen(r, onClose = {}, onComparePages = {}, onExportPdf = {}, onExportJson = {}) } }
        shot("report-confirmed-change")
    }

    @Test fun reportNoIndicators() {
        val r = ForensicEngine().analyze(bytes("A_original.pdf"), "A_original.pdf")
        rule.setContent { ForensicsTheme { ReportScreen(r, onClose = {}, onExportPdf = {}, onExportJson = {}) } }
        shot("report-no-indicators")
    }

    @Test fun reportSigned() {
        val r = ForensicEngine().analyze(bytes("H2_signed_then_edited.pdf"), "H2_signed_then_edited.pdf", null, null, trust)
        rule.setContent { ForensicsTheme { ReportScreen(r, onClose = {}, onExportPdf = {}, onExportJson = {}) } }
        shot("report-signed-edited")
    }

    @Test @Config(sdk = [34], qualifiers = "w411dp-h2800dp-xxhdpi")
    fun reportSignedTall() {
        val r = ForensicEngine().analyze(bytes("H2_signed_then_edited.pdf"), "H2_signed_then_edited.pdf", null, null, trust)
        rule.setContent { ForensicsTheme { ReportScreen(r, onClose = {}, onExportPdf = {}, onExportJson = {}) } }
        shot("report-signed-edited-tall")
    }

    @Test fun setup() {
        rule.setContent { ForensicsTheme { SetupScreen("D_roundtrip_amount_altered.pdf", 36611, ReferenceDraft(), {}, {}, {}, {}, {}) } }
        shot("setup")
    }
}
