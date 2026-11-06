package com.docintegrity.app

import androidx.test.core.app.ApplicationProvider
import com.docintegrity.forensics.image.ImageDecoders
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** The Application must register everything the engine needs; unit tests that install it themselves would not notice a gap. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = ForensicsApp::class)
class ApplicationWiringTest {
    @Test fun applicationInitialisesPdfLibraryAndImageDecoder() {
        ApplicationProvider.getApplicationContext<ForensicsApp>()
        assertTrue(PDFBoxResourceLoader.isReady())
        assertNotNull("image decoder must be registered by the app, not only by tests", ImageDecoders.default)
    }
}
