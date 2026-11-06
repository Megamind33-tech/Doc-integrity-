package com.docintegrity.forensics

import com.docintegrity.forensics.image.AndroidImageDecoder
import com.docintegrity.forensics.pdf.images.ImageKind
import com.docintegrity.forensics.pdf.images.PdfImageExtractor
import com.docintegrity.forensics.pdf.raw.PdfFile
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** Exercises the real Android BitmapFactory path (Robolectric native graphics) on JPEGs taken out of real PDFs. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34])
class AndroidImageDecoderTest {
    @Test fun decodesEmbeddedScanToRealPixels() {
        val img = PdfImageExtractor.extract(PdfFile.open(Fixtures.bytes("G0_scan_unedited.pdf"))!!).images.single()
        assertEquals(ImageKind.JPEG, img.kind); assertEquals(1654, img.width)
        val r = AndroidImageDecoder().decode(img.data, 2400)!!
        assertEquals(1654, r.w); assertEquals(2339, r.h)
        val mean = r.gray().data.map { it.toInt() and 255 }.average()
        assertTrue("a document scan is mostly white (mean=$mean)", mean > 200)
    }

    @Test fun largeImagesAreSubsampledToBoundMemory() {
        val img = PdfImageExtractor.extract(PdfFile.open(Fixtures.bytes("G0_scan_unedited.pdf"))!!).images.single()
        val r = AndroidImageDecoder().decode(img.data, 800)!!
        assertTrue(maxOf(r.w, r.h) <= 1200)
    }

    @Test fun garbageIsNotDecoded() {
        assertNull(AndroidImageDecoder().decode(ByteArray(100) { it.toByte() }, 800))
    }

    @Test fun photoInsideAPdfIsExtractedWithItsGeometry() {
        val imgs = PdfImageExtractor.extract(PdfFile.open(Fixtures.bytes("A_original.pdf"))!!).images
        assertEquals(1, imgs.size)
        assertEquals(160, imgs[0].width); assertEquals(200, imgs[0].height)
        assertEquals(setOf(0), imgs[0].pages)
    }
}
