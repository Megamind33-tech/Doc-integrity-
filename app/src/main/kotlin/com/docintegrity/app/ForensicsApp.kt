package com.docintegrity.app

import android.app.Application
import com.docintegrity.forensics.image.AndroidImageDecoder
import com.docintegrity.forensics.image.ImageDecoders
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader

class ForensicsApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // PdfBox-Android loads its glyph lists / CMaps from assets; must be initialised once.
        PDFBoxResourceLoader.init(applicationContext)
        // Picture comparison, noise analysis and page-image analysis decode through the platform codec.
        ImageDecoders.default = AndroidImageDecoder()
    }
}
