package com.docintegrity.app

import android.app.Application
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader

class ForensicsApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // PdfBox-Android loads its glyph lists / CMaps from assets; must be initialised once.
        PDFBoxResourceLoader.init(applicationContext)
    }
}
