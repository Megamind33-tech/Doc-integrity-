package com.docintegrity.forensics

import androidx.test.core.app.ApplicationProvider
import com.tom_roush.pdfbox.android.PDFBoxResourceLoader

object RobolectricSupport {
    /** PdfBox-Android needs its resource loader initialised once per (Robolectric) application. */
    fun initPdfBox() = PDFBoxResourceLoader.init(ApplicationProvider.getApplicationContext())
}
