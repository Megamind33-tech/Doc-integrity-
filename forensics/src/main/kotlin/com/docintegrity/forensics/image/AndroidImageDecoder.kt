package com.docintegrity.forensics.image

import android.graphics.Bitmap
import android.graphics.BitmapFactory

/** Platform decoder. Uses sub-sampling so a 50-megapixel scan cannot exhaust memory. */
class AndroidImageDecoder : ImageDecoder {
    override fun decode(bytes: ByteArray, maxDim: Int): RasterImage? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / sample > maxDim) sample *= 2
        val opts = BitmapFactory.Options().apply { inSampleSize = sample; inPreferredConfig = Bitmap.Config.ARGB_8888 }
        val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts) ?: return null
        val px = IntArray(bmp.width * bmp.height)
        bmp.getPixels(px, 0, bmp.width, 0, 0, bmp.width, bmp.height)
        val r = RasterImage(bmp.width, bmp.height, px)
        bmp.recycle()
        return r
    }
}
