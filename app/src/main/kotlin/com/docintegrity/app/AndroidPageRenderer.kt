package com.docintegrity.app

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import com.docintegrity.forensics.compare.PageRenderer
import com.docintegrity.forensics.image.GrayImage
import com.docintegrity.forensics.util.Hashing
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom

/**
 * Secure temporary files for the few operations that need a seekable file descriptor (PdfRenderer).
 *  - created in the app-private cache directory with owner-only permissions (0600),
 *  - random, non-guessable names that do not reveal the document name,
 *  - overwritten with zeros before deletion,
 *  - every stale file is wiped at startup, so a crash cannot leave a document behind.
 */
class SecureTempFiles(context: Context) {
    private val dir = File(context.cacheDir, "forensics-tmp").apply { mkdirs() }
    private val live = HashMap<String, File>()

    init { wipeAll() }

    @Synchronized
    fun put(bytes: ByteArray): File {
        val key = Hashing.sha256(bytes)
        live[key]?.let { if (it.exists()) return it }
        val name = ByteArray(12).also { SecureRandom().nextBytes(it) }.let { Hashing.hex(it) } + ".bin"
        val path = dir.toPath().resolve(name)
        Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        val f = path.toFile()
        f.writeBytes(bytes)
        live[key] = f
        return f
    }

    @Synchronized
    fun wipeAll() {
        live.clear()
        dir.listFiles()?.forEach { shred(it) }
    }

    private fun shred(f: File) {
        try {
            if (f.isFile) RandomAccessFile(f, "rw").use { raf ->
                val zeros = ByteArray(64 * 1024)
                var left = raf.length()
                raf.seek(0)
                while (left > 0) { val n = minOf(left, zeros.size.toLong()).toInt(); raf.write(zeros, 0, n); left -= n }
                raf.fd.sync()
            }
        } catch (_: Exception) { /* best effort */ }
        f.delete()
    }
}

/** Renders PDF pages with the platform PdfRenderer. One page is rendered at a time (PdfRenderer is not thread-safe). */
class AndroidPageRenderer(private val temp: SecureTempFiles) : PageRenderer {
    private val lock = Any()

    fun renderBitmap(pdfBytes: ByteArray, page: Int, widthPx: Int): Bitmap? = synchronized(lock) {
        try {
            val file = temp.put(pdfBytes)
            ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
                PdfRenderer(pfd).use { r ->
                    if (page !in 0 until r.pageCount) return null
                    r.openPage(page).use { p ->
                        val h = maxOf(1, (widthPx.toDouble() * p.height / p.width).toInt())
                        val bmp = Bitmap.createBitmap(widthPx, h, Bitmap.Config.ARGB_8888)
                        bmp.eraseColor(Color.WHITE)
                        p.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                        bmp
                    }
                }
            }
        } catch (e: Exception) { null }
    }

    override fun render(pdfBytes: ByteArray, page: Int, widthPx: Int): GrayImage? {
        val bmp = renderBitmap(pdfBytes, page, widthPx) ?: return null
        val px = IntArray(bmp.width * bmp.height)
        bmp.getPixels(px, 0, bmp.width, 0, 0, bmp.width, bmp.height)
        val g = ByteArray(px.size)
        for (i in px.indices) {
            val p = px[i]
            g[i] = ((((p shr 16) and 255) * 299 + ((p shr 8) and 255) * 587 + (p and 255) * 114) / 1000).toByte()
        }
        val out = GrayImage(bmp.width, bmp.height, g)
        bmp.recycle()
        return out
    }
}
