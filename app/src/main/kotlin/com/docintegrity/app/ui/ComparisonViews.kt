package com.docintegrity.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.docintegrity.forensics.compare.ComparisonResult
import com.docintegrity.forensics.compare.SegKind
import com.docintegrity.forensics.compare.Segment
import com.docintegrity.forensics.compare.Tri
import com.docintegrity.forensics.model.Region
import com.docintegrity.forensics.model.Side

/**
 * Bytes and meaning are shown as two separate conclusions, because a re-saved or converted file changes every byte
 * while leaving its wording untouched.
 */
@Composable
fun BytesVersusMeaning(c: ComparisonResult) {
    Panel {
        Text("What the comparison shows", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        val bytes = when (c.bytesIdentical) { Tri.YES -> "Identical to the reference"; Tri.NO -> "Different from the reference"; Tri.UNKNOWN -> "Not compared" }
        val meaning = when (c.meaningChanged) {
            Tri.YES -> "Differences found (wording, figures, pictures or record fields)"
            Tri.NO -> "No difference found in text, names, dates, amounts, numbers or pictures"
            Tri.UNKNOWN -> "Not assessed (needs a reference file or an issuer record)"
        }
        KeyValue("File bytes", bytes)
        KeyValue("Document meaning", meaning)
        c.referenceName?.let { KeyValue("Reference", "$it (${c.referenceKind?.label ?: ""})") }
        c.referenceSha256?.let { KeyValue("Reference SHA-256", it, mono = true) }
        c.referenceDocxNotes.forEach { KeyValue("Note", it) }
        Spacer(Modifier.height(6.dp))
        Text(
            "Reference material is supplied by you; this tool cannot confirm it is authentic.",
            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun annotate(segs: List<Segment>, removed: Boolean): AnnotatedString {
    val hi = if (removed) Forensic.colors.confirmed else Forensic.colors.suspicious
    val bg = if (removed) Forensic.colors.confirmedContainer else Forensic.colors.suspiciousContainer
    return buildAnnotatedString {
        for (s in segs) {
            if (s.kind == SegKind.EQUAL) append(s.text + " ")
            else withStyle(SpanStyle(background = bg, color = hi, fontWeight = FontWeight.Bold)) { append(s.text) }.also { append(" ") }
        }
    }
}

/** Text of the original and of the examined document next to each other, differences highlighted. */
@Composable
fun SideBySideText(c: ComparisonResult) {
    val s = c.sideBySide ?: return
    Panel {
        Text("Side-by-side text", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Text("Highlighted passages are those that differ.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Column(Modifier.weight(1f)) {
                Text("ORIGINAL", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                Text(annotate(s.reference, removed = true), fontSize = 12.sp, lineHeight = 17.sp)
            }
            Column(Modifier.weight(1f)) {
                Text("EXAMINED", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                Text(annotate(s.submitted, removed = false), fontSize = 12.sp, lineHeight = 17.sp)
            }
        }
    }
}

/** A rendered page with review regions drawn on top. */
@Composable
fun PageWithRegions(bitmap: ImageBitmap, regions: List<Region>, modifier: Modifier = Modifier) {
    val colour = Forensic.colors.confirmed
    Box(modifier.aspectRatio(bitmap.width.toFloat() / bitmap.height).background(androidx.compose.ui.graphics.Color.White)) {
        Image(bitmap, contentDescription = "Rendered page", modifier = Modifier.fillMaxSize())
        Canvas(Modifier.fillMaxSize()) {
            for (r in regions) {
                val sx = size.width / r.pageWidth.toFloat(); val sy = size.height / r.pageHeight.toFloat()
                val pad = 3f
                drawRect(colour.copy(alpha = 0.16f), Offset(r.x.toFloat() * sx - pad, r.y.toFloat() * sy - pad), Size(r.w.toFloat() * sx + 2 * pad, r.h.toFloat() * sy + 2 * pad))
                drawRect(colour, Offset(r.x.toFloat() * sx - pad, r.y.toFloat() * sy - pad), Size(r.w.toFloat() * sx + 2 * pad, r.h.toFloat() * sy + 2 * pad), style = Stroke(2.5f))
            }
        }
    }
}

/**
 * Original and examined pages next to each other with the regions that need review outlined on both.
 * Rendering uses the platform PdfRenderer on secure temporary files (see SecureTempFiles).
 */
@Composable
fun PageCompareScreen(
    pageCount: Int,
    regions: List<Region>,
    loadExamined: suspend (page: Int, widthPx: Int) -> android.graphics.Bitmap?,
    loadReference: (suspend (page: Int, widthPx: Int) -> android.graphics.Bitmap?)?,
    onClose: () -> Unit,
) {
    var page by remember { mutableStateOf(0) }
    var left by remember { mutableStateOf<ImageBitmap?>(null) }
    var right by remember { mutableStateOf<ImageBitmap?>(null) }
    var failed by remember { mutableStateOf(false) }
    LaunchedEffect(page) {
        left = null; right = null; failed = false
        right = loadExamined(page, 900)?.asImageBitmap()
        left = loadReference?.invoke(page, 900)?.asImageBitmap()
        if (right == null) failed = true
    }
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().padding(12.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Page ${page + 1} of $pageCount", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            OutlinedButton(onClick = onClose) { Text("Back to report") }
        }
        Row(Modifier.padding(vertical = 6.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { if (page > 0) page-- }, enabled = page > 0) { Text("Previous") }
            OutlinedButton(onClick = { if (page < pageCount - 1) page++ }, enabled = page < pageCount - 1) { Text("Next") }
        }
        Row(Modifier.fillMaxWidth().weight(1f).verticalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Column(Modifier.weight(1f)) {
                Text("ORIGINAL", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                val l = left
                if (l != null) PageWithRegions(l, regions.filter { it.page == page && it.side == Side.REFERENCE }, Modifier.fillMaxWidth())
                else Text(if (loadReference == null) "No original page available (hash or issuer record only)." else "Loading…", style = MaterialTheme.typography.bodySmall)
            }
            Column(Modifier.weight(1f)) {
                Text("EXAMINED", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                val r = right
                if (r != null) PageWithRegions(r, regions.filter { it.page == page && it.side == Side.SUBMITTED }, Modifier.fillMaxWidth())
                else Text(if (failed) "This page could not be rendered." else "Loading…", style = MaterialTheme.typography.bodySmall)
            }
        }
        Text(
            "Outlined areas need human review. They are not proof: re-rendering and re-scanning also change pixels.",
            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 6.dp),
        )
    }
}
