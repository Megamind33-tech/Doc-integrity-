package com.docintegrity.app.ui

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Finding
import com.docintegrity.forensics.model.Verdict
import com.docintegrity.forensics.model.VerdictResult

@Composable
fun SectionHeader(title: String, subtitle: String? = null, modifier: Modifier = Modifier) {
    Column(modifier.padding(top = 24.dp, bottom = 8.dp)) {
        Text(title.uppercase(), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary, letterSpacing = 1.2.sp)
        if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
fun Pill(text: String, color: Color, modifier: Modifier = Modifier) {
    Surface(modifier, shape = RoundedCornerShape(50), color = color.copy(alpha = 0.14f), border = BorderStroke(1.dp, color.copy(alpha = 0.5f))) {
        Text(text, Modifier.padding(horizontal = 10.dp, vertical = 3.dp), style = MaterialTheme.typography.labelSmall, color = color, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun KeyValue(key: String, value: String, mono: Boolean = false) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.Top) {
        Text(key, Modifier.width(116.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        SelectionContainer(Modifier.weight(1f)) {
            Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = if (mono) FontFamily.Monospace else null, fontSize = if (mono) 12.sp else 14.sp)
        }
    }
}

@Composable
fun Panel(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Card(
        modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) { Column(Modifier.padding(16.dp)) { content() } }
}

/**
 * The category banner. By design it always carries the statement that the app cannot certify authenticity, and the
 * "no indicators" state uses a neutral slate colour rather than a reassuring one.
 */
@Composable
fun VerdictBanner(result: VerdictResult, modifier: Modifier = Modifier) {
    val (main, on, container) = verdictColors(result.verdict)
    Card(
        modifier.fillMaxWidth(), shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = container), border = BorderStroke(1.5.dp, main),
    ) {
        Column(Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.width(10.dp).height(10.dp).background(main, CircleShape))
                Spacer(Modifier.width(10.dp))
                Text("REPORT CATEGORY", style = MaterialTheme.typography.labelMedium, color = main, letterSpacing = 1.4.sp)
            }
            Spacer(Modifier.height(6.dp))
            Text(result.verdict.label, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
            Spacer(Modifier.height(4.dp))
            Text(result.verdict.summary, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
            Spacer(Modifier.height(12.dp))
            Text("Why this category", style = MaterialTheme.typography.labelLarge, color = main)
            result.reasons.forEach { r ->
                Row(Modifier.padding(top = 4.dp)) {
                    Text("•", Modifier.width(14.dp), color = main)
                    Text(r, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface)
                }
            }
            Spacer(Modifier.height(12.dp))
            Text(
                "This is an analysis of what could be shown from the file. It does not certify the document as genuine, and no probability or confidence score is given.",
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
fun FindingCard(f: Finding, modifier: Modifier = Modifier, startExpanded: Boolean = f.evidence == EvidenceClass.INDICATOR || f.evidence == EvidenceClass.ESTABLISHED) {
    var open by rememberSaveable(f.id + f.title) { mutableStateOf(startExpanded) }
    val color = evidenceColor(f.evidence)
    Card(
        modifier.fillMaxWidth().animateContentSize().clickable { open = !open },
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)),
        border = BorderStroke(1.dp, color.copy(alpha = 0.45f)),
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Pill(f.evidence.label, color)
                Spacer(Modifier.width(8.dp))
                Text(f.area.title, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Spacer(Modifier.height(6.dp))
            Text(f.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            if (!open) {
                Text(f.detected.lineSequence().first(), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2)
            } else {
                Labeled("Detected", f.detected, color)
                Labeled("What this establishes", f.establishes, color)
                Labeled("What remains unknown", f.unknown, color)
                if (f.details.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    f.details.take(40).forEach { (k, v) -> KeyValue(k, v) }
                }
                if (f.regions.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text("${f.regions.size} highlighted region(s) require review", style = MaterialTheme.typography.labelMedium, color = color)
                }
            }
        }
    }
}

@Composable
private fun Labeled(label: String, body: String, accent: Color) {
    Spacer(Modifier.height(8.dp))
    Text(label, style = MaterialTheme.typography.labelMedium, color = accent)
    SelectionContainer { Text(body, style = MaterialTheme.typography.bodyMedium) }
}

@Composable
fun verdictChipColor(v: Verdict): Color = verdictColors(v).first
