package com.docintegrity.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import com.docintegrity.forensics.model.EvidenceClass
import com.docintegrity.forensics.model.Verdict

/**
 * Semantic colours for the four report categories. There is deliberately NO green: "no indicators detected"
 * must never look like a pass or a certificate of authenticity.
 */
data class ForensicColors(
    val confirmed: Color, val onConfirmed: Color, val confirmedContainer: Color,
    val suspicious: Color, val onSuspicious: Color, val suspiciousContainer: Color,
    val none: Color, val onNone: Color, val noneContainer: Color,
    val inconclusive: Color, val onInconclusive: Color, val inconclusiveContainer: Color,
    val info: Color,
)

private val LightForensic = ForensicColors(
    confirmed = Color(0xFFB3261E), onConfirmed = Color.White, confirmedContainer = Color(0xFFFCE4E1),
    suspicious = Color(0xFF9A5B00), onSuspicious = Color.White, suspiciousContainer = Color(0xFFFFEFD1),
    none = Color(0xFF3F5E7D), onNone = Color.White, noneContainer = Color(0xFFE3EBF3),
    inconclusive = Color(0xFF5E5A75), onInconclusive = Color.White, inconclusiveContainer = Color(0xFFE9E7F1),
    info = Color(0xFF5C6670),
)
private val DarkForensic = ForensicColors(
    confirmed = Color(0xFFFFB4AB), onConfirmed = Color(0xFF3B0A07), confirmedContainer = Color(0xFF4A1612),
    suspicious = Color(0xFFFFC46B), onSuspicious = Color(0xFF3A2500), suspiciousContainer = Color(0xFF402B00),
    none = Color(0xFFA9C7E8), onNone = Color(0xFF0E2A44), noneContainer = Color(0xFF1B3550),
    inconclusive = Color(0xFFC9C3E3), onInconclusive = Color(0xFF2A2640), inconclusiveContainer = Color(0xFF3A3652),
    info = Color(0xFFB7C0C9),
)

val LocalForensicColors = staticCompositionLocalOf { LightForensic }

object Forensic {
    val colors: ForensicColors @Composable get() = LocalForensicColors.current
}

@Composable
fun ForensicsTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val scheme = if (dark) {
        darkColorScheme(
            primary = Color(0xFF9CC2F0), onPrimary = Color(0xFF00315C), secondary = Color(0xFFB9C7DA),
            background = Color(0xFF111418), onBackground = Color(0xFFE2E4E8), surface = Color(0xFF111418), onSurface = Color(0xFFE2E4E8),
            surfaceVariant = Color(0xFF22272E), onSurfaceVariant = Color(0xFFC2C7CF), outline = Color(0xFF8B919A), outlineVariant = Color(0xFF3A4048),
        )
    } else {
        lightColorScheme(
            primary = Color(0xFF1F4E8C), onPrimary = Color.White, secondary = Color(0xFF4A5D78),
            background = Color(0xFFF7F8FA), onBackground = Color(0xFF191C20), surface = Color(0xFFF7F8FA), onSurface = Color(0xFF191C20),
            surfaceVariant = Color(0xFFE4E8EE), onSurfaceVariant = Color(0xFF444A54), outline = Color(0xFF747B86), outlineVariant = Color(0xFFCBD0D8),
        )
    }
    CompositionLocalProvider(LocalForensicColors provides if (dark) DarkForensic else LightForensic) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

@Composable
fun verdictColors(v: Verdict): Triple<Color, Color, Color> { // main, on-main, container
    val c = Forensic.colors
    return when (v) {
        Verdict.CONFIRMED_CHANGE -> Triple(c.confirmed, c.onConfirmed, c.confirmedContainer)
        Verdict.SUSPICIOUS_INDICATORS -> Triple(c.suspicious, c.onSuspicious, c.suspiciousContainer)
        Verdict.NO_INDICATORS_DETECTED -> Triple(c.none, c.onNone, c.noneContainer)
        Verdict.INCONCLUSIVE -> Triple(c.inconclusive, c.onInconclusive, c.inconclusiveContainer)
    }
}

@Composable
fun evidenceColor(e: EvidenceClass): Color {
    val c = Forensic.colors
    return when (e) {
        EvidenceClass.ESTABLISHED -> c.confirmed
        EvidenceClass.INDICATOR -> c.suspicious
        EvidenceClass.LIMITATION -> c.inconclusive
        EvidenceClass.INFO -> c.info
    }
}
