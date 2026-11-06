package com.docintegrity.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.docintegrity.forensics.sig.CryptoStatus
import com.docintegrity.forensics.sig.PostSignChange
import com.docintegrity.forensics.sig.RevocationStatus
import com.docintegrity.forensics.sig.SignatureResult
import com.docintegrity.forensics.sig.TrustStatus

/**
 * One signature summarised as four separate statements so that "valid" is never read as "genuine":
 * integrity of the signed bytes, trust in the certificate, what happened after signing, and the standing caveat.
 */
@Composable
fun SignatureCard(s: SignatureResult, trustSet: String) {
    val c = Forensic.colors
    Panel {
        Row {
            Text(if (s.timestampOnly) "Document timestamp" else "Signature", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.width(8.dp))
            Text(s.fieldName ?: "#${s.index + 1}", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        s.signerCn?.let { KeyValue("Signer", it) }
        Spacer(Modifier.height(6.dp))

        val cryptoColor: Color = when (s.crypto) {
            CryptoStatus.VALID -> if (s.byteRangeProblems.isEmpty()) c.none else c.suspicious
            CryptoStatus.DIGEST_MISMATCH -> c.confirmed
            CryptoStatus.SIGNATURE_INVALID -> c.suspicious
            else -> c.inconclusive
        }
        Pill("1 · Integrity: ${s.crypto.label}", cryptoColor)
        Text(s.cryptoDetail, style = MaterialTheme.typography.bodySmall, )
        if (s.byteRangeProblems.isNotEmpty()) Text("Irregular signed range: " + s.byteRangeProblems.joinToString("; "), style = MaterialTheme.typography.bodySmall, color = c.suspicious)

        Spacer(Modifier.height(8.dp))
        val t = s.trustAtSigning
        val trustColor = when (t?.status) { TrustStatus.TRUSTED -> c.none; TrustStatus.EXPIRED_AT_SIGNING -> c.suspicious; null -> c.inconclusive; else -> c.inconclusive }
        Pill("2 · Certificate: ${t?.status?.label ?: "not evaluated"}", trustColor)
        Text("Trust set used: $trustSet", style = MaterialTheme.typography.bodySmall)
        s.revocation?.let { Text("Revocation: ${it.status.label}. ${it.detail}", style = MaterialTheme.typography.bodySmall, color = if (it.status == RevocationStatus.REVOKED) c.confirmed else MaterialTheme.colorScheme.onSurface) }

        Spacer(Modifier.height(8.dp))
        if (!s.timestampOnly) {
            val changed = s.laterChanges.groupBy { it.cls }
            val serious = changed.keys.any { it == PostSignChange.VISIBLE_CONTENT || it == PostSignChange.OTHER }
            Pill("3 · After signing: " + if (s.laterRevisions == 0 && s.bytesAfterSignature <= 2) "nothing appended" else if (changed.isEmpty()) "${s.bytesAfterSignature} bytes appended" else changed.entries.joinToString(", ") { "${it.value.size} ${it.key.label}" },
                if (serious) c.confirmed else c.none)
            Spacer(Modifier.height(8.dp))
        }
        s.verifiedTimestamp?.let { KeyValue("Timestamp", s.timestampNote ?: it.toString()) }
        s.claimedTime?.let { KeyValue("Claimed time", "$it (the signer's own claim unless a verified timestamp is shown)") }
        Text(
            "4 · A valid signature does not show that the signed information is true: a document made with false information and then signed still verifies.",
            style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
