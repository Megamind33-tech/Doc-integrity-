package com.docintegrity.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.docintegrity.app.ReferenceDraft

/** Step between choosing the document and analysing it: optionally supply a trusted original. */
@Composable
fun SetupScreen(
    name: String,
    sizeBytes: Int,
    ref: ReferenceDraft,
    onPickReference: () -> Unit,
    onClearReference: () -> Unit,
    onChange: ((ReferenceDraft) -> ReferenceDraft) -> Unit,
    onAnalyze: () -> Unit,
    onBack: () -> Unit,
) {
    Column(
        Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Document to examine", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Panel {
            Text(name, style = MaterialTheme.typography.titleSmall)
            Text("$sizeBytes bytes · read into memory only; the original file is never changed", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        SectionHeader("Trusted original (optional)", "Without one, the tool cannot say what the document originally contained.")
        Panel {
            Text("Authenticated original", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text("A PDF, image or Word (.docx) file you obtained from the issuer or another trusted source.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(8.dp))
            if (ref.fileName == null) {
                OutlinedButton(onClick = onPickReference) { Text("Choose original file") }
            } else {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(ref.fileName, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    TextButton(onClick = onClearReference) { Text("Remove") }
                }
            }
        }
        Panel {
            Text("Trusted reference hash", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text("SHA-256 (or SHA-1/MD5/SHA-512) published by the issuer. Separate several with spaces.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            OutlinedTextField(
                value = ref.hashText, onValueChange = { v -> onChange { it.copy(hashText = v) } },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Hash") }, singleLine = false, minLines = 2,
            )
        }
        Panel {
            Text("Verified issuer record", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text("Values you confirmed on the issuer's portal or register, for example: Name, Receipt number, Total amount, Date of issue.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            ref.issuerFields.forEachIndexed { i, (k, v) ->
                Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(k, { nk -> onChange { d -> d.copy(issuerFields = d.issuerFields.toMutableList().also { l -> l[i] = nk to v }) } }, Modifier.weight(0.45f), label = { Text("Field") }, singleLine = true)
                    OutlinedTextField(v, { nv -> onChange { d -> d.copy(issuerFields = d.issuerFields.toMutableList().also { l -> l[i] = k to nv }) } }, Modifier.weight(0.55f), label = { Text("Value") }, singleLine = true)
                }
            }
            TextButton(onClick = { onChange { it.copy(issuerFields = it.issuerFields + ("" to "")) } }) { Text("Add field") }
        }
        Panel {
            Text(
                "The tool cannot verify that what you supply here is itself authentic. Every comparison result says it is only as reliable as that reference.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Button(onClick = onAnalyze, modifier = Modifier.fillMaxWidth().height(54.dp)) { Text("Analyse on this device") }
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Choose a different document") }
        Spacer(Modifier.width(1.dp))
    }
}
