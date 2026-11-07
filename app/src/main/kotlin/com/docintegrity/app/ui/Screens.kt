package com.docintegrity.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.docintegrity.forensics.engine.ForensicReport
import com.docintegrity.forensics.model.Area
import com.docintegrity.forensics.model.EvidenceClass

@Composable
fun HomeScreen(onPick: () -> Unit, error: String?) {
    Column(
        Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("Document Forensics", style = MaterialTheme.typography.displaySmall, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text(
            "Investigate whether a PDF may have been edited, converted or altered. Evidence is classified, never scored, and the app will not call a document genuine.",
            style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(28.dp))
        Button(onClick = onPick, modifier = Modifier.fillMaxWidth().height(54.dp)) { Text("Choose a PDF to examine") }
        if (error != null) {
            Spacer(Modifier.height(16.dp))
            Text(error, color = Forensic.colors.confirmed, style = MaterialTheme.typography.bodyMedium)
        }
        Spacer(Modifier.height(28.dp))
        Panel {
            Text("Privacy", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(
                "Analysis runs entirely on this device. The app has no network permission, never uploads a document, never modifies the file you choose, and keeps nothing after you close the report.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
fun WorkingScreen(message: String) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Spacer(Modifier.height(16.dp))
            Text(message, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
fun ReportScreen(
    report: ForensicReport,
    onClose: () -> Unit,
    onComparePages: (() -> Unit)? = null,
    onExportPdf: (() -> Unit)? = null,
    onExportJson: (() -> Unit)? = null,
) {
    LazyColumn(
        Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().testTag("report"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                Column(Modifier.weight(1f)) {
                    Text("Forensic report", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    Text(report.fileName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
                }
                OutlinedButton(onClick = onClose) { Text("Close") }
            }
        }
        item { VerdictBanner(report.verdict) }
        item { EvidenceCounts(report) }
        if (onExportPdf != null || onExportJson != null) {
            item {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (onExportPdf != null) Button(onClick = onExportPdf, modifier = Modifier.weight(1f)) { Text("Export PDF report") }
                    if (onExportJson != null) OutlinedButton(onClick = onExportJson, modifier = Modifier.weight(1f)) { Text("Export JSON") }
                }
            }
        }

        item { SectionHeader("Document overview") }
        item { OverviewPanel(report) }

        if (onComparePages != null && report.findings.any { it.regions.isNotEmpty() } && report.comparison?.referenceKind.let { it == null || it !in setOf(com.docintegrity.forensics.compare.ReferenceKind.PDF, com.docintegrity.forensics.compare.ReferenceKind.IMAGE) }) {
            item { OutlinedButton(onClick = onComparePages, modifier = Modifier.fillMaxWidth()) { Text("View pages with highlighted regions") } }
        }
        report.comparison?.takeIf { it.referenceKind != null }?.let { c ->
            item { SectionHeader("File comparison", "Compared with the trusted reference you supplied") }
            item { BytesVersusMeaning(c) }
            if (c.sideBySide != null && c.textHunks.isNotEmpty()) item { SideBySideText(c) }
            if (onComparePages != null && c.referenceKind in setOf(com.docintegrity.forensics.compare.ReferenceKind.PDF, com.docintegrity.forensics.compare.ReferenceKind.IMAGE)) {
                item { OutlinedButton(onClick = onComparePages, modifier = Modifier.fillMaxWidth()) { Text("Compare rendered pages side by side") } }
            }
            val cmp = report.findings.filter { it.area == Area.COMPARISON }
            items(cmp, key = { "cmp-" + it.id + it.title }) { FindingCard(it) }
        }
        if (report.comparison?.referenceKind == null) {
            report.findings.firstOrNull { it.id == "CMP_NO_REFERENCE" }?.let { f ->
                item { SectionHeader("File comparison") }
                item { FindingCard(f, startExpanded = true) }
            }
        }

        item { SectionHeader("Digital signatures", "Cryptographic validity, certificate trust and the truth of the content are three different questions.") }
        if (report.signatures.isEmpty()) {
            report.findings.filter { it.area == Area.SIGNATURE }.forEach { f -> item(key = "sig0-" + f.id) { FindingCard(f, startExpanded = true) } }
        } else {
            items(report.signatures, key = { "sigres-" + it.objNum }) { SignatureCard(it, report.trust.description) }
            val sf = report.findings.filter { it.area == Area.SIGNATURE }
            items(sf, key = { "sigf-" + it.id + it.title }) { FindingCard(it) }
        }

        val tool = report.findings.filter { it.area == Area.CREATION_TOOL || it.area == Area.METADATA }
        if (tool.isNotEmpty()) {
            item { SectionHeader("Creation-tool and metadata evidence", "Self-asserted labels; they can be edited or forged.") }
            items(tool, key = { "tool-" + it.id + it.title }) { FindingCard(it) }
        }
        val rev = report.findings.filter { it.area == Area.REVISIONS || it.area == Area.STRUCTURE }
        if (rev.isNotEmpty()) {
            item { SectionHeader("Revisions and structure") }
            items(rev, key = { "rev-" + it.id + it.title }) { FindingCard(it) }
        }
        val content = report.findings.filter { it.area == Area.CONTENT || it.area == Area.FONTS || it.area == Area.IMAGE }
        if (content.isNotEmpty()) {
            item { SectionHeader("Content, fonts and images") }
            items(content, key = { "con-" + it.id + it.title }) { FindingCard(it) }
        }
        val other = report.findings.filter { it.area !in setOf(Area.CREATION_TOOL, Area.METADATA, Area.REVISIONS, Area.STRUCTURE, Area.CONTENT, Area.FONTS, Area.IMAGE, Area.COMPARISON, Area.SIGNATURE) }
        if (other.isNotEmpty()) {
            item { SectionHeader("Other findings") }
            items(other, key = { "oth-" + it.id + it.title }) { FindingCard(it) }
        }

        val regionRows = report.findings.flatMap { f -> f.regions.map { f to it } }
        if (regionRows.isNotEmpty()) {
            item { SectionHeader("Highlighted regions requiring review", "These are prompts for human review, not proof.") }
            item {
                Panel {
                    regionRows.take(24).forEach { (f, g) ->
                        Row(Modifier.padding(vertical = 3.dp)) {
                            Text("p.${g.page + 1}", Modifier.width(34.dp), style = MaterialTheme.typography.labelMedium, color = evidenceColor(f.evidence))
                            Text(g.label.ifEmpty { f.title }, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    if (regionRows.size > 24) Text("… ${regionRows.size - 24} more in the exported report", style = MaterialTheme.typography.labelSmall)
                    if (onComparePages != null) {
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = onComparePages, modifier = Modifier.fillMaxWidth()) { Text("Open pages with highlights") }
                    }
                }
            }
        }

        item { SectionHeader("Limitations") }
        item {
            Panel {
                report.standingLimitations.forEach {
                    Row(Modifier.padding(vertical = 3.dp)) { Text("•  ", style = MaterialTheme.typography.bodySmall); Text(it, style = MaterialTheme.typography.bodySmall) }
                }
                val lim = report.findings.filter { f -> f.evidence == EvidenceClass.LIMITATION }
                if (lim.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text("Specific to this file", style = MaterialTheme.typography.labelLarge, color = Forensic.colors.inconclusive)
                    lim.forEach { Row(Modifier.padding(vertical = 3.dp)) { Text("•  ", style = MaterialTheme.typography.bodySmall); Text("${it.title}: ${it.unknown}", style = MaterialTheme.typography.bodySmall) } }
                }
            }
        }
        item { SectionHeader("Reproducibility") }
        item {
            Panel {
                KeyValue("Tool", "${report.tool.name} ${report.tool.version}")
                KeyValue("Ruleset", report.tool.rulesetVersion)
                KeyValue("PDF library", report.tool.pdfboxAndroid)
                KeyValue("Crypto library", report.tool.bouncyCastle)
                KeyValue("Analysed at", report.tool.analysedAtIso)
                KeyValue("Checks run", report.checksRun.joinToString("; "))
            }
        }
        item { Spacer(Modifier.height(32.dp)) }
    }
}

@Composable
private fun EvidenceCounts(r: ForensicReport) {
    val by = r.findings.groupingBy { it.evidence }.eachCount()
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        for (e in listOf(EvidenceClass.ESTABLISHED, EvidenceClass.INDICATOR, EvidenceClass.LIMITATION, EvidenceClass.INFO)) {
            Pill("${by[e] ?: 0} ${e.label.lowercase()}", evidenceColor(e))
        }
    }
}

@Composable
private fun OverviewPanel(r: ForensicReport) {
    Panel {
        KeyValue("File", r.fileName)
        KeyValue("Size", "${r.hashes.size} bytes")
        if (r.isPdf) {
            KeyValue("PDF version", r.pdfVersion ?: "unknown")
            KeyValue("Pages", r.pageCount.toString())
            KeyValue("Revisions", if (r.revisions.size <= 1) "1 (no incremental updates)" else "${r.revisions.size} (${r.revisions.size - 1} incremental update(s))")
            r.metadata?.let { m ->
                m.info["Creator"]?.let { KeyValue("Creator", it) }
                m.info["Producer"]?.let { KeyValue("Producer", it) }
                m.creationDate?.let { KeyValue("Created", it.display()) }
                m.modDate?.let { KeyValue("Modified", it.display()) }
            }
        }
        Spacer(Modifier.height(6.dp))
        KeyValue("SHA-256", r.hashes.sha256, mono = true)
        KeyValue("SHA-512", r.hashes.sha512, mono = true)
        KeyValue("SHA-1", r.hashes.sha1, mono = true)
        KeyValue("MD5", r.hashes.md5, mono = true)
    }
}
