package com.docintegrity.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import com.docintegrity.app.ui.ForensicsTheme
import com.docintegrity.app.ui.HomeScreen
import com.docintegrity.app.ui.PageCompareScreen
import com.docintegrity.app.ui.ReportScreen
import com.docintegrity.app.ui.SetupScreen
import com.docintegrity.app.ui.WorkingScreen

class MainActivity : ComponentActivity() {
    private val vm: AnalysisViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ForensicsTheme {
                Surface(Modifier.fillMaxSize(), color = androidx.compose.material3.MaterialTheme.colorScheme.background) { Root() }
            }
        }
    }

    @Composable
    private fun Root() {
        val state by vm.state.collectAsState()
        var comparing by remember { mutableStateOf(false) }
        // OpenDocument gives read access to exactly the file the user picked; no storage permission is requested.
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) vm.choose(uri) }
        val refPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) vm.chooseReference(uri) }
        val pickPdf = { picker.launch(arrayOf("application/pdf")) }
        val refTypes = arrayOf("application/pdf", "image/*", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        when (val s = state) {
            is UiState.Idle -> HomeScreen(onPick = pickPdf, error = null)
            is UiState.Failed -> HomeScreen(onPick = pickPdf, error = s.message)
            is UiState.Working -> WorkingScreen(s.message)
            is UiState.Setup -> { BackHandler { vm.reset() }
                SetupScreen(s.name, s.bytes.size, s.reference, { refPicker.launch(refTypes) }, { vm.updateReference { it.copy(fileName = null, fileBytes = null) } }, { f -> vm.updateReference(f) }, vm::analyze, vm::reset) }
            is UiState.Done -> {
                if (comparing) {
                    BackHandler { comparing = false }
                    val regions = s.report.findings.flatMap { it.regions }
                    PageCompareScreen(
                        pageCount = s.report.pageCount.coerceAtLeast(1), regions = regions,
                        loadExamined = { p, w -> vm.renderPage(s.examined, p, w) },
                        loadReference = s.reference?.takeIf { s.report.comparison?.referenceKind == com.docintegrity.forensics.compare.ReferenceKind.PDF }?.let { rb -> { p: Int, w: Int -> vm.renderPage(rb, p, w) } },
                        onClose = { comparing = false },
                    )
                } else {
                    BackHandler { vm.reset() }
                    ReportScreen(s.report, onClose = vm::reset, onComparePages = { comparing = true })
                }
            }
        }
    }
}
