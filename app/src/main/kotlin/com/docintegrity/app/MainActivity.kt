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
import androidx.compose.ui.platform.LocalContext
import com.docintegrity.app.ui.ForensicsTheme
import com.docintegrity.app.ui.HomeScreen
import com.docintegrity.app.ui.ReportScreen
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
        // OpenDocument gives read access to exactly the file the user picked; no storage permission is requested.
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) vm.analyze(uri) }
        when (val s = state) {
            is UiState.Idle -> HomeScreen(onPick = { picker.launch(arrayOf("application/pdf", "*/*")) }, error = null)
            is UiState.Failed -> HomeScreen(onPick = { picker.launch(arrayOf("application/pdf", "*/*")) }, error = s.message)
            is UiState.Working -> WorkingScreen(s.message)
            is UiState.Done -> { BackHandler { vm.reset() }; ReportScreen(s.report, onClose = vm::reset) }
        }
    }
}
