package com.docintegrity.app

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.engine.ForensicReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface UiState {
    data object Idle : UiState
    data class Working(val message: String) : UiState
    data class Done(val report: ForensicReport) : UiState
    data class Failed(val message: String) : UiState
}

class AnalysisViewModel(app: Application) : AndroidViewModel(app) {
    private val _state = MutableStateFlow<UiState>(UiState.Idle)
    val state: StateFlow<UiState> = _state

    companion object { const val MAX_BYTES = 128L * 1024 * 1024 }

    /** Reads the chosen document into memory (never copied to storage) and analyses it locally. */
    fun analyze(uri: Uri) {
        _state.value = UiState.Working("Reading document…")
        viewModelScope.launch {
            try {
                val (name, bytes) = withContext(Dispatchers.IO) { read(uri) }
                _state.value = UiState.Working("Analysing ${bytes.size / 1024} KB on this device…")
                val report = withContext(Dispatchers.Default) { ForensicEngine().analyze(bytes, name) }
                _state.value = UiState.Done(report)
            } catch (e: Throwable) {
                _state.value = UiState.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    fun reset() { _state.value = UiState.Idle }

    private fun read(uri: Uri): Pair<String, ByteArray> {
        val cr = getApplication<Application>().contentResolver
        var name = "document"
        var size = -1L
        cr.query(uri, null, null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                c.getColumnIndex(OpenableColumns.DISPLAY_NAME).takeIf { it >= 0 }?.let { name = c.getString(it) ?: name }
                c.getColumnIndex(OpenableColumns.SIZE).takeIf { it >= 0 }?.let { size = c.getLong(it) }
            }
        }
        if (size > MAX_BYTES) error("File is larger than ${MAX_BYTES / 1024 / 1024} MB; not loaded.")
        val bytes = cr.openInputStream(uri)?.use { it.readBytes() } ?: error("Could not open the document.")
        if (bytes.size > MAX_BYTES) error("File is larger than ${MAX_BYTES / 1024 / 1024} MB; not loaded.")
        return name to bytes
    }
}
