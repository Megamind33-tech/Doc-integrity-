package com.docintegrity.app

import android.app.Application
import android.graphics.Bitmap
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.docintegrity.forensics.compare.ReferenceFile
import com.docintegrity.forensics.compare.ReferenceInput
import com.docintegrity.forensics.engine.ForensicEngine
import com.docintegrity.forensics.engine.ForensicReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The trusted reference the examiner is assembling. Everything is held in memory only. */
data class ReferenceDraft(
    val fileName: String? = null,
    val fileBytes: ByteArray? = null,
    val hashText: String = "",
    val issuerFields: List<Pair<String, String>> = listOf("" to ""),
) {
    fun toInput() = ReferenceInput(
        file = if (fileName != null && fileBytes != null) ReferenceFile(fileName, fileBytes) else null,
        hashes = hashText.split(Regex("[\\s,;]+")).filter { it.isNotBlank() },
        issuerRecord = issuerFields.filter { it.first.isNotBlank() && it.second.isNotBlank() }.toMap(),
    )
}

sealed interface UiState {
    data object Idle : UiState
    data class Setup(val name: String, val bytes: ByteArray, val reference: ReferenceDraft = ReferenceDraft()) : UiState
    data class Working(val message: String) : UiState
    data class Done(val report: ForensicReport, val examined: ByteArray, val reference: ByteArray?) : UiState
    data class Failed(val message: String) : UiState
}

class AnalysisViewModel(app: Application) : AndroidViewModel(app) {
    private val _state = MutableStateFlow<UiState>(UiState.Idle)
    val state: StateFlow<UiState> = _state
    private val temp = SecureTempFiles(app)
    private val renderer = AndroidPageRenderer(temp)

    companion object { const val MAX_BYTES = 128L * 1024 * 1024 }

    /** Reads the chosen document into memory (never copied to storage). */
    fun choose(uri: Uri) {
        _state.value = UiState.Working("Reading document…")
        viewModelScope.launch {
            try {
                val (name, bytes) = withContext(Dispatchers.IO) { read(uri) }
                _state.value = UiState.Setup(name, bytes)
            } catch (e: Throwable) { _state.value = UiState.Failed(e.message ?: e.javaClass.simpleName) }
        }
    }

    fun chooseReference(uri: Uri) {
        val s = _state.value as? UiState.Setup ?: return
        viewModelScope.launch {
            try {
                val (name, bytes) = withContext(Dispatchers.IO) { read(uri) }
                _state.value = s.copy(reference = s.reference.copy(fileName = name, fileBytes = bytes))
            } catch (e: Throwable) { _state.value = UiState.Failed(e.message ?: e.javaClass.simpleName) }
        }
    }

    fun updateReference(f: (ReferenceDraft) -> ReferenceDraft) {
        val s = _state.value as? UiState.Setup ?: return
        _state.value = s.copy(reference = f(s.reference))
    }

    fun analyze() {
        val s = _state.value as? UiState.Setup ?: return
        _state.value = UiState.Working("Analysing ${s.bytes.size / 1024} KB on this device…")
        viewModelScope.launch {
            try {
                val ref = s.reference.toInput()
                val report = withContext(Dispatchers.Default) { ForensicEngine().analyze(s.bytes, s.name, ref, renderer) }
                _state.value = UiState.Done(report, s.bytes, s.reference.fileBytes)
            } catch (e: Throwable) { _state.value = UiState.Failed(e.message ?: e.javaClass.simpleName) }
        }
    }

    /** Renders a page of the examined (or reference) PDF for the comparison view. */
    suspend fun renderPage(pdfBytes: ByteArray, page: Int, widthPx: Int): Bitmap? = withContext(Dispatchers.IO) { renderer.renderBitmap(pdfBytes, page, widthPx) }

    fun reset() { temp.wipeAll(); _state.value = UiState.Idle }

    override fun onCleared() { temp.wipeAll(); super.onCleared() }

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
