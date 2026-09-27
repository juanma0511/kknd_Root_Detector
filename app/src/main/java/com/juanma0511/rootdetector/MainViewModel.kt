package com.juanma0511.rootdetector

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.juanma0511.rootdetector.detector.HwSecurityDetector
import com.juanma0511.rootdetector.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val hwDetector = HwSecurityDetector(application)

    private val _scanState = MutableStateFlow(ScanState.IDLE)
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()

    private val _scanProgress = MutableStateFlow(0)
    val scanProgress: StateFlow<Int> = _scanProgress.asStateFlow()

    private val _scanResult = MutableStateFlow<ScanResult?>(null)
    val scanResult: StateFlow<ScanResult?> = _scanResult.asStateFlow()

    private val _hwScanState = MutableStateFlow(HwScanState.IDLE)
    val hwScanState: StateFlow<HwScanState> = _hwScanState.asStateFlow()

    private val _hwScanProgress = MutableStateFlow(0)
    val hwScanProgress: StateFlow<Int> = _hwScanProgress.asStateFlow()

    private val _hwScanResult = MutableStateFlow<HwScanResult?>(null)
    val hwScanResult: StateFlow<HwScanResult?> = _hwScanResult.asStateFlow()

    fun startScan() {
        _scanState.value = ScanState.SCANNING
        _scanProgress.value = 0
        _scanResult.value = null

        RootDetector.scan(
            getApplication(),
            ScanProgressListener { progress ->
                _scanProgress.value = progress
            },
            ScanCallback { result ->
                _scanProgress.value = 100
                _scanResult.value = result
                _scanState.value = ScanState.DONE
            }
        )
    }

    fun resetRootScan() {
        _scanState.value = ScanState.IDLE
        _scanProgress.value = 0
        _scanResult.value = null
    }

    fun startHwScan() {
        viewModelScope.launch {
            _hwScanState.value = HwScanState.SCANNING
            _hwScanProgress.value = 0
            _hwScanResult.value = null

            val items = withContext(Dispatchers.IO) {
                hwDetector.runAllChecks { p -> _hwScanProgress.value = (p * 0.9).toInt() }
            }

            _hwScanProgress.value = 100
            delay(300)
            
            _hwScanResult.value = HwScanResult(
                items = items,
                scanDurationMs = 0
            )
            _hwScanState.value = HwScanState.DONE
        }
    }

    fun resetHwScan() {
        _hwScanState.value = HwScanState.IDLE
        _hwScanProgress.value = 0
        _hwScanResult.value = null
    }
}
