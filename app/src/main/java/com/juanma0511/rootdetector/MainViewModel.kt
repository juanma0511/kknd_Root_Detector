package com.juanma0511.rootdetector

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import com.juanma0511.rootdetector.model.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class MainViewModel(application: Application) : AndroidViewModel(application) {

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
        _hwScanState.value = HwScanState.SCANNING
        _hwScanProgress.value = 0
        _hwScanResult.value = null

        HardwareSecurity.scan(
            getApplication(),
            ScanProgressListener { progress ->
                _hwScanProgress.value = progress
            },
            HwScanCallback { result ->
                _hwScanProgress.value = 100
                _hwScanResult.value = result
                _hwScanState.value = HwScanState.DONE
            }
        )
    }

    fun resetHwScan() {
        _hwScanState.value = HwScanState.IDLE
        _hwScanProgress.value = 0
        _hwScanResult.value = null
    }
}
