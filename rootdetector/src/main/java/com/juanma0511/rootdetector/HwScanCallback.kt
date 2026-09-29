package com.juanma0511.rootdetector

import com.juanma0511.rootdetector.model.HwScanResult

fun interface HwScanCallback {
    fun onComplete(result: HwScanResult)
}
