package com.juanma0511.rootdetector

import com.juanma0511.rootdetector.model.ScanResult

fun interface ScanCallback {
    fun onComplete(result: ScanResult)
}
