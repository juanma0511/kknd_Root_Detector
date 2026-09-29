package com.juanma0511.rootdetector

import android.content.Context
import android.os.Handler
import android.os.Looper
import com.juanma0511.rootdetector.detector.HwSecurityDetector
import com.juanma0511.rootdetector.model.HwCheckItem
import com.juanma0511.rootdetector.model.HwCheckStatus
import com.juanma0511.rootdetector.model.HwGroup
import com.juanma0511.rootdetector.model.HwScanResult
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Public entry point for the hardware-security scan.
 *
 * Scans run off the main thread. Progress and completion callbacks are delivered
 * on the main thread. The library does not retain the latest result.
 */
object HardwareSecurity {

    private val executor: ExecutorService = Executors.newCachedThreadPool()
    private val mainHandler = Handler(Looper.getMainLooper())

    @JvmStatic
    fun scan(context: Context, callback: HwScanCallback) {
        scan(context, ScanProgressListener { }, callback)
    }

    @JvmStatic
    fun scan(
        context: Context,
        progressListener: ScanProgressListener,
        callback: HwScanCallback
    ) {
        val appContext = context.applicationContext

        executor.execute {
            val startedAt = System.currentTimeMillis()

            val items = try {
                HwSecurityDetector(appContext).runAllChecks { progress ->
                    mainHandler.post { progressListener.onProgress(progress.coerceIn(0, 100)) }
                }
            } catch (error: Throwable) {
                listOf(
                    HwCheckItem(
                        id = "hardware_scanner_error",
                        name = "Hardware security scan failed",
                        description = "The hardware-security scan stopped because of an unexpected error",
                        group = HwGroup.SYSTEM_PROPS,
                        status = HwCheckStatus.UNKNOWN,
                        value = "Error",
                        detail = error.message ?: error.javaClass.name
                    )
                )
            }

            val result = HwScanResult(
                items = items,
                scanDurationMs = System.currentTimeMillis() - startedAt
            )

            mainHandler.post {
                progressListener.onProgress(100)
                callback.onComplete(result)
            }
        }
    }
}
