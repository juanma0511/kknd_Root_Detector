package com.juanma0511.rootdetector

import android.content.Context
import android.os.Handler
import android.os.Looper
import com.juanma0511.rootdetector.internal.ResultAggregator
import com.juanma0511.rootdetector.model.CheckCategory
import com.juanma0511.rootdetector.model.CheckResult
import com.juanma0511.rootdetector.model.CheckStatus
import com.juanma0511.rootdetector.model.Severity
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Public entry point for a full root/integrity scan.
 *
 * Scans run off the main thread. Progress and completion callbacks are delivered
 * on the main thread. The library does not retain the latest result.
 */
object RootDetector {

    private val executor: ExecutorService = Executors.newCachedThreadPool()
    private val mainHandler = Handler(Looper.getMainLooper())

    @JvmStatic
    fun scan(context: Context, callback: ScanCallback) {
        scan(context, ScanProgressListener { }, callback)
    }

    @JvmStatic
    fun scan(
        context: Context,
        progressListener: ScanProgressListener,
        callback: ScanCallback
    ) {
        val appContext = context.applicationContext

        executor.execute {
            val startedAt = System.currentTimeMillis()

            val checks = try {
                com.juanma0511.rootdetector.detector.RootDetector(appContext).runAllChecks { progress ->
                    mainHandler.post { progressListener.onProgress(progress.coerceIn(0, 100)) }
                }
            } catch (error: Throwable) {
                listOf(
                    CheckResult(
                        id = "scanner.unhandled_error",
                        name = "Root scan failed",
                        description = "The scan engine stopped because of an unexpected error",
                        category = CheckCategory.SCANNER,
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        detail = error.message ?: error.javaClass.name,
                        evidence = mapOf("exception" to error.javaClass.name)
                    )
                )
            }

            val result = ResultAggregator.build(
                checks = checks,
                scanDurationMs = System.currentTimeMillis() - startedAt
            )

            mainHandler.post {
                progressListener.onProgress(100)
                callback.onComplete(result)
            }
        }
    }
}
