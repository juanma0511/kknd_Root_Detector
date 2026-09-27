package com.juanma0511.rootdetector.internal

import com.juanma0511.rootdetector.model.CheckResult
import com.juanma0511.rootdetector.model.CheckStatus
import com.juanma0511.rootdetector.model.ScanResult
import com.juanma0511.rootdetector.model.ScanStatus
import com.juanma0511.rootdetector.model.ScanSummary
import com.juanma0511.rootdetector.model.Severity

internal object ResultAggregator {

    fun build(
        checks: List<CheckResult>,
        scanDurationMs: Long,
        timestamp: Long = System.currentTimeMillis()
    ): ScanResult {
        val summary = ScanSummary(
            totalChecks = checks.size,
            detectedChecks = checks.count { it.detected },
            highRiskDetections = checks.count { it.detected && it.severity == Severity.HIGH },
            warningDetections = checks.count { it.detected && it.severity == Severity.WARNING },
            failedChecks = checks.count { it.status == CheckStatus.ERROR },
            skippedChecks = checks.count { it.status == CheckStatus.SKIPPED },
            unsupportedChecks = checks.count { it.status == CheckStatus.UNSUPPORTED }
        )

        val status = when {
            summary.highRiskDetections > 0 -> ScanStatus.ROOTED
            summary.detectedChecks > 0 -> ScanStatus.SUSPICIOUS
            summary.failedChecks > 0 || summary.skippedChecks > 0 -> ScanStatus.INCOMPLETE
            else -> ScanStatus.CLEAN
        }

        return ScanResult(
            status = status,
            checks = checks,
            summary = summary,
            scanDurationMs = scanDurationMs,
            timestamp = timestamp
        )
    }
}
