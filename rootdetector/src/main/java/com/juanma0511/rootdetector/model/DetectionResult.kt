package com.juanma0511.rootdetector.model

enum class CheckCategory {
    SU_BINARIES,
    ROOT_APPS,
    SYSTEM_PROPS,
    MOUNT_POINTS,
    BUILD_TAGS,
    BUSYBOX,
    WRITABLE_PATHS,
    MAGISK,
    FRIDA,
    EMULATOR,
    CUSTOM_ROM,
    INTEGRITY,
    SCANNER
}

enum class Severity {
    HIGH,
    WARNING
}

enum class CheckStatus {
    DETECTED,
    NOT_DETECTED,
    ERROR,
    SKIPPED,
    UNSUPPORTED
}

enum class ScanStatus {
    CLEAN,
    SUSPICIOUS,
    ROOTED,
    INCOMPLETE
}

data class CheckResult(
    val id: String,
    val name: String,
    val description: String,
    val category: CheckCategory,
    val severity: Severity,
    val status: CheckStatus,
    val detail: String? = null,
    val evidence: Map<String, String> = detail?.let { mapOf("detail" to it) } ?: emptyMap()
) {
    val detected: Boolean get() = status == CheckStatus.DETECTED
}

data class ScanSummary(
    val totalChecks: Int,
    val detectedChecks: Int,
    val highRiskDetections: Int,
    val warningDetections: Int,
    val failedChecks: Int,
    val skippedChecks: Int,
    val unsupportedChecks: Int
)

data class ScanResult(
    val status: ScanStatus,
    val checks: List<CheckResult>,
    val summary: ScanSummary,
    val scanDurationMs: Long,
    val timestamp: Long = System.currentTimeMillis()
) {
    val isRooted: Boolean get() = status == ScanStatus.ROOTED

    val isSuspicious: Boolean
        get() = status == ScanStatus.ROOTED || status == ScanStatus.SUSPICIOUS

    val detectedCount: Int get() = summary.detectedChecks
    val highRiskCount: Int get() = summary.highRiskDetections
    val warningCount: Int get() = summary.warningDetections
}
