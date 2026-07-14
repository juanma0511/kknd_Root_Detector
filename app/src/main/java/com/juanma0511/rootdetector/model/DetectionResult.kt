package com.juanma0511.rootdetector.model

enum class DetectionCategory {
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
    CUSTOM_ROM
}

enum class Severity { HIGH, WARNING }

data class DetectionItem(
    val id: String,
    val name: String,
    val description: String,
    val category: DetectionCategory,
    val severity: Severity,
    val detected: Boolean,
    val detail: String? = null
)

data class ScanResult(
    val items: List<DetectionItem>,
    val scanDurationMs: Long,
    val timestamp: Long = System.currentTimeMillis()
) {
    val isRooted: Boolean get() = items.any { it.detected && it.severity == Severity.HIGH }
    val isSuspicious: Boolean get() = items.any { it.detected }
    val detectedCount: Int get() = items.count { it.detected }
    val highRiskCount: Int get() = items.count { it.detected && it.severity == Severity.HIGH }
    val warningCount: Int get() = items.count { it.detected && it.severity == Severity.WARNING }
}

enum class ScanState { IDLE, SCANNING, DONE }
