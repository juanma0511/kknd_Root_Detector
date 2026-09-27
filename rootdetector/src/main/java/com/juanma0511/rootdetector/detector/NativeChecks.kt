package com.juanma0511.rootdetector.detector

import com.juanma0511.rootdetector.model.CheckCategory
import com.juanma0511.rootdetector.model.CheckResult
import com.juanma0511.rootdetector.model.CheckStatus
import com.juanma0511.rootdetector.model.Severity

internal class NativeChecks {

    companion object {
        private const val FIELD_SEPARATOR = '\u001F'

        private var libLoaded = false
        private var libError: String? = null

        init {
            try {
                System.loadLibrary("rootdetector")
                libLoaded = true
            } catch (e: UnsatisfiedLinkError) {
                libError = e.message
            }
        }

        fun isAvailable() = libLoaded
        fun loadError() = libError
    }

    private data class NativeSignal(
        val id: String,
        val name: String,
        val detail: String
    )

    private external fun runNativeChecks(): Array<String>

    fun run(): List<CheckResult> {
        if (!libLoaded) {
            return listOf(nativeEngineError("Native root checks could not be loaded", libError))
        }

        return try {
            val raw = runNativeChecks()
            if (raw.isEmpty()) {
                listOf(
                    nativeEngineError(
                        description = "Native root checks returned no task results",
                        detail = "JNI call completed, but the native task result array was empty"
                    )
                )
            } else {
                raw.mapIndexed { index, entry ->
                    parseTaskResult(entry) ?: CheckResult(
                        id = "native_protocol_$index",
                        name = "Native result protocol error",
                        description = "A native task returned a malformed result",
                        category = CheckCategory.SCANNER,
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        detail = entry.take(300),
                        evidence = mapOf("rawIndex" to index.toString())
                    )
                }
            }
        } catch (e: Throwable) {
            listOf(
                nativeEngineError(
                    description = "Native root checks failed while executing",
                    detail = e.message ?: e.javaClass.name
                )
            )
        }
    }

    private fun parseTaskResult(entry: String): CheckResult? {
        val parts = entry.split(FIELD_SEPARATOR)
        if (parts.size < 5) return null

        val taskId = parts[0]
        val rawStatus = parts[1]
        val taskName = parts[2]
        val taskDetail = parts[3]
        val signalCount = parts[4].toIntOrNull() ?: return null
        val requiredParts = 5 + (signalCount * 3)
        if (signalCount < 0 || parts.size < requiredParts) return null

        val signals = ArrayList<NativeSignal>(signalCount)
        var offset = 5
        repeat(signalCount) {
            signals += NativeSignal(
                id = parts[offset],
                name = parts[offset + 1],
                detail = parts[offset + 2]
            )
            offset += 3
        }

        val status = runCatching { CheckStatus.valueOf(rawStatus) }
            .getOrDefault(CheckStatus.ERROR)

        val classifierText = signals.firstOrNull()?.name ?: taskName

        val severity = if (status == CheckStatus.DETECTED && signals.isNotEmpty()) {
            if (signals.any { classifySeverity(it.name) == Severity.HIGH }) {
                Severity.HIGH
            } else {
                Severity.WARNING
            }
        } else {
            classifySeverity(taskName)
        }

        val evidence = linkedMapOf<String, String>(
            "nativeTask" to taskId,
            "nativeStatus" to rawStatus,
            "signalCount" to signals.size.toString()
        )
        signals.forEachIndexed { index, signal ->
            evidence["signal.$index.id"] = signal.id
            evidence["signal.$index.name"] = signal.name
            evidence["signal.$index.detail"] = signal.detail
        }

        val detectedDetail = signals.joinToString("\n") { signal ->
            "[${signal.id}] ${signal.name}: ${signal.detail}"
        }

        return CheckResult(
            id = "native_$taskId",
            name = taskName,
            description = when (status) {
                CheckStatus.DETECTED -> "Native check reported ${signals.size} detection signal(s)"
                CheckStatus.NOT_DETECTED -> "Native check completed without detections"
                CheckStatus.ERROR -> "Native check failed while executing"
                CheckStatus.SKIPPED -> "Native check was skipped"
                CheckStatus.UNSUPPORTED -> "Native check is not supported on this device"
            },
            category = classifyCategory(classifierText),
            severity = severity,
            status = status,
            detail = if (signals.isNotEmpty()) detectedDetail else taskDetail.ifBlank { null },
            evidence = evidence
        )
    }

    private fun nativeEngineError(description: String, detail: String?): CheckResult = CheckResult(
        id = "native_engine",
        name = "Native detection engine",
        description = description,
        category = CheckCategory.SCANNER,
        severity = Severity.HIGH,
        status = CheckStatus.ERROR,
        detail = detail
    )

    private fun classifyCategory(name: String): CheckCategory = when {
        name.contains("Frida", ignoreCase = true) ||
        name.contains("Port", ignoreCase = true)            -> CheckCategory.FRIDA
        name.contains("Magisk", ignoreCase = true) ||
        name.contains("Zygisk", ignoreCase = true) ||
        name.contains("Socket", ignoreCase = true) ||
        name.contains("Mount", ignoreCase = true) ||
        name.contains("Cgroup", ignoreCase = true) ||
        name.contains("Hidden Process", ignoreCase = true)  -> CheckCategory.MAGISK
        name.contains("KernelSU", ignoreCase = true) ||
        name.contains("KSU", ignoreCase = true) ||
        name.contains("APatch", ignoreCase = true) ||
        name.contains("jbd2", ignoreCase = true)            -> CheckCategory.MAGISK
        name.contains("SU", ignoreCase = true) ||
        name.contains("Root File", ignoreCase = true) ||
        name.contains("Root Binar", ignoreCase = true) ||
        name.contains("Root Process", ignoreCase = true) ||
        name.contains("Root Daemon", ignoreCase = true)     -> CheckCategory.SU_BINARIES
        name.contains("Prop", ignoreCase = true) ||
        name.contains("resetprop", ignoreCase = true) ||
        name.contains("SELinux", ignoreCase = true) ||
        name.contains("Kernel", ignoreCase = true) ||
        name.contains("AVB", ignoreCase = true) ||
        name.contains("Bootloader", ignoreCase = true) ||
        name.contains("dm-verity", ignoreCase = true)       -> CheckCategory.SYSTEM_PROPS
        name.contains("Custom ROM", ignoreCase = true) ||
        name.contains("Third-party ROM", ignoreCase = true) ||
        name.contains("LineageOS", ignoreCase = true) ||
        name.contains("ROM", ignoreCase = true)             -> CheckCategory.CUSTOM_ROM
        name.contains("Injected", ignoreCase = true) ||
        name.contains("RWX", ignoreCase = true) ||
        name.contains("Hook", ignoreCase = true) ||
        name.contains("Bridge", ignoreCase = true) ||
        name.contains("Trace", ignoreCase = true) ||
        name.contains("PTY", ignoreCase = true) ||
        name.contains("Env", ignoreCase = true)             -> CheckCategory.MAGISK
        else                                                 -> CheckCategory.MAGISK
    }

    private fun classifySeverity(name: String): Severity = when {
        name.contains("prctl", ignoreCase = true) ||
        name.contains("kill 0x", ignoreCase = true) ||
        name.contains("SU Exec", ignoreCase = true) ||
        name.contains("Magisk Socket", ignoreCase = true) ||
        name.contains("Mount Loophole", ignoreCase = true) ||
        name.contains("resetprop", ignoreCase = true) ||
        name.contains("Frida", ignoreCase = true) ||
        name.contains("uid=0", ignoreCase = true)           -> Severity.HIGH
        name.contains("Custom ROM", ignoreCase = true) ||
        name.contains("Third-party ROM", ignoreCase = true) ||
        name.contains("Bootloader", ignoreCase = true) ||
        name.contains("PTY", ignoreCase = true)             -> Severity.WARNING
        else                                                 -> Severity.HIGH
    }
}
