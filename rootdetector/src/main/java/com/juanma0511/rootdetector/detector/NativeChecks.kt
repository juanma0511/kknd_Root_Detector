package com.juanma0511.rootdetector.detector

import com.juanma0511.rootdetector.model.CheckCategory
import com.juanma0511.rootdetector.model.CheckResult
import com.juanma0511.rootdetector.model.CheckStatus
import com.juanma0511.rootdetector.model.Severity

class NativeChecks {

    companion object {
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

    private external fun runNativeChecks(): Array<String>

    fun run(): List<CheckResult> {
        if (!libLoaded) {
            return listOf(
                CheckResult(
                    id = "native_engine",
                    name = "Native detection engine",
                    description = "Native root checks could not be loaded",
                    category = CheckCategory.SCANNER,
                    severity = Severity.HIGH,
                    status = CheckStatus.ERROR,
                    detail = libError
                )
            )
        }

        return try {
            val raw = runNativeChecks()
            if (raw.isEmpty()) {
                listOf(
                    CheckResult(
                        id = "native_engine",
                        name = "Native detection engine",
                        description = "Native checks completed without positive detections",
                        category = CheckCategory.SCANNER,
                        severity = Severity.WARNING,
                        status = CheckStatus.NOT_DETECTED
                    )
                )
            } else {
                raw.mapNotNull { entry ->
                    val parts = entry.split('|', limit = 3)
                    if (parts.size < 3) return@mapNotNull null
                    val id = parts[0]
                    val name = parts[1]
                    val desc = parts[2]

                    CheckResult(
                        id = "native_$id",
                        name = name,
                        description = desc,
                        category = classifyCategory(name),
                        severity = classifySeverity(name),
                        status = CheckStatus.DETECTED,
                        detail = desc,
                        evidence = mapOf("nativeId" to id)
                    )
                }
            }
        } catch (e: Throwable) {
            listOf(
                CheckResult(
                    id = "native_engine",
                    name = "Native checks error",
                    description = "Native root checks failed while executing",
                    category = CheckCategory.SCANNER,
                    severity = Severity.HIGH,
                    status = CheckStatus.ERROR,
                    detail = e.message
                )
            )
        }
    }

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
        name.contains("Bootloader", ignoreCase = true) ||
        name.contains("PTY", ignoreCase = true)             -> Severity.WARNING
        else                                                 -> Severity.HIGH
    }
}
