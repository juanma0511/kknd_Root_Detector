package com.juanma0511.rootdetector.detector

import com.juanma0511.rootdetector.model.DetectionCategory
import com.juanma0511.rootdetector.model.DetectionItem
import com.juanma0511.rootdetector.model.Severity
import java.io.File

class OverlayFsDetector {

    fun detect(): DetectionItem {
        val evidence = linkedSetOf<String>()
        val trustedLocked = DetectorTrust.bootLooksTrustedLocked()

        try {
            File("/proc/mounts").forEachLine { line ->
                val parts = line.split(" ")
                if (parts.size < 4) return@forEachLine
                val device = parts[0]
                val mountPoint = parts[1]
                val fileSystem = parts[2]
                val options = parts[3]
                if (HardcodedSignals.protectedSystemPaths.any { mountPoint.startsWith(it) }) {
                    val signature = "$device $fileSystem $options ${line.lowercase()}"
                    if (DetectorTrust.hasRootMountSignal(signature, mountPoint, trustedLocked)) {
                        evidence += "$mountPoint [$device $fileSystem $options]"
                    }
                }
            }
        } catch (_: Exception) {}

        return DetectionItem(
            id = "overlayfs_system",
            name = "OverlayFS Modification",
            description = "System partitions backed by root-specific overlay, tmpfs, loop or adb staging traces",
            category = DetectionCategory.MOUNT_POINTS,
            severity = Severity.WARNING,
            detected = evidence.isNotEmpty(),
            detail = evidence.take(6).joinToString("\n").ifEmpty { null }
        )
    }
}
