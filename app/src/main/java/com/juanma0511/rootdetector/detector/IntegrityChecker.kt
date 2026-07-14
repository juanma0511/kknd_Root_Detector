package com.juanma0511.rootdetector.detector

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.juanma0511.rootdetector.model.DetectionCategory
import com.juanma0511.rootdetector.model.DetectionItem
import com.juanma0511.rootdetector.model.Severity
import java.io.File
import java.security.MessageDigest

class IntegrityChecker(private val context: Context) {

    fun runAllChecks(): List<DetectionItem> {
        val items = mutableListOf<DetectionItem>()
        items += checkApkSignature()
        items += checkClassLoader()
        items += checkDexIntegrity()
        items += checkTrustStore()
        return items
    }

    private fun checkApkSignature(): DetectionItem {
        return try {
            val pm = context.packageManager
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                info.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info.signatures
            }

            if (signatures.isNullOrEmpty()) {
                return det("sig_missing", "APK Signature Missing",
                    "No signatures found — APK may have been stripped",
                    Severity.HIGH, true, "Signatures array is null or empty")
            }

            val cert = signatures[0].toByteArray()
            val sha256 = MessageDigest.getInstance("SHA-256")
                .digest(cert)
                .joinToString("") { "%02x".format(it) }

            val prefs = context.getSharedPreferences("integrity_baseline", Context.MODE_PRIVATE)
            val baseline = prefs.getString("apk_sig_sha256", null)

            if (baseline == null) {

                prefs.edit().putString("apk_sig_sha256", sha256).apply()
                det("apk_sig", "APK Signature",
                    "Signature recorded as baseline on first run",
                    Severity.WARNING, false, "SHA-256: ${sha256.take(16)}…")
            } else if (baseline != sha256) {
                det("apk_sig_mismatch", "APK Signature Changed",
                    "Signature differs from baseline — APK was patched or re-signed",
                    Severity.HIGH, true,
                    "Expected: ${baseline.take(16)}…\nGot: ${sha256.take(16)}…")
            } else {
                det("apk_sig", "APK Signature Valid",
                    "Signature matches baseline",
                    Severity.WARNING, false, "SHA-256: ${sha256.take(16)}…")
            }
        } catch (e: Exception) {
            det("apk_sig_error", "APK Signature Check Failed",
                "Could not verify APK signature: ${e.message}",
                Severity.WARNING, false, e.message)
        }
    }

    private fun checkClassLoader(): DetectionItem {
        val cl = context.classLoader
        val clName = cl.javaClass.name
        val clStr = cl.toString()

        val legit = listOf(
            "dalvik.system.PathClassLoader",
            "dalvik.system.DexClassLoader",
            "dalvik.system.BaseDexClassLoader",
            "com.android.internal.os.ClassLoaderFactory"
        )

        if (legit.none { clName.startsWith(it) }) {
            return det("classloader_hook", "ClassLoader Replaced",
                "Non-standard ClassLoader detected — Xposed/LSPosed hook likely",
                Severity.HIGH, true,
                "ClassLoader: $clName\n$clStr")
        }

        val apkPath = context.packageCodePath
        if (!clStr.contains(apkPath) && !clStr.contains(context.packageName)) {
            return det("classloader_path", "ClassLoader Path Anomaly",
                "ClassLoader doesn't reference our APK path",
                Severity.WARNING, true,
                "Expected path: $apkPath\nClassLoader: $clStr")
        }

        return det("classloader_ok", "ClassLoader Integrity",
            "ClassLoader is standard PathClassLoader pointing to correct APK",
            Severity.WARNING, false, clName)
    }

    private fun checkDexIntegrity(): DetectionItem {
        return try {
            val apkFile = File(context.packageCodePath)

            if (!apkFile.exists()) {
                return det("apk_missing", "APK File Missing",
                    "APK file not found at expected path — very suspicious",
                    Severity.HIGH, true, context.packageCodePath)
            }

            val apkSize = apkFile.length()
            val apkLastModified = apkFile.lastModified()
            val prefs = context.getSharedPreferences("integrity_baseline", Context.MODE_PRIVATE)

            val currentVersion = if (Build.VERSION.SDK_INT >= 28) {
                context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(context.packageName, 0).versionCode.toLong()
            }

            val savedVersion = prefs.getLong("apk_version_code", -1L)
            val savedModified = prefs.getLong("apk_last_modified", -1L)

            val isNewInstall = savedVersion != currentVersion || savedModified != apkLastModified

            if (isNewInstall) {
                prefs.edit()
                    .putLong("apk_size", apkSize)
                    .putLong("apk_version_code", currentVersion)
                    .putLong("apk_last_modified", apkLastModified)
                    .apply()
                return det("apk_size", "APK Baseline Updated",
                    "New install or update detected — baseline reset",
                    Severity.WARNING, false, "v$currentVersion · $apkSize bytes")
            }

            val baselineSize = prefs.getLong("apk_size", -1L)

            if (baselineSize == -1L) {
                prefs.edit().putLong("apk_size", apkSize).apply()
                det("apk_size", "APK Size Recorded",
                    "APK size recorded as baseline",
                    Severity.WARNING, false, "Size: $apkSize bytes")
            } else if (apkSize != baselineSize) {
                det("apk_size_changed", "APK Size Changed",
                    "APK size differs from baseline — LSPatch or module injection detected",
                    Severity.HIGH, true,
                    "Baseline: $baselineSize bytes\nCurrent: $apkSize bytes\nDiff: ${apkSize - baselineSize} bytes")
            } else {
                det("apk_size_ok", "APK File Integrity",
                    "APK size matches baseline",
                    Severity.WARNING, false, "Size: $apkSize bytes")
            }
        } catch (e: Exception) {
            det("apk_size_error", "APK Integrity Check Failed",
                "Error checking APK file: ${e.message}",
                Severity.WARNING, false, e.message)
        }
    }

    private fun checkTrustStore(): DetectionItem {
        return try {
            val userCaDir = File("/data/misc/user/0/cacerts-added")
            val certs = if (userCaDir.exists() && userCaDir.isDirectory) {
                userCaDir.listFiles()?.filter { it.isFile } ?: emptyList()
            } else emptyList()

            if (certs.isNotEmpty()) {
                det("user_ca_kt", "User CA Certificates (${certs.size})",
                    "User-installed CA certs enable SSL interception (Burp/Charles/mitmproxy)",
                    Severity.HIGH, true,
                    "${certs.size} cert(s) in /data/misc/user/0/cacerts-added")
            } else {
                det("user_ca_ok", "Trust Store Clean",
                    "No user-installed CA certificates found",
                    Severity.WARNING, false, null)
            }
        } catch (e: Exception) {
            det("user_ca_error", "Trust Store Check Failed",
                "Could not check user CA directory",
                Severity.WARNING, false, e.message)
        }
    }

    private fun det(
        id: String, name: String, desc: String,
        sev: Severity, detected: Boolean, detail: String?
    ) = DetectionItem(
        id = id, name = name, description = desc,
        category = DetectionCategory.MAGISK,
        severity = sev, detected = detected, detail = detail
    )
}
