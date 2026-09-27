package com.juanma0511.rootdetector.detector

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.juanma0511.rootdetector.model.HwCheckStatus
import com.juanma0511.rootdetector.model.HwCheckItem
import com.juanma0511.rootdetector.model.HwGroup
import java.io.BufferedReader
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.security.auth.x500.X500Principal

class HwSecurityDetector(private val context: Context) {

    fun runAllChecks(progressCallback: (Int) -> Unit = {}): List<HwCheckItem> {
        val checks = mutableListOf<() -> HwCheckItem>(
            ::checkTeeAvailability,
            ::checkKeystoreBacking,
            ::checkStrongBox,
            ::checkStrongBoxKey,
            ::checkVerifiedBootState,
            ::checkVerifiedBootKey,
            ::checkBootloaderState,
            ::checkDmVerity,
            ::checkVbmetaDigest,
            ::checkAvbVersion,
            ::checkEncryptionState,
            ::checkSecurityPatchLevel
        )
        val items = mutableListOf<HwCheckItem>()
        val total = (checks.size + 3).coerceAtLeast(1)
        var done = 0
        fun tick() { done++; progressCallback((done * 100) / total) }

        checks.forEach { check ->
            items += check().also { tick() }
        }

        val keyAttest = KeyAttestationChecker(context)
        items += keyAttest.checkKeyAttestationChain(strongBox = false).also { tick() }
        items += keyAttest.checkKeyAttestationChain(strongBox = true).also { tick() }
        items += keyAttest.checkRootCertTrust().also { tick() }

        return items
    }

    private fun isBootStateCompromised(): Boolean {
        val flashLocked = getProp("ro.boot.flash.locked").lowercase()
        val vbmetaState = getProp("ro.boot.vbmeta.device_state").lowercase()
        val verifiedBoot = getProp("ro.boot.verifiedbootstate").lowercase()
        val verityMode = getProp("ro.boot.veritymode").lowercase()
        val vbmetaDigest = getProp("ro.boot.vbmeta.digest").lowercase()
        val bootKey = getProp("ro.boot.bootkey").lowercase()
        val unlocked = flashLocked == "0" || vbmetaState == "unlocked"
        val badVerifiedBoot = verifiedBoot == "orange" || verifiedBoot == "red"
        val badVerity = verityMode == "disabled" || verityMode == "logging"
        val zeroDigest = vbmetaDigest.isNotEmpty() && vbmetaDigest != "unknown" && vbmetaDigest.all { it == '0' || it == ':' || it == '-' }
        val zeroBootKey = bootKey.isNotEmpty() && bootKey != "unknown" && bootKey.all { it == '0' || it == ':' || it == '-' }
        return unlocked || badVerifiedBoot || badVerity || zeroDigest || zeroBootKey
    }

    private fun checkTeeAvailability(): HwCheckItem {
        return try {
            val alias = "rootdetector_tee_probe"
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            keyStore.deleteEntry(alias)

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            kpg.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
            kpg.generateKeyPair()

            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            val privateKey = entry?.privateKey
            val keyInfo: KeyInfo? = if (privateKey != null) {
                val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                factory.getKeySpec(privateKey, KeyInfo::class.java)
            } else null
            keyStore.deleteEntry(alias)

            @Suppress("DEPRECATION")
            val inTee = keyInfo?.isInsideSecureHardware ?: false
            val compromisedBoot = isBootStateCompromised()
            val status = when {
                inTee && !compromisedBoot -> HwCheckStatus.PASS
                inTee -> HwCheckStatus.WARN
                !compromisedBoot -> HwCheckStatus.UNKNOWN
                else -> HwCheckStatus.WARN
            }

            HwCheckItem(
                id = "tee_available",
                name = "TEE (Trusted Execution Env.)",
                group = HwGroup.KEYSTORE,
                description = "Checks if keys can be backed by a hardware TEE",
                status = status,
                value = when {
                    inTee -> "Hardware-backed"
                    else -> "Software-only"
                },
                expected = "Hardware-backed preferred",
                detail = when {
                    inTee && compromisedBoot -> "Secure hardware exists, but direct boot-state properties still show compromise."
                    !inTee && !compromisedBoot -> "No hardware-backed TEE was exposed for this probe. This can be normal on some devices and should not be treated as a failure by itself."
                    !inTee && compromisedBoot -> "No hardware-backed TEE was exposed and boot-state properties look compromised."
                    else -> null
                }
            )
        } catch (e: Exception) {
            HwCheckItem(
                id = "tee_available",
                name = "TEE (Trusted Execution Env.)",
                group = HwGroup.KEYSTORE,
                description = "Checks if keys can be backed by a hardware TEE",
                status = HwCheckStatus.UNKNOWN,
                value = "Error: ${e.message?.take(50)}",
                detail = e.message
            )
        }
    }

    private fun checkKeystoreBacking(): HwCheckItem {
        return try {
            val alias = "rootdetector_ks_backing"
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            keyStore.deleteEntry(alias)

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
            kpg.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setKeySize(2048)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setCertificateSubject(X500Principal("CN=test"))
                    .build()
            )
            kpg.generateKeyPair()

            val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            val privateKey = entry?.privateKey
            val keyInfo: KeyInfo? = if (privateKey != null) {
                val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                factory.getKeySpec(privateKey, KeyInfo::class.java)
            } else null
            keyStore.deleteEntry(alias)

            @Suppress("DEPRECATION")
            val hwBacked = keyInfo?.isInsideSecureHardware == true
            val secLevelLabel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && keyInfo != null) {
                when (keyInfo.securityLevel) {
                    1 -> "SOFTWARE"
                    2 -> "TRUSTED_ENVIRONMENT (TEE)"
                    3 -> "STRONGBOX"
                    else -> if (hwBacked) "Hardware (TEE)" else "Software"
                }
            } else {
                if (hwBacked) "Hardware (TEE)" else "Software"
            }
            val secureLevel = hwBacked || secLevelLabel.contains("TEE") || secLevelLabel.contains("STRONGBOX")
            val compromisedBoot = isBootStateCompromised()
            val status = when {
                secureLevel && !compromisedBoot -> HwCheckStatus.PASS
                secureLevel -> HwCheckStatus.WARN
                !compromisedBoot -> HwCheckStatus.UNKNOWN
                else -> HwCheckStatus.WARN
            }

            HwCheckItem(
                id = "keystore_backing",
                name = "Keystore Security Level",
                group = HwGroup.KEYSTORE,
                description = "Reports the Android Keystore security level",
                status = status,
                value = secLevelLabel,
                expected = "TEE or StrongBox preferred",
                detail = when {
                    secureLevel && compromisedBoot -> "Secure keystore exists, but direct boot-state properties still look compromised."
                    !secureLevel && !compromisedBoot -> "Software keystore is exposed. This is weaker than TEE or StrongBox, but it can still be normal on some locked devices."
                    !secureLevel && compromisedBoot -> "Software keystore is exposed and direct boot-state properties look compromised."
                    else -> null
                }
            )
        } catch (e: Exception) {
            HwCheckItem(
                id = "keystore_backing",
                name = "Keystore Security Level",
                group = HwGroup.KEYSTORE,
                description = "Reports the security level of the Android Keystore",
                status = HwCheckStatus.UNKNOWN,
                value = "Error: ${e.message?.take(60)}"
            )
        }
    }

    private fun checkStrongBox(): HwCheckItem {
        val hasStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore")
        } else false

        return HwCheckItem(
            id = "strongbox_feature",
            name = "StrongBox Feature",
            group = HwGroup.KEYSTORE,
            description = "Checks if the device has a dedicated StrongBox security chip",
            status = if (hasStrongBox) HwCheckStatus.PASS else HwCheckStatus.UNKNOWN,
            value = if (hasStrongBox) "Present" else "Not available",
            expected = "Optional",
            detail = if (!hasStrongBox) "No dedicated StrongBox chip. TEE is used instead and that is normal on many devices." else null
        )
    }

    private fun checkStrongBoxKey(): HwCheckItem {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return HwCheckItem(
                id = "strongbox_key",
                name = "StrongBox Key Generation",
                group = HwGroup.KEYSTORE,
                description = "Attempts to generate a key in StrongBox",
                status = HwCheckStatus.UNKNOWN,
                value = "Android < 9",
                detail = "StrongBox-backed key generation is not available on this Android version"
            )
        }
        if (!context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore")) {
            return HwCheckItem(
                id = "strongbox_key",
                name = "StrongBox Key Generation",
                group = HwGroup.KEYSTORE,
                description = "Attempts to generate a key in StrongBox",
                status = HwCheckStatus.UNKNOWN,
                value = "Not available",
                detail = "This device does not advertise StrongBox-backed key generation"
            )
        }
        return try {
            val alias = "rootdetector_sb_key"
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            keyStore.deleteEntry(alias)

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            kpg.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setIsStrongBoxBacked(true)
                    .build()
            )
            kpg.generateKeyPair()
            keyStore.deleteEntry(alias)

            HwCheckItem(
                id = "strongbox_key",
                name = "StrongBox Key Generation",
                group = HwGroup.KEYSTORE,
                description = "Attempts to generate a key backed by StrongBox hardware",
                status = HwCheckStatus.PASS,
                value = "Success — key generated in StrongBox"
            )
        } catch (e: StrongBoxUnavailableException) {
            HwCheckItem(
                id = "strongbox_key",
                name = "StrongBox Key Generation",
                group = HwGroup.KEYSTORE,
                description = "Attempts to generate a key backed by StrongBox hardware",
                status = HwCheckStatus.UNKNOWN,
                value = "StrongBox unavailable",
                detail = "The device did not expose StrongBox-backed key generation"
            )
        } catch (e: Exception) {
            HwCheckItem(
                id = "strongbox_key",
                name = "StrongBox Key Generation",
                group = HwGroup.KEYSTORE,
                description = "Attempts to generate a key backed by StrongBox hardware",
                status = HwCheckStatus.FAIL,
                value = "Error",
                detail = e.message
            )
        }
    }

    private fun checkVerifiedBootState(): HwCheckItem {
        val state = getProp("ro.boot.verifiedbootstate")
            .ifEmpty { getProp("ro.boot.veritymode") }
            .ifEmpty { "unknown" }

        val status = when (state.lowercase()) {
            "green" -> HwCheckStatus.PASS
            "yellow" -> HwCheckStatus.WARN
            "orange", "red" -> HwCheckStatus.FAIL
            else -> HwCheckStatus.UNKNOWN
        }
        return HwCheckItem(
            id = "verified_boot_state",
            name = "Verified Boot State",
            group = HwGroup.BOOT,
            description = "ro.boot.verifiedbootstate — green=locked/unmodified, orange=unlocked",
            status = status,
            value = state.uppercase(),
            expected = "GREEN",
            detail = when (state.lowercase()) {
                "orange" -> "Bootloader is UNLOCKED."
                "red" -> "dm-verity FAILED — system may be tampered."
                "yellow" -> "Signed with custom key."
                else -> null
            }
        )
    }

    private fun checkVerifiedBootKey(): HwCheckItem {
        val key = getProp("ro.boot.vbmeta.digest")
            .ifEmpty { getProp("ro.boot.bootkey") }
            .ifEmpty { "unknown" }
        val invalidKey = key == "unknown" || key == "0" || key.all { it == '0' }
        return HwCheckItem(
            id = "verified_boot_key",
            name = "Verified Boot Key / Digest",
            group = HwGroup.BOOT,
            description = "ro.boot.vbmeta.digest and ro.boot.bootkey should not be unknown or all-zero on a healthy verified boot chain",
            status = if (invalidKey) HwCheckStatus.FAIL else HwCheckStatus.PASS,
            value = if (key.length > 32) key.take(16) + "…" + key.takeLast(8) else key,
            expected = "Known non-zero OEM digest",
            detail = when {
                key == "unknown" -> "Verified boot key or digest is unknown — hardware boot attestation is not trustworthy"
                else -> "Boot key or digest is all zeros — bootloader unlocked, bypassed or custom key likely"
            }.takeIf { invalidKey }
        )
    }

    private fun checkBootloaderState(): HwCheckItem {
        val state = getProp("ro.boot.flash.locked")
            .ifEmpty { getProp("ro.bootloader") }
            .ifEmpty { "unknown" }
        val locked = state == "1" || state.lowercase() == "locked"
        val unlocked = state == "0" || state.lowercase().contains("unlock")
        return HwCheckItem(
            id = "bootloader_state",
            name = "Bootloader Lock State",
            group = HwGroup.BOOT,
            description = "ro.boot.flash.locked — 1=locked (secure), 0=unlocked",
            status = when {
                locked -> HwCheckStatus.PASS
                unlocked -> HwCheckStatus.FAIL
                else -> HwCheckStatus.UNKNOWN
            },
            value = when {
                locked -> "LOCKED (1)"
                unlocked -> "UNLOCKED (0)"
                else -> state
            },
            expected = "LOCKED (1)",
            detail = if (unlocked) "Bootloader is unlocked — root/custom ROM possible" else null
        )
    }

    private fun checkDmVerity(): HwCheckItem {
        val mode = getProp("ro.boot.veritymode")
            .ifEmpty { getProp("partition.system.verified") }
            .ifEmpty { "unknown" }
        val enforcing = mode.lowercase() == "enforcing" || mode == "1"
        val disabled = mode.lowercase().contains("disable") || mode == "0"
        return HwCheckItem(
            id = "dm_verity",
            name = "dm-verity Mode",
            group = HwGroup.BOOT,
            description = "ro.boot.veritymode — enforcing means system partition is verified",
            status = when {
                enforcing -> HwCheckStatus.PASS
                disabled -> HwCheckStatus.FAIL
                else -> HwCheckStatus.UNKNOWN
            },
            value = mode.ifEmpty { "unknown" }.uppercase(),
            expected = "ENFORCING",
            detail = if (disabled) "dm-verity DISABLED — system partition modifications not detected" else null
        )
    }

    private fun checkVbmetaDigest(): HwCheckItem {
        val digest = getProp("ro.boot.vbmeta.digest").ifEmpty { "unknown" }
        val avbSize = getProp("ro.boot.vbmeta.size").ifEmpty { "?" }
        val invalidDigest = digest == "unknown" || digest.all { it == '0' }
        return HwCheckItem(
            id = "vbmeta_digest",
            name = "VBMeta Digest (AVB)",
            group = HwGroup.VBMETA,
            description = "SHA-256 of vbmeta partition should not be unknown or all-zero on a healthy AVB chain",
            status = if (invalidDigest) HwCheckStatus.FAIL else HwCheckStatus.PASS,
            value = if (digest.length > 32) "${digest.take(12)}…${digest.takeLast(8)} (${avbSize}B)" else digest,
            expected = "Known non-zero AVB digest",
            detail = when {
                digest == "unknown" -> "VBMeta digest is unknown — verified boot metadata could not be trusted"
                else -> "All-zero VBMeta digest — boot verification bypassed"
            }.takeIf { invalidDigest }
        )
    }

    private fun checkAvbVersion(): HwCheckItem {
        val avbVer = getProp("ro.boot.avb_version")
            .ifEmpty { getProp("ro.avb.version") }
            .ifEmpty { "unknown" }
        return HwCheckItem(
            id = "avb_version",
            name = "Android Verified Boot Version",
            group = HwGroup.VBMETA,
            description = "ro.boot.avb_version — AVB 2.0+ required for full partition verification",
            status = when {
                avbVer.startsWith("2") || avbVer.startsWith("3") -> HwCheckStatus.PASS
                avbVer.startsWith("1.") && avbVer >= "1.3" -> HwCheckStatus.PASS
                else -> HwCheckStatus.UNKNOWN
            },
            value = if (avbVer == "unknown") "Not detected" else avbVer,
            expected = "1.3+ or 2.x"
        )
    }

    private fun checkEncryptionState(): HwCheckItem {
        val crypto = getProp("ro.crypto.state").ifEmpty { "unknown" }
        val type = getProp("ro.crypto.type").ifEmpty { "" }
        val encrypted = crypto == "encrypted"
        return HwCheckItem(
            id = "encryption",
            name = "File-Based Encryption",
            group = HwGroup.SYSTEM_PROPS,
            description = "ro.crypto.state should be 'encrypted' on all modern devices",
            status = if (encrypted) HwCheckStatus.PASS else HwCheckStatus.WARN,
            value = if (encrypted) "encrypted${if (type.isNotEmpty()) " ($type)" else ""}" else crypto,
            expected = "encrypted",
            detail = if (!encrypted && crypto != "unknown") "Storage is not encrypted" else null
        )
    }

    private fun checkSecurityPatchLevel(): HwCheckItem {
        val patch = Build.VERSION.SECURITY_PATCH
        val ok = try {
            val parts = patch.split("-")
            val year = parts[0].toInt()
            val month = parts[1].toInt()
            val patchEpoch = year * 12 + month
            val now = java.util.Calendar.getInstance()
            val nowEpoch = now.get(java.util.Calendar.YEAR) * 12 + (now.get(java.util.Calendar.MONTH) + 1)
            (nowEpoch - patchEpoch) <= 12
        } catch (_: Exception) { false }

        return HwCheckItem(
            id = "security_patch",
            name = "Security Patch Level",
            group = HwGroup.SYSTEM_PROPS,
            description = "Build.VERSION.SECURITY_PATCH — older than 12 months is a risk",
            status = if (ok) HwCheckStatus.PASS else HwCheckStatus.WARN,
            value = patch,
            expected = "Within last 12 months",
            detail = if (!ok) "Patch older than 12 months — may be vulnerable to known CVEs" else null
        )
    }

    private fun getProp(key: String): String = try {
        val process = Runtime.getRuntime().exec("getprop $key")
        BufferedReader(InputStreamReader(process.inputStream)).readLine()?.trim() ?: ""
    } catch (_: Exception) { "" }
}
