# Kknd Root Detector

![Banner](art/banner.png)

Kknd Root Detector is an Android application that performs deep, multi-layer detection of root access, hook frameworks, SELinux policy tampering, and system integrity violations — using both Kotlin and native C++ checks.

---

## Features — v3.1

### Native (C++) — 71 checks

| Category | Description |
|---|---|
| Binary scan | `su`, root manager packages, suspicious paths |
| Mount namespace | Bind-mounts, overlayfs, namespace isolation |
| Property tampering | Resetprop scan across all partition prop files; `__system_property_serial` drift; PIF/TrickyStore spoof configs |
| SELinux | `attr/current` write probe (root contexts in policy); DirtySepolicy `selinux_check_access` rule checks |
| Zygisk / LSPosed | Module presence, memory maps, JNI hook traces |
| Hardware security | Keystore attestation, TEE status, boot state |

### Kotlin — 68 checks

Mirrors the native layer with JVM-level checks: package manager scans, reflection-based `SELinux.checkSELinuxAccess`, prop reads, Play Integrity API integration, and certificate chain validation.

---

## Installation

Download the latest signed APK from the **Releases page**:

https://github.com/juanma0511/Kknd_Root_Detector/releases

Two APK variants are provided per release — pick the one matching your device:

| File | ABI |
|---|---|
| `RootDetector-3.1-arm64-v8a-release.apk` | 64-bit (most modern devices) |
| `RootDetector-3.1-armeabi-v7a-release.apk` | 32-bit |

Or grab the latest CI artifact from **Actions**.

---

## Build From Source

### Requirements

- Android Studio Hedgehog or later
- Android SDK (API 36)
- NDK 27
- JDK 17
- CMake 3.22.1

### Steps

```bash
git clone https://github.com/juanma0511/Kknd_Root_Detector.git
cd Kknd_Root_Detector
./gradlew assembleDebug
```

The debug APK will be at:

    app/build/outputs/apk/debug/*.apk

### Build the reusable AAR

The detection core is also available as the headless `:rootdetector` Android library module.
It contains the Kotlin checks, native C++ checks, AIDL/app-zygote integration, and the
consumer ProGuard rules required by the JNI entry points.

```bash
./gradlew :rootdetector:assembleRelease
```

The AAR will be generated at:

    rootdetector/build/outputs/aar/rootdetector-release.aar

### Library API

The public entry point is `RootDetector.scan(...)`. No Activity, Fragment, Compose UI,
initialization call, or retained last-result state is required. Scans execute off the main
thread; progress and completion callbacks are delivered on the main thread.

```kotlin
RootDetector.scan(
    context,
    ScanProgressListener { progress ->
        // Optional progress: 0..100
    },
    ScanCallback { result ->
        if (result.isRooted) {
            // High-risk root evidence was detected.
        }

        // Full structured result remains available when more detail is needed.
        val status = result.status
        val checks = result.checks
        val summary = result.summary
    }
)
```

Each `CheckResult` exposes a stable `id`, category, severity, status, detail, and evidence.
`CheckStatus` distinguishes `DETECTED`, `NOT_DETECTED`, `ERROR`, `SKIPPED`, and
`UNSUPPORTED`, so a check that could not run is not silently treated as a clean result.
The aggregate `ScanStatus` is one of `CLEAN`, `SUSPICIOUS`, `ROOTED`, or `INCOMPLETE`.

The API is Kotlin-first but Java-friendly: `scan(...)` is exposed as a static method and the
callbacks are SAM interfaces.

#### Integration notes

- The AAR merges its package-visibility queries, isolated App Zygote service, and
  `zygotePreloadName` into the consuming application's manifest. An application that already
  defines its own `zygotePreloadName` must resolve that manifest-level conflict explicitly.
- Native binaries currently target `arm64-v8a` and `armeabi-v7a`, matching the existing app's
  supported ABIs. On an unsupported ABI, the native layer reports an explicit error rather than
  silently treating the device as clean.
- JVM/Android and native scan tasks return structured statuses. Each executed native detector
  contributes one `CheckResult` (`DETECTED`, `NOT_DETECTED`, or `ERROR`); when a native task
  detects one or more lower-level signals, their stable IDs and descriptions are preserved in
  that check's `evidence` map. A native library/JNI failure is reported as `native_engine=ERROR`.

For a signed release build see the **Release workflow** section below.

---

## Release Workflow

Releases are built and signed automatically via GitHub Actions when a `v*` tag is pushed:

```bash
git tag v3.1
git push origin v3.1
```

Or trigger manually from the **Actions** tab using the **Release Build** workflow.

### Required GitHub Secrets

| Secret | Value |
|---|---|
| `KEYSTORE_BASE64` | Base64-encoded `.jks` keystore file |
| `STORE_PASSWORD` | Keystore password |
| `KEY_ALIAS` | Key alias inside the keystore |
| `KEY_PASSWORD` | Key password |

Generate a keystore if you don't have one:

```bash
keytool -genkey -v -keystore keystore.jks -alias mykey \
  -keyalg RSA -keysize 2048 -validity 10000
base64 -w0 keystore.jks
```

---

## Project Preview

<img src="art/rootdetection.jpg" width="350">

---

## Use Cases

- Testing rooted Android devices
- Studying root and hook framework detection techniques
- Learning Android native security (SELinux, properties, mount namespaces)
- Developing root detection in production apps

---

## Credits

Native detection ideas inspired by:

- [Native Detector](https://github.com/reveny/Android-Native-Root-Detector)
- [Duck Detector](https://github.com/eltavine/Duck-Detector-Refactoring)

---

## Reporting Issues

- Open an issue: https://github.com/juanma0511/Kknd_Root_Detector/issues
- Telegram: https://t.me/juanma0511

---

## Disclaimer

This project is provided for **educational and research purposes only**.
Do not use it to bypass security protections in applications without authorization.
