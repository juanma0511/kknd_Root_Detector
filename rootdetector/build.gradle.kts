plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.io.File

val defaultRootDetectorPackage = "com.juanma0511.rootdetector"
val rootDetectorPackage = providers.gradleProperty("rootDetectorPackage")
    .orElse(defaultRootDetectorPackage)
    .get()

// Keep custom package names simple and JNI-safe. This intentionally disallows
// underscores/$ in custom segments so the generated JNI symbol stays trivial.
val packagePattern = Regex("^[A-Za-z][A-Za-z0-9]*(\\.[A-Za-z][A-Za-z0-9]*)+$")
require(packagePattern.matches(rootDetectorPackage)) {
    "Invalid -ProotDetectorPackage value: $rootDetectorPackage"
}

val isRelocatedBuild = rootDetectorPackage != defaultRootDetectorPackage
val relocatedRoot = layout.buildDirectory.dir("generated/relocatedRootDetector/main")
val relocatedJavaDir = relocatedRoot.map { it.dir("java") }
val relocatedAidlDir = relocatedRoot.map { it.dir("aidl") }

val generateRelocatedRootDetectorSources by tasks.registering {
    onlyIf { isRelocatedBuild }
    inputs.property("rootDetectorPackage", rootDetectorPackage)
    inputs.dir("src/main/java")
    inputs.dir("src/main/aidl")
    outputs.dir(relocatedRoot)

    doLast {
        val outputRoot = relocatedRoot.get().asFile
        outputRoot.deleteRecursively()

        val oldPath = defaultRootDetectorPackage.replace('.', '/')
        val newPath = rootDetectorPackage.replace('.', '/')

        fun relocateTree(sourceRoot: File, targetRoot: File) {
            if (!sourceRoot.exists()) return
            sourceRoot.walkTopDown()
                .filter { it.isFile }
                .forEach { sourceFile ->
                    val relative = sourceFile.relativeTo(sourceRoot).invariantSeparatorsPath
                    var relocatedRelative = if (relative.startsWith("$oldPath/")) {
                        "$newPath/${relative.removePrefix("$oldPath/")}"
                    } else {
                        relative
                    }

                    if (isRelocatedBuild) {
                        relocatedRelative = relocatedRelative
                            .replace("/AppZygote.java", "/PreloadCore.java")
                            .replace("/DirtySepolicyService.java", "/PolicyService.java")
                    }

                    val targetFile = File(targetRoot, relocatedRelative)
                    targetFile.parentFile.mkdirs()

                    var relocatedText = sourceFile.readText()
                        .replace(defaultRootDetectorPackage, rootDetectorPackage)

                    if (isRelocatedBuild) {
                        relocatedText = relocatedText
                            .replace("AppZygote", "PreloadCore")
                            .replace("DirtySepolicyService", "PolicyService")
                            // Keep the Binder/AIDL interface name stable. The service class is
                            // renamed to PolicyService, but AIDL requires its declared interface
                            // name to match the IDirtySepolicyService.aidl filename exactly.
                            .replace("IPolicyService", "IDirtySepolicyService")
                    }

                    targetFile.writeText(relocatedText)
                }
        }

        relocateTree(file("src/main/java"), relocatedJavaDir.get().asFile)
        relocateTree(file("src/main/aidl"), relocatedAidlDir.get().asFile)
    }
}

val zygotePreloadClass = if (isRelocatedBuild) {
    "$rootDetectorPackage.zygote.PreloadCore"
} else {
    "$rootDetectorPackage.zygote.AppZygote"
}
val dirtySepolicyServiceClass = if (isRelocatedBuild) {
    "$rootDetectorPackage.zygote.PolicyService"
} else {
    "$rootDetectorPackage.zygote.DirtySepolicyService"
}
val jniMethodName = "Java_${rootDetectorPackage.replace('.', '_')}_detector_NativeChecks_runNativeChecks"

android {
    namespace = rootDetectorPackage
    compileSdk = 36
    ndkVersion = "28.0.12433566"

    defaultConfig {
        minSdk = 26
        manifestPlaceholders["rootDetectorZygotePreloadName"] = zygotePreloadClass
        manifestPlaceholders["rootDetectorDirtySepolicyServiceName"] = dirtySepolicyServiceClass

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                cppFlags += "-DROOTDETECTOR_JNI_METHOD=$jniMethodName"
                arguments += "-DANDROID_STL=c++_static"
                arguments += "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"
            }
        }

        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("main") {
            if (isRelocatedBuild) {
                java.setSrcDirs(listOf(relocatedJavaDir.get().asFile))
                aidl.setSrcDirs(listOf(relocatedAidlDir.get().asFile))
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_11)
        }
    }

    buildFeatures {
        aidl = true
    }

    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

tasks.named("preBuild").configure {
    if (isRelocatedBuild) {
        dependsOn(generateRelocatedRootDetectorSources)
    }
}
