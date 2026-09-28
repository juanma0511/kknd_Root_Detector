plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.io.File

val defaultZygotePreloadClass = "com.juanma0511.rootdetector.zygote.AppZygote"
val zygotePreloadClass = providers.gradleProperty("zygotePreloadClass")
    .orElse(defaultZygotePreloadClass)
    .get()

val zygoteClassPattern = Regex("^[A-Za-z_$][A-Za-z\\d_$]*(\\.[A-Za-z_$][A-Za-z\\d_$]*)+$")
require(zygoteClassPattern.matches(zygotePreloadClass)) {
    "Invalid -PzygotePreloadClass value: $zygotePreloadClass"
}

val generatedZygoteDir = layout.buildDirectory.dir("generated/source/zygotePreload/main/java")

val generateZygotePreloadClass by tasks.registering {
    inputs.property("zygotePreloadClass", zygotePreloadClass)
    outputs.dir(generatedZygoteDir)

    doLast {
        val outputDir = generatedZygoteDir.get().asFile
        outputDir.deleteRecursively()
        outputDir.mkdirs()

        if (zygotePreloadClass == defaultZygotePreloadClass) return@doLast

        val packageName = zygotePreloadClass.substringBeforeLast('.')
        val simpleName = zygotePreloadClass.substringAfterLast('.')
        val sourceFile = File(
            outputDir,
            packageName.replace('.', '/') + "/$simpleName.java"
        )
        sourceFile.parentFile.mkdirs()
        sourceFile.writeText(
            """
            package $packageName;

            /** Generated build-specific App Zygote preload entry point. */
            public final class $simpleName
                    extends com.juanma0511.rootdetector.zygote.AppZygote {
            }
            """.trimIndent() + "\n"
        )
    }
}

android {
    namespace = "com.juanma0511.rootdetector"
    compileSdk = 36
    ndkVersion = "28.0.12433566"

    defaultConfig {
        minSdk = 26
        manifestPlaceholders["rootDetectorZygotePreloadName"] = zygotePreloadClass

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                arguments += "-DANDROID_STL=c++_static"
                arguments += "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"
            }
        }

        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("main").java.srcDir(generatedZygoteDir)
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
    dependsOn(generateZygotePreloadClass)
}
