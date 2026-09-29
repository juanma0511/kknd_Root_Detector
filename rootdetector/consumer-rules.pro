# NativeChecks uses a statically named JNI entry point. Keep the class and native
# method names stable when the consuming application enables R8/ProGuard.
-keep class **.detector.NativeChecks { *; }

# These classes are referenced by the merged AndroidManifest/AIDL runtime.
-keep class **.zygote.AppZygote { *; }
-keep class **.zygote.PreloadCore { *; }
-keep class **.zygote.DirtySepolicyService { *; }
-keep class **.zygote.PolicyService { *; }
-keep interface **.zygote.IDirtySepolicyService { *; }

# android:zygotePreloadName loads this class reflectively from the manifest.
-keep class * implements android.app.ZygotePreload { *; }
