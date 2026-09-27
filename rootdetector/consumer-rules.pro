# NativeChecks uses statically named JNI entry points. Keep the class and native
# method names stable when the consuming application enables R8/ProGuard.
-keep class com.juanma0511.rootdetector.detector.NativeChecks { *; }

# These classes are referenced by the merged AndroidManifest/AIDL runtime.
-keep class com.juanma0511.rootdetector.zygote.AppZygote { *; }
-keep class com.juanma0511.rootdetector.zygote.DirtySepolicyService { *; }
-keep interface com.juanma0511.rootdetector.zygote.IDirtySepolicyService { *; }
