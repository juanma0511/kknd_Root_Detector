package com.juanma0511.rootdetector.zygote;

import android.annotation.TargetApi;
import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;

import java.util.LinkedHashSet;

/**
 * SELinux / DirtySepolicy detector running inside the app_zygote isolated
 * process. Ported from LSPosed/DirtySepolicy (https://github.com/LSPosed/DirtySepolicy).
 *
 * <p>Crucially this uses {@link SELinux} (direct selinuxfs I/O) and NO reflection
 * on the hidden {@code android.os.SELinux} class. The earlier reflection-based
 * version aborted the app_zygote preload process (blocklisted hidden-API),
 * causing the system to fall back to a plain isolated process so {@code doPreload}
 * never ran and the binder only returned the initial sentinel. Direct selinuxfs
 * access fixes that and is exactly what makes LSPosed's tool work.
 *
 * <p>Two results are exposed to the client:
 * <ul>
 *   <li>{@link #result} -- dirty-sepolicy sweep. "WARNING: ..." = detection,
 *       "OK: ..." = clean, "ERROR: ..." = sanity gate failed (informational).
 *   <li>{@link #oracleResult} -- context-validity oracle. "ROOT: ..." = a root
 *       framework's SELinux footprint is present, "CLEAN: ..." = none,
 *       "ERROR: ..." = gate/self-test failure (informational).
 * </ul>
 */
@TargetApi(29)
public final class AppZygote implements ZygotePreload {

    private static final String TAG = "RootDetector-AppZygote";

    static volatile String result = "ERROR: app zygote not called";
    static volatile String oracleResult = "ERROR: app zygote not called";

    @Override
    public void doPreload(ApplicationInfo appInfo) {
        int uid = Os.getuid();
        if (uid != appInfo.uid) {
            result = "ERROR: UID mismatch: " + uid + " != app uid " + appInfo.uid;
            oracleResult = result;
            return;
        }

        try {
            result = doCheck();
        } catch (Throwable e) {
            result = "ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage();
            Log.e(TAG, Log.getStackTraceString(e));
        }

        try {
            oracleResult = runContextValidityOracle();
        } catch (Throwable e) {
            oracleResult = "ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage();
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    // ---------------------------------------------------------------------
    //  Dirty-sepolicy sweep (LSPosed/DirtySepolicy doCheck, verbatim logic)
    // ---------------------------------------------------------------------

    private static int parseVersion(String release, int start) {
        int end = start;
        while (end < release.length()) {
            var c = release.charAt(end);
            if (c < '0' || c > '9') break;
            end++;
        }
        return Integer.parseInt(release.substring(start, end));
    }

    private static boolean isNewKernel() {
        var release = Os.uname().release;
        int major = parseVersion(release, 0);
        int dot = release.indexOf('.');
        int minor = parseVersion(release, dot + 1);
        // https://github.com/torvalds/linux/commit/fc983171e4c8
        return major > 6 || (major == 6 && minor >= 10);
    }

    private static String doCheck() {
        if (!SELinux.isSELinuxEnabled()) {
            return "ERROR: SELinux is disabled";
        }
        var context = SELinux.getContext();
        if (context == null || !context.startsWith("u:r:app_zygote:s0")) {
            return "ERROR: unexpected SELinux context: " + context;
        }
        var pidContext = SELinux.getPidContext(Os.getpid());
        if (!context.equals(pidContext)) {
            return "ERROR: PID context mismatch: " + pidContext;
        }
        var procContext = SELinux.getFileContext("/proc/self");
        if (!context.equals(procContext)) {
            return "ERROR: /proc/self context mismatch: " + procContext;
        }
        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:app_zygote:s0", "process", "setcurrent")) {
            return "ERROR: cannot check SELinux access";
        }
        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:kernel:s0", "security", "check_context")) {
            return "ERROR: cannot check SELinux context";
        }
        var sb = new StringBuilder();
        if (!SELinux.isSELinuxEnforced()) {
            sb.append("SELinux is permissive; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem")) {
            sb.append("system_server can execmem; ");
        }
        if (Build.TYPE.equals("user")
                && SELinux.checkSELinuxAccess("u:r:shell:s0", "u:r:su:s0", "process", "transition")) {
            sb.append("found AOSP su in user build; ");
        }
        if (SELinux.contextExists("u:r:adbroot:s0")) {
            sb.append("found adb_root; ");
        }
        if (SELinux.contextExists("u:r:magisk:s0") || SELinux.contextExists("u:object_r:magisk_file:s0")
                || SELinux.checkSELinuxAccess("u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate")
                || SELinux.checkSELinuxAccess("u:r:kernel:s0", "u:object_r:tmpfs:s0", "fifo_file", "open")) {
            sb.append("found Magisk; ");
        }
        if (SELinux.contextExists("u:r:ksu:s0") || SELinux.contextExists("u:object_r:ksu_file:s0")
                || SELinux.checkSELinuxAccess("u:r:kernel:s0", "u:object_r:adb_data_file:s0", "file", "read")) {
            sb.append("found KernelSU; ");
        }
        if (SELinux.contextExists("u:r:apd:s0") || SELinux.contextExists("u:object_r:apd_exec:s0")) {
            sb.append("found APatch; ");
        }
        if (SELinux.contextExists("u:object_r:lsposed_file:s0")
                || SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute")) {
            sb.append("found LSPosed; ");
        }
        if (SELinux.contextExists("u:object_r:xposed_data:s0") || SELinux.contextExists("u:object_r:xposed_file:s0")
                || SELinux.checkSELinuxAccess("u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans")) {
            sb.append("found Xposed; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:zygote:s0", "u:object_r:adb_data_file:s0", "dir", "search")) {
            sb.append("found ZygiskNext; ");
        }

        try {
            var buffer = SELinux.readStatus();
            int version = buffer.getInt(0);
            if (version != 1) {
                return "ERROR: unknown status version: " + version;
            }
            int sequence = buffer.getInt(4);
            int policyload = buffer.getInt(12);
            if (!(isNewKernel() ? sequence == 4 : sequence == 0)) {
                sb.append("sequence=").append(sequence).append("; ");
            }
            try {
                var avd = SELinux.access("u:r:untrusted_app:s0", "u:r:untrusted_app:s0", 0);
                var avdSeqNo = Integer.parseUnsignedInt(avd[4]);
                if (avdSeqNo != 1) {
                    sb.append("avdSeqNo=").append(avdSeqNo).append("; ");
                }
            } catch (ErrnoException e) {
                throw new RuntimeException(e);
            }
        } catch (RuntimeException e) {
            // status/access probes are informational; ignore if unreadable.
            Log.w(TAG, "status probe: " + e.getMessage());
        }

        if (sb.length() == 0) {
            return "OK: no dirty sepolicy found";
        }
        return "WARNING: " + sb;
    }

    // ---------------------------------------------------------------------
    //  SELinux context-validity oracle
    // ---------------------------------------------------------------------
    //
    //  Asks the live kernel policy whether a root framework's SELinux footprint
    //  is present, using the same direct-selinuxfs primitives. contextExists()
    //  is the context-validity oracle proper: writing a context to
    //  /sys/fs/selinux/context (plus the two fallback probes) tells us whether
    //  the type is in the loaded policy. For KernelSU we additionally consult a
    //  merged AVC allow rule (untrusted_app -> ksu:binder call), which catches
    //  variants whose type exists but never forms a valid full context.
    //
    //  A negative-control sentinel that no real policy can contain must be
    //  rejected first; if the oracle accepts it, it is rubber-stamping and we
    //  emit no verdict.

    private static String runContextValidityOracle() {
        if (!SELinux.isSELinuxEnabled()) {
            return "ERROR: SELinux is disabled";
        }
        var context = SELinux.getContext();
        if (context == null || !context.startsWith("u:r:app_zygote:s0")) {
            return "ERROR: carrier is not app_zygote: " + context;
        }
        if (!SELinux.isSELinuxEnforced()) {
            return "ERROR: SELinux is permissive";
        }

        // Self-test: an impossible sentinel context must be rejected.
        if (contextExistsQuiet("u:r:rootdetector_oracle_sentinel_9x3q:s0")
                || contextExistsQuiet("u:object_r:rootdetector_oracle_sentinel_9x3q_file:s0")) {
            return "ERROR: oracle self-test failed (sentinel context accepted)";
        }

        var found = new LinkedHashSet<String>();
        if (contextExistsQuiet("u:r:ksu:s0") || contextExistsQuiet("u:object_r:ksu_file:s0")
                || accessQuiet("u:r:untrusted_app:s0", "u:r:ksu:s0", "binder", "call")) {
            found.add("KernelSU");
        }
        if (contextExistsQuiet("u:r:magisk:s0") || contextExistsQuiet("u:object_r:magisk_file:s0")) {
            found.add("Magisk");
        }
        if (contextExistsQuiet("u:r:apd:s0") || contextExistsQuiet("u:object_r:apd_exec:s0")) {
            found.add("APatch");
        }
        if (contextExistsQuiet("u:object_r:lsposed_file:s0")) {
            found.add("LSPosed");
        }

        if (!found.isEmpty()) {
            return "ROOT: " + String.join(", ", found) + " via SELinux context validity oracle";
        }
        return "CLEAN: no root SELinux contexts found in live policy";
    }

    /** contextExists() that swallows an unexpected-errno throw as "not found". */
    private static boolean contextExistsQuiet(String context) {
        try {
            return SELinux.contextExists(context);
        } catch (RuntimeException e) {
            Log.w(TAG, "contextExists(" + context + "): " + e.getMessage());
            return false;
        }
    }

    private static boolean accessQuiet(String scon, String tcon, String tclass, String perm) {
        try {
            return SELinux.checkSELinuxAccess(scon, tcon, tclass, perm);
        } catch (RuntimeException e) {
            Log.w(TAG, "checkSELinuxAccess: " + e.getMessage());
            return false;
        }
    }
}
