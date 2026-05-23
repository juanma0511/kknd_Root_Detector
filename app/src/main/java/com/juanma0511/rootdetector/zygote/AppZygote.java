package com.juanma0511.rootdetector.zygote;

import android.annotation.TargetApi;
import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;

/**
 * SELinux / DirtySepolicy detector running inside the app_zygote isolated process.
 *
 * Strategy adapted from LSPosed/DirtySepolicy
 * (https://github.com/LSPosed/DirtySepolicy):
 *
 *   1. Sanity-gate the SELinux state before doing any policy probes. If the
 *      context, PID match, /proc/self match, enforced flag, or required API
 *      permissions are not exactly as expected, return "ERROR: ..." -- NEVER
 *      a WARNING. This eliminates false positives from broken/hooked APIs.
 *
 *   2. For each known root framework, OR together several SELinux signals:
 *      contextExists() probes plus targeted checkSELinuxAccess() rules.
 *      Any single hit emits "found X" for that framework.
 *
 *   3. contextExists() uses the kernel's strict EINVAL/EPERM semantics:
 *        - Write to /sys/fs/selinux/context: success = true, EINVAL = not in
 *          policy (continue), other errno = SELinux is in an unexpected state
 *          -> throw (yields ERROR, not a false WARNING).
 *        - dyntransition allowed -> true.
 *        - Write to /proc/self/attr/current: EINVAL = type not in policy,
 *          EPERM = type exists but transition denied (true), success = the
 *          kernel is broken -> throw.
 *
 * Result prefixes consumed by RootDetector.checkAppZygoteSepolicy:
 *   "WARNING: ..."  -> root framework detected (HIGH, detected=true)
 *   "OK: ..."       -> clean policy        (LOW, detected=false)
 *   "ERROR: ..."    -> service/API issue   (LOW, detected=false, informational)
 */
@TargetApi(29)
public final class AppZygote implements ZygotePreload {

    private static final String TAG = "RootDetector-AppZygote";

    static volatile String result = "ERROR: app zygote not called";

    @Override
    public void doPreload(ApplicationInfo appInfo) {
        int uid = Os.getuid();
        if (uid != appInfo.uid) {
            result = "ERROR: UID mismatch: " + uid + " != app uid " + appInfo.uid;
            return;
        }

        // On API <= 30, libselinux can leak a netlink socket FD during
        // selinux_check_access. The fd is rejected when the app_zygote later
        // forks isolated children, crashing the zygote. Track open FDs before
        // doCheck() and dup2 any new ones to FileDescriptor.in afterwards.
        HashSet<String> baseline = new HashSet<>();
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) {
            File[] fds = new File("/proc/self/fd").listFiles(File::exists);
            if (fds != null) {
                for (File fd : fds) baseline.add(fd.getName());
            }
        }

        try {
            result = doCheck();
        } catch (Throwable e) {
            // Catch Throwable (not just RuntimeException) so that LinkageError,
            // ExceptionInInitializerError, or hidden-API blocking on the Sel
            // reflection static initializer cannot escape and crash the
            // isolated app_zygote process. Any escape would surface to the
            // client as a bind timeout, costing detection coverage.
            result = "ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage();
            Log.e(TAG, Log.getStackTraceString(e));
        } finally {
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) {
                File[] fds = new File("/proc/self/fd").listFiles(File::exists);
                if (fds != null) {
                    for (File fd : fds) {
                        if (baseline.add(fd.getName())) {
                            try {
                                Os.dup2(FileDescriptor.in, Integer.parseInt(fd.getName()));
                            } catch (ErrnoException | NumberFormatException e) {
                                Log.e(TAG, "Close leaked SELinux netlink fd " + fd.getName(), e);
                            }
                        }
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    //  Core check
    // ---------------------------------------------------------------------

    private static String doCheck() {
        if (!Sel.isEnabled()) {
            return "ERROR: SELinux is disabled";
        }
        String context = Sel.getContext();
        if (context == null || !context.startsWith("u:r:app_zygote:s0")) {
            return "ERROR: unexpected SELinux context: " + context;
        }
        String pidContext = Sel.getPidContext(Os.getpid());
        if (!context.equals(pidContext)) {
            return "ERROR: PID context mismatch: " + pidContext;
        }
        String procContext = Sel.getFileContext("/proc/self");
        if (!context.equals(procContext)) {
            return "ERROR: /proc/self context mismatch: " + procContext;
        }
        if (!Sel.isEnforced()) {
            return "ERROR: SELinux is permissive";
        }
        if (!Sel.checkAccess("u:r:app_zygote:s0", "u:r:app_zygote:s0", "process", "setcurrent")) {
            return "ERROR: cannot check SELinux access (process:setcurrent denied)";
        }
        if (!Sel.checkAccess("u:r:app_zygote:s0", "u:r:kernel:s0", "security", "check_context")) {
            return "ERROR: cannot check SELinux context (security:check_context denied)";
        }

        StringBuilder sb = new StringBuilder();

        if (Sel.checkAccess("u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem")) {
            sb.append("system_server can execmem; ");
        }
        if ("user".equals(Build.TYPE)
                && Sel.checkAccess("u:r:shell:s0", "u:r:su:s0", "process", "transition")) {
            sb.append("found AOSP su in user build; ");
        }
        if (contextExists("u:r:adbroot:s0")
                || Sel.checkAccess("u:r:adbd:s0", "u:r:adbroot:s0", "binder", "call")) {
            sb.append("found adb_root; ");
        }
        if (contextExists("u:r:magisk:s0") || contextExists("u:object_r:magisk_file:s0")
                || Sel.checkAccess("u:r:untrusted_app:s0", "u:object_r:magisk_file:s0", "file", "read")
                || Sel.checkAccess("u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate")
                || Sel.checkAccess("u:r:kernel:s0", "u:object_r:tmpfs:s0", "fifo_file", "open")) {
            sb.append("found Magisk; ");
        }
        if (contextExists("u:r:ksu:s0") || contextExists("u:object_r:ksu_file:s0")
                || Sel.checkAccess("u:r:kernel:s0", "u:object_r:adb_data_file:s0", "file", "read")
                || Sel.checkAccess("u:r:untrusted_app:s0", "u:object_r:ksu_file:s0", "file", "read")) {
            sb.append("found KernelSU; ");
        }
        if (contextExists("u:r:apd:s0") || contextExists("u:object_r:apd_exec:s0")
                || Sel.checkAccess("u:r:untrusted_app:s0", "u:object_r:apd_exec:s0", "file", "execute")) {
            sb.append("found APatch; ");
        }
        if (contextExists("u:object_r:lsposed_file:s0")
                || Sel.checkAccess("u:r:untrusted_app:s0", "u:object_r:lsposed_file:s0", "file", "read")
                || Sel.checkAccess("u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute")) {
            sb.append("found LSPosed; ");
        }
        if (contextExists("u:object_r:xposed_data:s0") || contextExists("u:object_r:xposed_file:s0")
                || Sel.checkAccess("u:r:untrusted_app:s0", "u:object_r:xposed_data:s0", "file", "read")
                || Sel.checkAccess("u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans")) {
            sb.append("found Xposed; ");
        }
        if (Sel.checkAccess("u:r:zygote:s0", "u:object_r:adb_data_file:s0", "dir", "search")) {
            sb.append("found ZygiskNext; ");
        }

        if (sb.length() == 0) {
            return "OK: no dirty sepolicy found";
        }
        return "WARNING: " + sb;
    }

    // ---------------------------------------------------------------------
    //  contextExists -- strict EINVAL/EPERM semantics
    // ---------------------------------------------------------------------

    private static boolean contextExists(String context) {
        byte[] data = context.getBytes(StandardCharsets.UTF_8);

        // Probe 1: security:check_context via /sys/fs/selinux/context.
        // Success     -> context exists in policy.
        // EINVAL      -> type not in loaded policy -> continue.
        // Other errno -> SELinux is in an unexpected state -> throw (ERROR).
        try (FileOutputStream file = new FileOutputStream("/sys/fs/selinux/context")) {
            Os.write(file.getFD(), data, 0, data.length);
            return true;
        } catch (ErrnoException e) {
            if (e.errno != OsConstants.EINVAL) {
                throw new RuntimeException("security_check_context errno=" + e.errno, e);
            }
        } catch (IOException e) {
            throw new RuntimeException("security_check_context: " + e.getMessage(), e);
        }

        // Probe 2: dyntransition allowed -> type exists.
        if (Sel.checkAccess("u:r:app_zygote:s0", context, "process", "dyntransition")) {
            return true;
        }

        // Probe 3: process:setcurrent via /proc/self/attr/current. Kernel
        // validates the context first (EINVAL if invalid) then dyntransition
        // (EPERM if denied). A successful write would mean the kernel is
        // bypassed -> we throw to surface that as ERROR.
        try (FileOutputStream current = new FileOutputStream("/proc/self/attr/current")) {
            Os.write(current.getFD(), data, 0, data.length);
            throw new RuntimeException("SELinux broken: setcon to '" + context + "' succeeded");
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.EINVAL) return false;
            if (e.errno == OsConstants.EPERM)  return true;
            throw new RuntimeException("setcon errno=" + e.errno, e);
        } catch (IOException e) {
            throw new RuntimeException("setcon: " + e.getMessage(), e);
        }
    }

    // ---------------------------------------------------------------------
    //  android.os.SELinux reflection wrapper
    // ---------------------------------------------------------------------

    private static final class Sel {
        private static final Class<?> CLS;
        private static final Method M_IS_ENABLED;
        private static final Method M_IS_ENFORCED;
        private static final Method M_GET_CONTEXT;
        private static final Method M_GET_PID_CONTEXT;
        private static final Method M_GET_FILE_CONTEXT;
        private static final Method M_CHECK_ACCESS;

        static {
            try {
                CLS = Class.forName("android.os.SELinux");
                M_IS_ENABLED       = CLS.getMethod("isSELinuxEnabled");
                M_IS_ENFORCED      = CLS.getMethod("isSELinuxEnforced");
                M_GET_CONTEXT      = CLS.getMethod("getContext");
                M_GET_PID_CONTEXT  = CLS.getMethod("getPidContext", int.class);
                M_GET_FILE_CONTEXT = CLS.getMethod("getFileContext", String.class);
                M_CHECK_ACCESS     = CLS.getMethod("checkSELinuxAccess",
                        String.class, String.class, String.class, String.class);
            } catch (Throwable t) {
                throw new RuntimeException("SELinux reflection setup failed: " + t.getMessage(), t);
            }
        }

        static boolean isEnabled() {
            try { return (Boolean) M_IS_ENABLED.invoke(null); }
            catch (Throwable t) { return false; }
        }
        static boolean isEnforced() {
            try { return (Boolean) M_IS_ENFORCED.invoke(null); }
            catch (Throwable t) { return false; }
        }
        static String getContext() {
            try { return (String) M_GET_CONTEXT.invoke(null); }
            catch (Throwable t) { return null; }
        }
        static String getPidContext(int pid) {
            try { return (String) M_GET_PID_CONTEXT.invoke(null, pid); }
            catch (Throwable t) { return null; }
        }
        static String getFileContext(String path) {
            try { return (String) M_GET_FILE_CONTEXT.invoke(null, path); }
            catch (Throwable t) { return null; }
        }
        static boolean checkAccess(String src, String tgt, String cls, String perm) {
            try { return Boolean.TRUE.equals(M_CHECK_ACCESS.invoke(null, src, tgt, cls, perm)); }
            catch (Throwable t) { return false; }
        }
    }
}
