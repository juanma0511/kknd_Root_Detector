package com.juanma0511.rootdetector.zygote;

import android.annotation.TargetApi;
import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;

@TargetApi(29)
public final class AppZygote implements ZygotePreload {

    static volatile String result = "ERROR:preload_not_called";

    @Override
    public void doPreload(ApplicationInfo appInfo) {
        java.util.Set<Integer> fdsBefore = snapshotOpenFds();
        try {
            result = runChecks();
        } catch (Throwable t) {
            result = "ERROR:" + t.getClass().getSimpleName();
        } finally {
            redirectNewFdsToDevNull(fdsBefore);
        }
    }

    private static String runChecks() {
        StringBuilder sb = new StringBuilder();
        probeContextExists(sb);
        probeDirtyPolicy(sb);
        return sb.length() == 0 ? "CLEAN" : sb.toString();
    }

    private static final String[] CONTEXT_LABELS = {
        "KernelSU", "KernelSU_file", "Magisk", "Magisk_file",
        "LSPosed_file", "Xposed_file", "Xposed_data",
        "MSD_app", "MSD_daemon", "APatch", "ZygiskNext", "AOSP_su"
    };

    private static final String[] CONTEXT_VALUES = {
        "u:r:ksu:s0", "u:r:ksu_file:s0", "u:r:magisk:s0", "u:r:magisk_file:s0",
        "u:r:lsposed_file:s0", "u:r:xposed_file:s0", "u:r:xposed_data:s0",
        "u:r:msd_app:s0", "u:r:msd_daemon:s0", "u:r:apd:s0", "u:r:zygisk_daemon:s0", "u:r:su:s0"
    };

    private static void probeContextExists(StringBuilder out) {
        for (int i = 0; i < CONTEXT_LABELS.length; i++) {
            String label = CONTEXT_LABELS[i];
            String ctx   = CONTEXT_VALUES[i];

            // Probe 1: /sys/fs/selinux/context — kernel validates context against loaded policy.
            // EINVAL/EPERM = type NOT in policy (stock device) → skip entirely.
            // EACCES/0    = type EXISTS in policy (DirtySepolicy injected it) → proceed.
            int probe1Errno = checkContextInPolicy(ctx);
            if (probe1Errno == android.system.OsConstants.EINVAL
                    || probe1Errno == android.system.OsConstants.EPERM) {
                continue;
            }
            String probe1 = (probe1Errno == 0) ? "EXIST_WRITABLE" : "EXIST_errno" + probe1Errno;

            // Probe 2: dyntransition check — is process→target dyntransition allowed by policy?
            String currentCtx = getCurrentContext();
            boolean dynAllowed = false;
            try {
                Class<?> sel = Class.forName("android.os.SELinux");
                java.lang.reflect.Method m = sel.getMethod(
                    "checkSELinuxAccess", String.class, String.class, String.class, String.class);
                dynAllowed = Boolean.TRUE.equals(m.invoke(null, currentCtx, ctx, "process", "dyntransition"));
            } catch (Throwable ignored) {}

            // Probe 3: /proc/self/attr/current write — actual transition attempt.
            // 0     = write succeeded (highest confidence)
            // EACCES = type exists in policy but transition denied (root framework present)
            // EINVAL/EPERM = type not in policy (should have been caught by probe 1, but guard here)
            int probe3Errno = probeAttrCurrentWrite(ctx);
            if (probe3Errno == android.system.OsConstants.EINVAL
                    || probe3Errno == android.system.OsConstants.EPERM) {
                continue;
            }
            String probe3 = (probe3Errno == 0) ? "WRITTEN" : "EACCES";

            out.append("WARNING:context_exists:")
               .append(label)
               .append(":p1=").append(probe1)
               .append(":p2_dyntrans=").append(dynAllowed ? "yes" : "no")
               .append(":p3=").append(probe3)
               .append("\n");
        }
    }

    private static int checkContextInPolicy(String ctx) {
        // Write to /sys/fs/selinux/context to validate context against loaded SELinux policy.
        // Returns errno (0 on success).
        try {
            java.io.FileOutputStream fos = new java.io.FileOutputStream("/sys/fs/selinux/context", false);
            try {
                byte[] bytes = (ctx + "\0").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                android.system.Os.write(fos.getFD(), bytes, 0, bytes.length);
                return 0;
            } catch (android.system.ErrnoException e) {
                return e.errno;
            } finally {
                try { fos.close(); } catch (java.io.IOException ignored) {}
            }
        } catch (java.io.FileNotFoundException e) {
            return android.system.OsConstants.ENOENT;
        }
    }

    private static int probeAttrCurrentWrite(String ctx) {
        try {
            java.io.FileOutputStream fos = new java.io.FileOutputStream("/proc/self/attr/current", false);
            try {
                byte[] bytes = (ctx + "\0").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                android.system.Os.write(fos.getFD(), bytes, 0, bytes.length);
                return 0;
            } catch (android.system.ErrnoException e) {
                return e.errno;
            } finally {
                try { fos.close(); } catch (java.io.IOException ignored) {}
            }
        } catch (java.io.FileNotFoundException e) {
            return android.system.OsConstants.ENOENT;
        }
    }

    private static String getCurrentContext() {
        try {
            return new String(
                java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/proc/self/attr/current")),
                java.nio.charset.StandardCharsets.UTF_8).trim();
        } catch (Throwable t) {
            return "u:r:untrusted_app:s0";
        }
    }

    private static void probeDirtyPolicy(StringBuilder out) {
        try {
            Class<?> cls = Class.forName("android.os.SELinux");
            java.lang.reflect.Method m = cls.getMethod("checkSELinuxAccess",
                String.class, String.class, String.class, String.class);

            boolean isUser = "user".equals(getSystemProperty("ro.build.type", ""));

            // Negative controls: these should NEVER be allowed on stock policy.
            // If they are, the checkSELinuxAccess API itself is unreliable; bail out.
            boolean neg1 = Boolean.TRUE.equals(m.invoke(null,
                "u:r:untrusted_app:s0", "u:r:init:s0", "binder", "call"));
            boolean neg2 = Boolean.TRUE.equals(m.invoke(null,
                "u:r:untrusted_app:s0", "u:r:init:s0", "binder", "call"));
            if (neg1 || neg2) return;

            Object[][] rules = {
                // --- Magisk / generic root framework rules ---
                {"u:r:untrusted_app:s0",  "u:object_r:magisk_file:s0",      "file",    "read",          "magisk_file_read",             false},
                {"u:r:untrusted_app:s0",  "u:object_r:ksu_file:s0",         "file",    "read",          "ksu_file_read",                false},
                {"u:r:untrusted_app:s0",  "u:object_r:lsposed_file:s0",     "file",    "read",          "lsposed_file_read",            false},
                {"u:r:untrusted_app:s0",  "u:object_r:xposed_data:s0",      "file",    "read",          "xposed_data_read",             false},
                {"u:r:untrusted_app:s0",  "u:object_r:apd_exec:s0",         "file",    "execute",       "apd_exec_execute",             false},
                // --- su transition (user-build only, stronger signal) ---
                {"u:r:shell:s0",          "u:r:su:s0",                      "process", "transition",    "shell_su_transition",          true},
                {"u:r:untrusted_app:s0",  "u:r:su:s0",                      "process", "dyntransition", "untrusted_su_dyntransition",   false},
                // --- system_server execmem (Magisk/Zygisk injection) ---
                {"u:r:system_server:s0",  "u:r:system_server:s0",           "process", "execmem",       "system_server_execmem",        false},
                // --- LSPosed: system_server ↔ apk_data_file execute ---
                {"u:r:system_server:s0",  "u:object_r:apk_data_file:s0",    "file",    "execute",       "ss_apk_data_execute",          false},
                // --- Xposed dex2oat exec permission ---
                {"u:r:dex2oat:s0",        "u:object_r:apk_data_file:s0",    "file",    "execute",       "dex2oat_apk_data_execute",     false},
                // --- KernelSU: kernel ↔ adb_data_file ---
                {"u:r:kernel:s0",         "u:object_r:adb_data_file:s0",    "dir",     "search",        "kernel_adb_data_search",       false},
                // --- rootfs ↔ tmpfs associate (root bind-mount injection) ---
                {"u:object_r:rootfs:s0",  "u:object_r:tmpfs:s0",            "filesystem","associate",   "rootfs_tmpfs_associate",       false},
                // --- kernel ↔ tmpfs fifo_file (root pipe injection) ---
                {"u:r:kernel:s0",         "u:object_r:tmpfs:s0",            "fifo_file","write",        "kernel_tmpfs_fifo_write",      false},
                // --- adbd adbroot binder call ---
                {"u:r:adbd:s0",           "u:r:adbroot:s0",                 "binder",  "call",          "adbd_adbroot_binder",          false},
                // --- ZygiskNext daemon write (root hiding) ---
                {"u:r:zygote:s0",         "u:object_r:adb_data_file:s0",    "dir",     "search",        "zygote_adb_data_search",       false},
            };

            for (Object[] rule : rules) {
                if ((boolean) rule[5] && !isUser) continue;
                boolean r1 = Boolean.TRUE.equals(m.invoke(null, rule[0], rule[1], rule[2], rule[3]));
                boolean r2 = Boolean.TRUE.equals(m.invoke(null, rule[0], rule[1], rule[2], rule[3]));
                if (r1 && r2) {
                    out.append("WARNING:dirty_policy:").append(rule[4]).append("\n");
                }
            }
        } catch (Throwable ignored) {}
    }

    private static String getSystemProperty(String key, String def) {
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            java.lang.reflect.Method m = cls.getMethod("get", String.class, String.class);
            return (String) m.invoke(null, key, def);
        } catch (Throwable t) {
            return def;
        }
    }

    private static java.util.Set<Integer> snapshotOpenFds() {
        java.util.Set<Integer> fds = new java.util.HashSet<>();
        String[] names = new java.io.File("/proc/self/fd").list();
        if (names != null) {
            for (String n : names) {
                try { fds.add(Integer.parseInt(n)); } catch (NumberFormatException ignored) {}
            }
        }
        return fds;
    }

    private static void redirectNewFdsToDevNull(java.util.Set<Integer> baseline) {
        try {
            java.io.FileDescriptor devNull = android.system.Os.open(
                "/dev/null", android.system.OsConstants.O_RDWR, 0);
            java.lang.reflect.Field f = java.io.FileDescriptor.class.getDeclaredField("descriptor");
            f.setAccessible(true);
            int devNullFd = f.getInt(devNull);
            String[] names = new java.io.File("/proc/self/fd").list();
            if (names != null) {
                for (String n : names) {
                    int fd;
                    try { fd = Integer.parseInt(n); } catch (NumberFormatException e) { continue; }
                    if (!baseline.contains(fd) && fd != devNullFd) {
                        try { android.system.Os.dup2(devNull, fd); } catch (Throwable ignored) {}
                    }
                }
            }
            android.system.Os.close(devNull);
        } catch (Throwable ignored) {}
    }
}
