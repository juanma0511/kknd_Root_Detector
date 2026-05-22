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
        probeAttrWrite(sb);
        probeDirtyPolicy(sb);
        return sb.length() == 0 ? "CLEAN" : sb.toString();
    }

    private static void probeAttrWrite(StringBuilder out) {
        String[] labels = {
            "KernelSU", "KernelSU_file", "Magisk", "Magisk_file",
            "LSPosed_file", "Xposed_file", "Xposed_data",
            "MSD_app", "MSD_daemon", "APatch", "ZygiskNext", "AOSP_su"
        };
        String[] contexts = {
            "u:r:ksu:s0", "u:r:ksu_file:s0", "u:r:magisk:s0", "u:r:magisk_file:s0",
            "u:r:lsposed_file:s0", "u:r:xposed_file:s0", "u:r:xposed_data:s0",
            "u:r:msd_app:s0", "u:r:msd_daemon:s0", "u:r:apd:s0", "u:r:zygisk_daemon:s0", "u:r:su:s0"
        };
        for (int i = 0; i < labels.length; i++) {
            try {
                java.io.FileOutputStream fos = new java.io.FileOutputStream("/proc/self/attr/current", false);
                try {
                    byte[] bytes = (contexts[i] + "\0").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    android.system.Os.write(fos.getFD(), bytes, 0, bytes.length);
                    out.append("WARNING:attr_write:").append(labels[i]).append(":SUCCESS\n");
                } catch (android.system.ErrnoException e) {
                    if (e.errno == android.system.OsConstants.EACCES) {
                        out.append("WARNING:attr_write:").append(labels[i]).append(":EACCES\n");
                    }
                } finally {
                    try { fos.close(); } catch (java.io.IOException ignored) {}
                }
            } catch (java.io.FileNotFoundException e) {
                break;
            }
        }
    }

    private static void probeDirtyPolicy(StringBuilder out) {
        try {
            Class<?> cls = Class.forName("android.os.SELinux");
            java.lang.reflect.Method m = cls.getMethod("checkSELinuxAccess",
                String.class, String.class, String.class, String.class);

            boolean neg1 = Boolean.TRUE.equals(m.invoke(null, "u:r:untrusted_app:s0", "u:r:init:s0", "binder", "call"));
            boolean neg2 = Boolean.TRUE.equals(m.invoke(null, "u:r:untrusted_app:s0", "u:r:init:s0", "binder", "call"));
            if (neg1 || neg2) return;

            boolean isUser = "user".equals(android.os.SystemProperties.get("ro.build.type", ""));

            Object[][] rules = {
                {"u:r:system_server:s0",  "u:r:system_server:s0",        "process", "execmem",    "system_server_execmem",       false},
                {"u:r:untrusted_app:s0",  "u:object_r:magisk_file:s0",   "file",    "read",       "magisk_file_read",            false},
                {"u:r:untrusted_app:s0",  "u:object_r:ksu_file:s0",      "file",    "read",       "ksu_file_read",               false},
                {"u:r:untrusted_app:s0",  "u:object_r:lsposed_file:s0",  "file",    "read",       "lsposed_file_read",           false},
                {"u:r:untrusted_app:s0",  "u:object_r:xposed_data:s0",   "file",    "read",       "xposed_data_read",            false},
                {"u:r:untrusted_app:s0",  "u:object_r:apd_exec:s0",      "file",    "execute",    "apd_exec_execute",            false},
                {"u:r:adbd:s0",           "u:r:adbroot:s0",              "binder",  "call",       "adbd_adbroot_binder",         false},
                {"u:r:zygote:s0",         "u:object_r:adb_data_file:s0", "dir",     "search",     "zygote_adb_data_search",      false},
                {"u:r:shell:s0",          "u:r:su:s0",                   "process", "transition", "shell_su_transition",         true},
                {"u:r:untrusted_app:s0",  "u:r:su:s0",                   "process", "dyntransition", "untrusted_su_dyntransition", false},
            };

            for (Object[] rule : rules) {
                if ((boolean) rule[5] && !isUser) continue;
                boolean r1 = Boolean.TRUE.equals(m.invoke(null, rule[0], rule[1], rule[2], rule[3]));
                boolean r2 = Boolean.TRUE.equals(m.invoke(null, rule[0], rule[1], rule[2], rule[3]));
                if (r1 && r2) {
                    out.append("WARNING:dirty_policy:").append(rule[4]).append("\n");
                }
            }
        } catch (Throwable ignored) {
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
