package com.juanma0511.rootdetector.zygote;

import android.annotation.TargetApi;
import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;

@TargetApi(29)
public final class AppZygote implements ZygotePreload {

    static volatile String result = "ERROR:preload_not_called";

    @Override
    public void doPreload(ApplicationInfo appInfo) {
        try {
            result = runChecks();
        } catch (Throwable t) {
            result = "ERROR:" + t.getClass().getSimpleName();
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
            "LSPosed_file", "Xposed_data", "MSD_app", "MSD_daemon"
        };
        String[] contexts = {
            "u:r:ksu:s0", "u:r:ksu_file:s0", "u:r:magisk:s0", "u:r:magisk_file:s0",
            "u:r:lsposed_file:s0", "u:r:xposed_data:s0", "u:r:msd_app:s0", "u:r:msd_daemon:s0"
        };
        for (int i = 0; i < labels.length; i++) {
            try {
                java.io.FileOutputStream fos = new java.io.FileOutputStream("/proc/self/attr/current");
                byte[] bytes = (contexts[i] + "\0").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                fos.write(bytes);
                fos.close();
                out.append("WARNING:attr_write:").append(labels[i]).append(":SUCCESS\n");
            } catch (java.io.IOException e) {
                String msg = e.getMessage();
                if (msg != null && msg.contains("Permission denied") && !msg.contains("Invalid argument")) {
                    out.append("WARNING:attr_write:").append(labels[i]).append(":EACCES\n");
                }
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
                {"u:r:system_server:s0",  "u:r:system_server:s0",        "process", "execmem",    "system_server_execmem",      false},
                {"u:r:untrusted_app:s0",  "u:object_r:magisk_file:s0",   "file",    "read",       "magisk_file_read",           false},
                {"u:r:untrusted_app:s0",  "u:object_r:ksu_file:s0",      "file",    "read",       "ksu_file_read",              false},
                {"u:r:untrusted_app:s0",  "u:object_r:lsposed_file:s0",  "file",    "read",       "lsposed_file_read",          false},
                {"u:r:untrusted_app:s0",  "u:object_r:xposed_data:s0",   "file",    "read",       "xposed_data_read",           false},
                {"u:r:adbd:s0",           "u:r:adbroot:s0",              "binder",  "call",       "adbd_adbroot_binder",        false},
                {"u:r:zygote:s0",         "u:object_r:adb_data_file:s0", "dir",     "search",     "zygote_adb_data_search",     false},
                {"u:r:shell:s0",          "u:r:su:s0",                   "process", "transition", "shell_su_transition",        true},
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
}
