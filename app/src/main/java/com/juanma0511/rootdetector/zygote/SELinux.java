package com.juanma0511.rootdetector.zygote;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Pair;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Direct selinuxfs access, ported verbatim from LSPosed/DirtySepolicy
 * (https://github.com/LSPosed/DirtySepolicy). Deliberately uses NO reflection
 * on the hidden {@code android.os.SELinux} class: that class is on the hidden-API
 * blocklist, and touching it inside the app_zygote preload process aborts the
 * process, so the system silently falls back to a plain isolated process and the
 * {@link AppZygote} preload never runs. Reading the selinuxfs pseudo-files
 * directly avoids that entirely and works from the app_zygote domain (which,
 * unlike untrusted_app/isolated_app, holds {@code security:check_context} and
 * {@code security:compute_av}).
 */
public final class SELinux {
    private static final Path SELINUX_FS = Paths.get("/sys/fs/selinux");
    private static final Map<String, Pair<Integer, Integer>> permCache = new HashMap<>();

    public static Pair<Integer, Integer> readIndex(String className, String permName) {
        var classDir = SELINUX_FS.resolve("class");
        var key = className + ":" + permName;
        var value = permCache.get(key);
        if (value != null) {
            return value;
        }
        try {
            var clazz = classDir.resolve(className);
            var bytes = Files.readAllBytes(clazz.resolve("index"));
            var classId = Integer.parseInt(new String(bytes).trim());

            var perm = clazz.resolve("perms").resolve(permName);
            var permId = Integer.parseInt(new String(Files.readAllBytes(perm)).trim());
            value = Pair.create(classId, 1 << (permId - 1));
            permCache.put(key, value);
            return value;
        } catch (IOException e) {
            throw new RuntimeException("readId: " + e.getMessage(), e);
        }
    }

    public static String[] access(String scon, String tcon, int tclass) throws ErrnoException {
        try (var access = new RandomAccessFile(SELINUX_FS.resolve("access").toFile(), "rw")) {
            var query = scon + " " + tcon + " " + tclass;
            var data = query.getBytes(StandardCharsets.UTF_8);
            Os.write(access.getFD(), data, 0, data.length);
            var result = new byte[64];
            var ret = access.read(result);
            var str = new String(result, 0, ret);
            var avd = str.split(" ");
            if (avd.length != 6) {
                throw new RuntimeException("Invalid access result: " + str);
            }
            return avd;
        } catch (IOException e) {
            throw new RuntimeException("access: " + e.getMessage(), e);
        }
    }

    public static boolean checkSELinuxAccess(String scon, String tcon, String tclass, String perm) {
        var pair = readIndex(tclass, perm);
        try {
            var parts = access(scon, tcon, pair.first);
            var allowd = Integer.parseUnsignedInt(parts[0], 16);
            return (allowd & pair.second) == pair.second;
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.EINVAL) {
                return false;
            }
            throw new RuntimeException("checkSELinuxAccess: " + e.getMessage(), e);
        }
    }

    public static boolean contextExists(String context) {
        var data = context.getBytes(StandardCharsets.UTF_8);

        try (var file = new FileOutputStream(SELINUX_FS.resolve("context").toFile())) {
            Os.write(file.getFD(), data, 0, data.length);
            return true;
        } catch (ErrnoException e) {
            if (e.errno != OsConstants.EINVAL) {
                throw new RuntimeException("security_check_context errno=" + e.errno, e);
            }
        } catch (IOException e) {
            throw new RuntimeException("security_check_context: " + e.getMessage(), e);
        }

        try {
            access(context, context, 0);
            return true;
        } catch (ErrnoException e) {
            if (e.errno != OsConstants.EINVAL) {
                throw new RuntimeException("selinux_check_access: " + e.getMessage(), e);
            }
        }

        try (var current = new FileOutputStream("/proc/self/attr/current")) {
            Os.write(current.getFD(), data, 0, data.length);
            throw new RuntimeException("SELinux is broken");
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.EINVAL) {
                return false;
            }
            if (e.errno == OsConstants.EPERM) {
                return true;
            }
            throw new RuntimeException("setcon errno=" + e.errno, e);
        } catch (IOException e) {
            throw new RuntimeException("setcon: " + e.getMessage(), e);
        }
    }

    public static ByteBuffer readStatus() {
        try (var status = new FileInputStream(SELINUX_FS.resolve("status").toFile())) {
            var buffer = ByteBuffer.allocate(20);
            buffer.order(ByteOrder.nativeOrder());
            Os.read(status.getFD(), buffer);
            return buffer;
        } catch (ErrnoException e) {
            throw new RuntimeException("read_status errno=" + e.errno, e);
        } catch (IOException e) {
            throw new RuntimeException("read_status: " + e.getMessage(), e);
        }
    }

    public static boolean isSELinuxEnabled() {
        return Files.isDirectory(SELINUX_FS);
    }

    public static boolean isSELinuxEnforced() {
        var enforce = SELINUX_FS.resolve("enforce");
        try {
            var str = new String(Files.readAllBytes(enforce));
            return Integer.parseInt(str.trim()) == 1;
        } catch (IOException e) {
            return false;
        }
    }

    public static String getFileContext(String path) {
        try {
            return new String(Os.getxattr(path, "security.selinux")).trim();
        } catch (ErrnoException e) {
            return null;
        }
    }

    public static String getContext() {
        var path = Paths.get("/proc/self/task/" + Os.gettid() + "/attr/current");
        try {
            return new String(Files.readAllBytes(path)).replace("\0", "").trim();
        } catch (IOException e) {
            return null;
        }
    }

    public static String getPidContext(int pid) {
        var path = Paths.get("/proc/" + pid + "/attr/current");
        try {
            return new String(Files.readAllBytes(path)).replace("\0", "").trim();
        } catch (IOException e) {
            return null;
        }
    }
}
