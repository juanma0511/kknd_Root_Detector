// TODO: Legacy JNI implementation. This file is not included by the current
// CMakeLists.txt and its JNI entry points still reference the old
// com.example.rootdetector package. Verify that no callers depend on it, then
// remove it in a dedicated cleanup change.

#include <jni.h>
#include <string>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <vector>
#include <fstream>
#include <sstream>

#define TAG "RootDetector"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

#define KSU_PRCTL_MAGIC_CODE 0xdeadbeef

static bool check_kernelsu_prctl() {

    errno = 0;
    long ret = prctl(0xdeadbeef, 0, 0, 0, 0);
    if (ret != 0 || errno == 0) {

        if (errno != EINVAL) {
            LOGI("KernelSU prctl hook detected (ret=%ld, errno=%d)", ret, errno);
            return true;
        }
    }

    errno = 0;
    ret = prctl(0x1314, 0, 0, 0, 0);
    if (errno != EINVAL && errno != EPERM) {
        LOGI("KernelSU Next prctl hook detected (ret=%ld, errno=%d)", ret, errno);
        return true;
    }

    return false;
}

static std::string check_maps_injection() {
    std::string result;
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return result;

    const char* suspects[] = {
        "magisk", "zygisk", "riru",
        "frida", "xposed", "lspatch",
        "dobby", "substrate", "whale",
        nullptr
    };

    const char* system_paths[] = {
        "/system/", "/apex/", "/vendor/",
        "/product/", "/odm/", nullptr
    };

    std::string line;
    while (std::getline(maps, line)) {
        
        if (line.find('/') == std::string::npos) continue;

        std::string lower = line;
        for (auto& c : lower) c = tolower(c);

        for (int i = 0; suspects[i]; i++) {
            if (lower.find(suspects[i]) != std::string::npos) {
                
                bool is_system = false;
                for (int j = 0; system_paths[j]; j++) {
                    if (line.find(system_paths[j]) != std::string::npos) {
                        is_system = true;
                        break;
                    }
                }
                if (!is_system) {
                    if (!result.empty()) result += "\n";
                    
                    size_t last_space = line.rfind(' ');
                    result += (last_space != std::string::npos)
                        ? line.substr(last_space + 1)
                        : line;
                }
                break;
            }
        }
    }
    return result;
}

static int count_anonymous_rwx() {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return 0;
    int count = 0;
    std::string line;
    while (std::getline(maps, line)) {
        
        if (line.find("rwxp") != std::string::npos) {
            
            std::istringstream iss(line);
            std::string addr, perms, offset, dev, inode, path;
            iss >> addr >> perms >> offset >> dev >> inode;
            if (!(iss >> path)) {
                
                count++;
            }
        }
    }
    return count;
}

static std::string check_open_files() {
    std::string result;
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) return result;

    const char* suspects[] = {
        "magisk", "zygisk", "ksu", "apatch", nullptr
    };

    struct dirent* ent;
    char link_path[256], target[512];
    while ((ent = readdir(dir)) != nullptr) {
        snprintf(link_path, sizeof(link_path), "/proc/self/fd/%s", ent->d_name);
        ssize_t len = readlink(link_path, target, sizeof(target) - 1);
        if (len <= 0) continue;
        target[len] = 0;

        std::string t = target;
        for (auto& c : t) c = tolower(c);

        for (int i = 0; suspects[i]; i++) {
            if (t.find(suspects[i]) != std::string::npos) {
                if (!result.empty()) result += "\n";
                result += target;
                break;
            }
        }
    }
    closedir(dir);
    return result;
}

static bool check_magisk_socket() {

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;

    const char* socket_names[] = {
        "@magisk_service",
        "@magisk_daemon",
        "@magiskd",
        nullptr
    };

    bool found = false;
    for (int i = 0; socket_names[i]; i++) {
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        
        size_t name_len = strlen(socket_names[i]);
        addr.sun_path[0] = '\0';
        memcpy(addr.sun_path + 1, socket_names[i] + 1, name_len - 1); 

        int ret = connect(sock, (struct sockaddr*)&addr,
                          sizeof(sa_family_t) + name_len);
        if (ret == 0) {
            found = true;
            break;
        }
    }
    close(sock);
    return found;
}

static bool check_self_uid() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.substr(0, 4) == "Uid:") {
            
            int ruid, euid;
            if (sscanf(line.c_str(), "Uid: %d %d", &ruid, &euid) == 2) {
                return ruid == 0 || euid == 0;
            }
        }
    }
    return false;
}

static bool check_data_adb_stat() {
    struct stat st{};
    
    if (stat("/data/adb", &st) == 0) return true;
    if (stat("/data/adb/magisk", &st) == 0) return true;
    if (stat("/data/adb/ksu", &st) == 0) return true;
    if (stat("/data/adb/modules", &st) == 0) return true;
    return false;
}

static std::string check_kernel_cmdline() {
    std::string result;
    std::ifstream f("/proc/cmdline");
    if (!f.is_open()) return result;
    std::string line;
    std::getline(f, line);

    const char* suspects[] = {
        "androidboot.verifiedbootstate=orange",  
        "androidboot.flash.locked=0",             
        "androidboot.vbmeta.device_state=unlocked",
        nullptr
    };
    for (int i = 0; suspects[i]; i++) {
        if (line.find(suspects[i]) != std::string::npos) {
            if (!result.empty()) result += "\n";
            result += suspects[i];
        }
    }
    return result;
}

static std::string check_props_native() {
    std::string result;

    const char* build_prop_paths[] = {
        "/system/build.prop",
        "/vendor/build.prop",
        nullptr
    };

    const char* suspicious_values[] = {
        "ro.debuggable=1",
        "ro.secure=0",
        "ro.build.type=userdebug",
        "ro.build.tags=test-keys",
        nullptr
    };

    for (int pi = 0; build_prop_paths[pi]; pi++) {
        std::ifstream f(build_prop_paths[pi]);
        if (!f.is_open()) continue;
        std::string line;
        while (std::getline(f, line)) {
            for (int si = 0; suspicious_values[si]; si++) {
                if (line.find(suspicious_values[si]) != std::string::npos) {
                    if (!result.empty()) result += "\n";
                    result += line;
                }
            }
        }
    }
    return result;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_rootdetector_detector_NativeChecks_checkKernelSUPrctl(JNIEnv*, jclass) {
    return check_kernelsu_prctl() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_rootdetector_detector_NativeChecks_checkMapInjections(JNIEnv* env, jclass) {
    return env->NewStringUTF(check_maps_injection().c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_rootdetector_detector_NativeChecks_countAnonymousRwxPages(JNIEnv*, jclass) {
    return count_anonymous_rwx();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_rootdetector_detector_NativeChecks_checkOpenFiles(JNIEnv* env, jclass) {
    return env->NewStringUTF(check_open_files().c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_rootdetector_detector_NativeChecks_checkMagiskSocket(JNIEnv*, jclass) {
    return check_magisk_socket() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_rootdetector_detector_NativeChecks_checkSelfUidIsRoot(JNIEnv*, jclass) {
    return check_self_uid() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_rootdetector_detector_NativeChecks_checkDataAdbStat(JNIEnv*, jclass) {
    return check_data_adb_stat() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_rootdetector_detector_NativeChecks_checkKernelCmdline(JNIEnv* env, jclass) {
    return env->NewStringUTF(check_kernel_cmdline().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_rootdetector_detector_NativeChecks_checkBuildPropsNative(JNIEnv* env, jclass) {
    return env->NewStringUTF(check_props_native().c_str());
}
