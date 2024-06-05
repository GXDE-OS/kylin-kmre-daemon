/*
 * Copyright (c) KylinSoft Co., Ltd. 2016-2024.All rights reserved.
 *
 * Authors:
 * Ma Chao    machao@kylinos.cn
 * Alan Xie   xiehuijun@kylinos.cn
 * Clom       huangcailong@kylinos.cn
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "utils.h"
#include "utils/load_module_manager.h"
#include "utils/rfkill_unblock_manager.h"
#include "fuse/common/lock_file.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <glibmm/keyfile.h>
#include <glibmm/fileutils.h>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <mntent.h>
#include <sys/poll.h>
#include <pwd.h>
#include <dirent.h>
#include <limits.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <sys/syslog.h>
#include "simpleIni/SimpleIni.h"

#include <regex>

#define PATH_SIZE 1024
#define BUF_SIZE 4096

namespace kmre {

static const std::string LEGACY_CONTAINER_PATH_PREFIX = "/var/lib/kydroid";
static const std::string CONTAINER_PATH_PREFIX = "/var/lib/kmre";
static const std::string LEGACY_CONTAINER_NAME_PREFIX = "kydroid";
static const std::string CONTAINER_NAME_PREFIX = "kmre";
static const std::string KMRE_CONTAINER_CONF = "/usr/share/kmre/kmre.conf";
static const std::string GROUP_IMAGE = "image";
static const std::string KEY_REPO = "repo";
static const std::string KEY_TAG = "tag";
static const std::string KEY_BASE_REPO = "base_repo";
static const std::string KEY_BASE_TAG = "base_tag";
static const std::string KMRE_FUSE = "/usr/bin/kylin-kmre-fuse";
static const std::string KMRE_FUSE3 = "/usr/bin/kylin-kmre-fuse3";
static const std::string GETSTATUS_PATH = "/usr/sbin/getstatus";
static const std::string SYSTEMCTL_PATH = "/bin/systemctl";
static const std::string RSYNC_PATH = "/usr/bin/rsync";

static const std::string DEV_PATH = "/dev";
static const std::string PROC_TTY_DRIVERS = "/proc/tty/drivers";

static const std::string fusermountPath = "/bin/fusermount";
static const std::string procFilesystems = "/proc/filesystems";

#ifdef DEBUG_DUMP_COMMAND
static void DumpCommand(const std::vector<std::string>& cmd);
#endif

std::vector<std::string> split(const std::string &s, char delim) {
    std::stringstream ss(s);
    std::string item;
    std::vector<std::string> elems;
    while (std::getline(ss, item, delim)) {
        elems.push_back(std::move(item));
    }
    return elems;
}

std::string LegacyContainerPath(const std::string& user, const int32_t& uid)
{
    std::string path;
    path = LEGACY_CONTAINER_PATH_PREFIX + "/" + LegacyContainerName(user, uid);

    return path;
}

std::string LegacyContainerName(const std::string& user, const int32_t& uid)
{
    std::string name;
    name = LEGACY_CONTAINER_NAME_PREFIX + "-" + std::to_string(uid) + "-" + user;

    return name;
}

std::string LegacyContainerNameToPath(const std::string &name)
{
    std::string path;
    path = LEGACY_CONTAINER_PATH_PREFIX + "/" + name;

    return path;
}

std::string ContainerPath(const std::string& user, const int32_t& uid)
{
    std::string path;
    path = CONTAINER_PATH_PREFIX + "/" + ContainerName(user, uid);

    return path;
}

std::string ContainerName(const std::string& user, const int32_t& uid)
{
    std::string name;
    name = CONTAINER_NAME_PREFIX + "-" + std::to_string(uid) + "-" + user;

    return name;
}

std::string ContainerNameToPath(const std::string &name)
{
    std::string path;
    path = CONTAINER_PATH_PREFIX + "/" + name;

    return path;
}

int32_t ForkExecvp(const std::vector<std::string>& args)
{
    int res = 0;
    int status = 0;
    pid_t pid;
    size_t argc = args.size();
    char** argv = (char**) calloc(argc + 1, sizeof(char*));
    for (size_t i = 0; i < argc; i++) {
        argv[i] = (char*) args[i].c_str();
    }

#ifdef DEBUG_DUMP_COMMAND
    DumpCommand(args);
#endif

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Failed to fork\n");
        res = -1;
        goto err_out;
    } else if (pid == 0) {
        if (execvp(argv[0], argv)) {
            fprintf(stderr, "executing %s failed: %s\n", argv[0], strerror(errno));
            std::quick_exit(-1);
        }
    } else {
        if (waitpid(pid, &status, 0) < 0) {
           res = errno;
           fprintf(stderr, "waitpid failed with %s\n", strerror(errno));
           goto err_out;
        }
        if (WIFEXITED(status)) {
            res = WEXITSTATUS(status);
        } else {
            res = -ECHILD;
        }
    }

err_out:

    free(argv);
    return res;
}

int32_t ForkExecvp(const std::vector<std::string>& args,
        std::vector<std::string>& output)
{
    std::string cmd;
    for (size_t i = 0; i < args.size(); i++) {
        cmd += args[i] + " ";
    }
    output.clear();

#ifdef DEBUG_DUMP_COMMAND
    DumpCommand(args);
#endif

    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) {
        fprintf(stderr, "Failed to popen %s\n", cmd.c_str());
        return -errno;
    }
    char line[4096];
    char* find;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        find = strchr(line, '\n');
        if (find) {
            *find = '\0';
        }
        output.push_back(std::string(line));
    }
    if (pclose(fp) != 0) {
        fprintf(stderr, "Failed to pclose %s\n", cmd.c_str());
        return -errno;
    }

    return 0;
}

pid_t ForkExecvpAsync(const std::vector<std::string>& args)
{
    size_t argc = args.size();
    char** argv = (char**) calloc(argc + 1, sizeof(char*));
    for (size_t i = 0; i < argc; i++) {
        argv[i] = (char*) args[i].c_str();
    }

#ifdef DEBUG_DUMP_COMMAND
    DumpCommand(args);
#endif

    pid_t pid = fork();
    if (pid == 0) {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        if (execvp(argv[0], argv)) {
            fprintf(stderr, "Failed to exec\n");
        }

        std::quick_exit(-1);
    }

    if (pid == -1) {
        fprintf(stderr, "Failed to exec\n");
    }

    free(argv);
    return pid;
}

static int procOpenAndRead(const std::vector<std::string>& args, pid_t& child)
{
    volatile int parent_end = -1;
    volatile int child_end = -1;
    int pipe_fds[2];
    pid_t child_pid = -1;

    size_t argc = args.size();
    char** argv = (char**) calloc(argc + 1, sizeof(char*));
    for (size_t i = 0; i < argc; i++) {
        argv[i] = (char*) args[i].c_str();
    }

    if (pipe(pipe_fds) < 0) {
        free(argv);
        return -1;
    }

    parent_end = pipe_fds[0];
    child_end = pipe_fds[1];

    child_pid = fork();

    if (child_pid < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        child = child_pid;
        free(argv);
        return -1;
    }

    if (child_pid == 0) {
        int child_std_end = STDOUT_FILENO;

        // close read end
        close(parent_end);

        if (child_end != child_std_end) {
            dup2(child_end, child_std_end);
            close(child_end);
        }

        if (execvp(argv[0], argv)) {
            fprintf(stderr, "executing %s failed: %s\n", argv[0], strerror(errno));
            std::quick_exit(-1);
        }
    }

    // close write end for parent process
    close(child_end);
    free(argv);

    child = child_pid;

    return parent_end;
}

int32_t ForkExecvpWithTimeout(const std::vector<std::string>& args,
                              std::vector<std::string>& output,
                              int timeout)
{
    int status = 0;
    int res = -1;
    pid_t child_pid = -1;
    int child_fd = -1;
    struct pollfd pollfds[1];
    int err;
    FILE* fp = nullptr;
    char line[4096] = {0};
    char* find;

    if (timeout < 0) {
        return ForkExecvp(args, output);
    }

    child_fd = procOpenAndRead(args, child_pid);
    if (child_fd < 0) {
        return -1;
    }

    if (child_pid < 0) {
        goto err_out;
    }

    pollfds[0].fd = child_fd;
    pollfds[0].events = POLLIN | POLLPRI;

    err = poll(pollfds, 1, timeout);
    if (err <= 0) {
        kill(child_pid, SIGTERM);
        res = -1;
        goto wait_child;
    }

    fp = fdopen(child_fd, "r");
    if (fp == nullptr) {
        goto wait_child;
    }

    output.clear();

    while (fgets(line, sizeof(line), fp) != nullptr) {
        find = strchr(line, '\n');
        if (find) {
            *find = '\0';
        }
        output.push_back(std::string(line));
    }

wait_child:

    if (waitpid(child_pid, &status, 0) < 0) {
        res = errno;
        fprintf(stderr, "waitpid failed with %s\n", strerror(errno));
        goto err_out;
    }
    if (WIFEXITED(status)) {
        res = WEXITSTATUS(status);
    } else {
        res = -ECHILD;
    }

err_out:
    if (fp) {
        fclose(fp);
    } else if (child_fd >= 0) {
        close(child_fd);
    }

    return res;
}

static std::string KeyFileGetString(const std::string& path, const std::string& group, const std::string& key)
{
    Glib::KeyFile keyFile;
    std::string value;
    bool keyFileLoaded = false;

    try {
        keyFileLoaded = keyFile.load_from_file(path, Glib::KEY_FILE_KEEP_COMMENTS | Glib::KEY_FILE_KEEP_TRANSLATIONS);
    } catch (Glib::FileError& error) {
        fprintf(stderr, "Failed to access file %s: %s\n", path.c_str(), error.what().c_str());
    } catch (Glib::KeyFileError& error) {
        fprintf(stderr, "Failed to load keyfile from file %s: %s\n", path.c_str(), error.what().c_str());
    }

    if (!keyFileLoaded) {
        return value;
    }

    if (!keyFile.has_group(group)) {
        return value;
    }

    if (!keyFile.has_key(group, key)) {
        return value;
    }

    value = keyFile.get_string(group, key);
    return value;
}

std::string ImageRepo()
{
    return KeyFileGetString(KMRE_CONTAINER_CONF, GROUP_IMAGE, KEY_REPO);
}

std::string ImageTag()
{
    return KeyFileGetString(KMRE_CONTAINER_CONF, GROUP_IMAGE, KEY_TAG);
}

std::string ImageVersion()
{
    std::string repo;
    std::string tag;
    std::string v;

    repo = ImageRepo();
    if (repo.empty() || repo.length() == 0) {
        return v;
    }

    tag = ImageTag();
    if (tag.empty() || tag.length() == 0) {
        return v;
    }

    v = repo + ":" + tag;
    return v;
}

bool ParseContainerName(const std::string& containerName, std::string& userName, int32_t& uid)
{
    int32_t _uid = -1;
    int ret = 0;
    char buffer[1024] = {0};

    ret = sscanf(containerName.c_str(), "kmre-%d-%s", &_uid, buffer);
    if (ret != 2) {
        return false;
    }

    if (_uid < 0) {
        return false;
    }

    uid = _uid;

    userName = std::string(buffer);

    return true;
}

std::string PrepareUserName(const std::string& userName)
{
    char buffer[BUF_SIZE] = {0};
    std::string name = userName;
    unsigned int i = 0;
    const char* str = nullptr;

    str = userName.c_str();
    if (str && strstr(str, "\\")) {
        snprintf(buffer, sizeof(buffer), "%s", str);
        for (i = 0; i < sizeof(buffer); ++i) {
            if ('\0' == buffer[i]) {
                break;
            }

            if ('\\' == buffer[i]) {
                buffer[i] = '_';
            }
        }

        name = buffer;
    }

    return name;
}

bool ParseImageVersion(const std::string& imageVersion, std::string& repo, std::string& tag)
{
    auto ss = split(imageVersion, ':');
    if (ss.size() != 2) {
        return false;
    }

    repo = ss[0];
    tag = ss[1];

    return true;
}

void CreateFile(const std::string& path, int mode)
{
    int fd;

    fd = open(path.c_str(), O_RDWR | O_CLOEXEC | O_CREAT, mode);
    if (fd < 0)
        return;

    close(fd);

    chmod(path.c_str(), mode);
}

static bool _isPathMounted(const std::string &path)
{
    bool found_mp = false;
    FILE *fp = setmntent("/proc/mounts", "r");
    if (fp == nullptr) {
        fprintf(stderr, "Error opening /proc/mounts (%s)\n", strerror(errno));
        return false;
    }

    mntent* mentry;
    while ((mentry = getmntent(fp)) != nullptr) {
        if (strcmp(mentry->mnt_dir, path.c_str()) == 0) {
            found_mp = true;
            break;
        }
    }
    endmntent(fp);
    return found_mp;
}

bool isPathMounted(const std::string &path)
{
    char realPath[PATH_MAX] = {0};

    if (realpath(path.c_str(), realPath)) {
        if (_isPathMounted(realPath)) {
            return true;
        }
    }

    return _isPathMounted(path);
}

static bool _isPathMountedWithType(const std::string &path, const std::string &type)
{
    bool mountedWithType = false;
    FILE *fp = setmntent("/proc/mounts", "r");
    if (fp == nullptr) {
        fprintf(stderr, "Error opening /proc/mounts (%s)\n", strerror(errno));
        return false;
    }

    mntent* mentry;
    while ((mentry = getmntent(fp)) != nullptr) {
        if (strcmp(mentry->mnt_dir, path.c_str()) == 0) {
            if (strcmp(mentry->mnt_type, type.c_str()) == 0) {
                mountedWithType = true;
            }
        }
    }
    endmntent(fp);
    return mountedWithType;
}

bool isPathMountedWithType(const std::string &path, const std::string &type)
{
    char realPath[PATH_MAX] = {0};

    if (realpath(path.c_str(), realPath)) {
        if (_isPathMountedWithType(realPath, type)) {
            return true;
        }
    }

    return _isPathMountedWithType(path, type);
}

int UnmountPathIfMounted(const std::string &path)
{
    int ret = 0;
    char realPath[PATH_MAX] = {0};

    if (!isPathMounted(path)) {
        return 0;
    }

    if (realpath(path.c_str(), realPath)) {
        ret = umount2(realPath, MNT_DETACH);
        if (ret == 0) {
            return 0;
        }
    }

    return umount2(path.c_str(), MNT_DETACH);
}

static bool fuseIsFuse3()
{
    char symlink_path[512] = {0};
    ssize_t size = -1;

    if (isPathRegularFile(fusermountPath, false)) {
        return false;
    }

    if (isPathSymlink(fusermountPath, false)) {
        size = readlink(fusermountPath.c_str(), symlink_path, sizeof(symlink_path));
        if (size > 0 && strstr(symlink_path, "fusermount3")) {
            return true;
        }
    }

    return false;
}

int32_t FuseMount(const std::string &destination, const std::string &source, int32_t uid, int32_t gid, int32_t set_uid, int32_t set_gid, bool allow_delete)
{
    /*
     * kylin-kmre-fuse -u ${set_uid} -g ${set_gid} ${destination} [--allow-delete] -o rw,nosuid,nodev,noexec,noatime,uid=${uid},gid=${gid},\
     *        default_permissions,allow_other,auto_unmount,nonempty,fsname=/dev/fuse,subtype=,\
     *        modules=subdir,subdir=${source}
     */
    std::vector<std::string> cmd;
    std::string arg;

    struct stat destSb, sourceSb;
    if ((stat(destination.c_str(), &destSb) != 0) ||
        (stat(source.c_str(), &sourceSb) != 0)) {
        return -1;
    }

    /* for arg */

    // rw,nosuid,nodev,noexec,noatime,
    arg = "rw,nosuid,nodev,noexec,noatime,";

    // uid=${uid},
    arg += ("uid=" + std::to_string(uid) + ",");

    // gid=${gid},
    arg += ("gid=" + std::to_string(gid) + ",");

    if (fuseIsFuse3()) {
        // Option nonempty is removed in fuse3
        // default_permissions,allow_other,auto_unmount,fsname=/dev/fuse,subtype=,
        arg += "default_permissions,allow_other,auto_unmount,fsname=/dev/fuse,subtype=,";
    } else {
        // default_permissions,allow_other,auto_unmount,nonempty,hard_remove,fsname=/dev/fuse,subtype=,
        arg += "default_permissions,allow_other,auto_unmount,nonempty,hard_remove,fsname=/dev/fuse,subtype=,";
    }

    // modules=subdir,
    arg += "modules=subdir,";

    // subdir=${source}
    arg += ("subdir=" + source);


    if (fuseIsFuse3()) {
        cmd.push_back(KMRE_FUSE3);
    } else {
        cmd.push_back(KMRE_FUSE);
    }
    cmd.push_back("-u");
    cmd.push_back(std::to_string(set_uid));
    cmd.push_back("-g");
    cmd.push_back(std::to_string(set_gid));
    if (allow_delete) {
        cmd.push_back("--allow-delete");
    }
    cmd.push_back(destination);
    cmd.push_back("-o");
    cmd.push_back(arg);

    return ForkExecvp(cmd);
}

int32_t MountPath(const std::string &destination, const std::string &source, const std::string &fsType, const unsigned long flags, const std::string &options)
{
    return mount(source.c_str(), destination.c_str(), fsType.c_str(), flags, options.c_str());
}

void unlinkFuseLockFile(const std::string& mountpoint)
{
    char lockfile_name[256] = {0};
    char lockfile_path[1024] = {0};

    slash_to_underline(mountpoint.c_str(), lockfile_name);
    sprintf(lockfile_path, "%s/.kmre-%s", LOCKFILE_PREFIX, lockfile_name);

    if (access(lockfile_path, F_OK) == 0) {
        unlink(lockfile_path);
    }
}

#ifdef DEBUG_DUMP_COMMAND
static void DumpCommand(const std::vector<std::string>& cmd)
{
    for (auto arg : cmd) {
        printf("%s ", arg.c_str());
    }
    printf("\n");
}
#endif

bool isPathFileType(const std::string &path, mode_t fileType, bool dereference)
{
    struct stat sb;
    int ret = 0;

    if (dereference) {
        ret = stat(path.c_str(), &sb);
    } else {
        ret = lstat(path.c_str(), &sb);
    }

    if (ret != 0) {
        return false;
    }

    return ((sb.st_mode & S_IFMT) == fileType);
}

bool isPathSymlink(const std::string &path, bool dereference)
{
    return isPathFileType(path, S_IFLNK, dereference);
}

bool isPathDir(const std::string &path, bool dereference)
{
    return isPathFileType(path, S_IFDIR, dereference);
}

bool isPathCharDevice(const std::string &path, bool dereference)
{
    return isPathFileType(path, S_IFCHR, dereference);
}

bool isPathRegularFile(const std::string &path, bool dereference)
{
    return isPathFileType(path, S_IFREG, dereference);
}

bool isPathReadable(const std::string &path)
{
    if (access(path.c_str(), R_OK) == 0) {
        return true;
    }

    return false;
}

bool pathExists(const std::string &path)
{
    struct stat sb;

    return (lstat(path.c_str(), &sb) == 0);
}

void loadModule(const std::string &moduleName)
{
    utils::LoadModuleManager* loadModuleManager = utils::LoadModuleManager::getInstance();
    if (loadModuleManager) {
        loadModuleManager->loadModule(moduleName);
    }
}

void rfkillUnblockDeviceByIndex(uint32_t index)
{
    if (isRfkillVirtualDeviceByIndex(index)) {
        utils::RfkillUnblockManager* rfkillUnblockManager = utils::RfkillUnblockManager::getInstance();
        if (rfkillUnblockManager) {
            rfkillUnblockManager->unblockDeviceByIndex(index);
        }
    }
}

bool isRfkillVirtualDeviceByIndex(uint32_t index) {
    char rfkill_file_path[512] = {0};
    char symlink_path[512] = {0};
    ssize_t path_size;

    snprintf(rfkill_file_path, sizeof(rfkill_file_path), "/sys/class/rfkill/rfkill%u", index);
    path_size = readlink(rfkill_file_path, symlink_path, sizeof(symlink_path));
    if (path_size > 0) {
        if (strstr(symlink_path, "virtual/ieee80211/")) {
            return true;
        }
    }

    return false;
}

void rfkillUnblockVirtualDevices()
{
    uint32_t i;

    for (i = 0; i < 255; i++) {
        if (isRfkillVirtualDeviceByIndex(i)) {
            rfkillUnblockDeviceByIndex(i);
        }
    }
}


std::string sha512sum(const void *data, size_t size)
{
    unsigned char md[SHA512_DIGEST_LENGTH] = {0};
    char digest[2 * SHA512_DIGEST_LENGTH + 1] = {0};
    SHA512_CTX ctx;
    int i;

    SHA512_Init(&ctx);
    SHA512_Update(&ctx, data, size);
    SHA512_Final(md, &ctx);

    for (i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(&digest[2 * i], "%02x", md[i] & 0xff);
    }

    for (i = 0; i < 2 * SHA512_DIGEST_LENGTH; i++) {
        if (isupper(digest[i])) {
            digest[i] = tolower(digest[i]);
        }
    }

    return std::string(digest);
}

bool isStringValid(const std::string &str)
{
    if (str.empty() || (str.length() == 0)) {
        return false;
    }
    return true;
}

bool isUserNameValid(const std::string& userName)
{
    static std::regex r_all("[`~!#%^&*()=+{}[|;:'\",<>/? ]");
    std::smatch m;
    const char* s = userName.c_str();
    char* p = nullptr;

    if (std::regex_search(userName, r_all)) {
        return false;
    }

    if (strstr((char*)s, "]") != nullptr) {
        return false;
    }

    p = strstr((char*)s, "$");
    if (p != nullptr) {
        ++p;
        if ('\0' != *p) {
            return false;
        }
    }

    return true;
}

std::string getHomePathFromUid(uid_t uid)
{
    std::string home = "";
    struct stat sb;
    char buf[4096] = {0};
    struct passwd pwd;
    struct passwd* result = nullptr;

    if (getpwuid_r(uid, &pwd, buf, sizeof(buf), &result) == 0) {
        if (result && pwd.pw_dir) {
            if (stat(pwd.pw_dir, &sb) == 0) {
                if (((sb.st_mode & S_IFMT) == S_IFDIR) && (sb.st_uid == uid)) {
                    home = pwd.pw_dir;
                }
            }
        }
    }

    return home;
}

static void listSerialPortDevices(const std::string& serialPortDevicesPrefix, std::set<std::string>& serialPortDevices)
{
    struct dirent* entry = nullptr;
    DIR* dp = nullptr;

    dp = opendir(DEV_PATH.c_str());
    if (!dp) {
        return;
    }

    while ((entry = readdir(dp)) != nullptr) {
        char filePath[PATH_MAX + NAME_MAX + 1] = {0};
        if (strlen(entry->d_name) == 0) {
            continue;
        }

        if (entry->d_name[0] == '.') {
            continue;
        }

        snprintf(filePath, PATH_MAX + NAME_MAX + 1, "%s/%s", DEV_PATH.c_str(), entry->d_name);
        if (!isPathCharDevice(filePath)) {
            continue;
        }

        if (strncmp(filePath, serialPortDevicesPrefix.c_str(), serialPortDevicesPrefix.length()) == 0) {
            serialPortDevices.insert(filePath);
        }
    }

    closedir(dp);
}

bool getProcessNameByPid(uint32_t pid, std::string &comm)
{
    char path[PATH_SIZE] = {0};
    char buf[BUF_SIZE] = {0};
    struct stat sb;
    size_t n;
    FILE *fp = nullptr;

    bool result = false;

    snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    if (stat(path, &sb) != 0) {
        goto error_out;
    }

    fp = fopen(path, "r");
    if (!fp) {
        goto error_out;
    }

    n = fread(buf, sizeof(char), sizeof(buf), fp);
    if (n <= 0) {
        goto error_out;
    }

    if (ferror(fp)) {
        goto error_out;
    }

    result = true;
    comm = buf;

error_out:
    if (fp)
        fclose(fp);

    return result;
}

static int runSystemdCommandForService(const std::string &command, const std::string &service)
{
    std::vector<std::string> cmd;

    // /bin/systemctl <command> <service>
    cmd.push_back(SYSTEMCTL_PATH);
    cmd.push_back(command);
    cmd.push_back(service);

    return ForkExecvp(cmd);
}

int startSystemdService(const std::string &service)
{
    return runSystemdCommandForService("start", service);
}

int unmaskSystemdService(const std::string &service)
{
    return runSystemdCommandForService("unmask", service);
}

static std::vector<std::string> listFileUnderDirectory(const std::string& path, bool keepPrefix = true)
{
    std::vector<std::string> list;
    struct dirent* entry = nullptr;
    DIR* dp = nullptr;

    if (!isPathDir(path)) {
        return list;
    }

    dp = opendir(path.c_str());
    if (!dp) {
        return list;
    }

    while ((entry = readdir(dp)) != nullptr) {
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        if (entry->d_type == DT_DIR ||
                entry->d_type == DT_LNK ||
                entry->d_type == DT_REG) {
            if (keepPrefix) {
                list.push_back(path + "/" + entry->d_name);
            } else {
                list.push_back(entry->d_name);
            }
        } else {
            continue;
        }
    }

    closedir(dp);

    return list;
}

bool isRsyncAvailable()
{
    return (access(RSYNC_PATH.c_str(), R_OK | X_OK) == 0);
}

int rsyncFilesUnderPath(const std::string &target, const std::string &source)
{
    std::vector<std::string> cmd;
    std::vector<std::string> list;

    list = listFileUnderDirectory(source);

    if (list.size() == 0) {
        return -1;
    }

    if (!isRsyncAvailable()) {
        return -1;
    }

    // /usr/bin/rsync -rlptgoX source/* target/
    cmd.push_back(RSYNC_PATH);
    cmd.push_back("-rlptgoX");
    for (std::string entry : list) {
        cmd.push_back(entry);
    }
    cmd.push_back(target + "/");

    return ForkExecvp(cmd);
}

bool getSerialPortDevices(std::set<std::string>& serialPortDevices)
{
    FILE* fp = nullptr;
    char buffer[1024] = {0};
    std::set<std::string> serialPortDevicesPrefixes;

    fp = fopen(PROC_TTY_DRIVERS.c_str(), "r");
    if (!fp) {
        return false;
    }

    serialPortDevices.clear();

    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        char* p;
        char driverName[256] = {0};
        char deviceName[256] = {0};
        unsigned int deviceMajor = 0;
        char driverMinor[256] = {0};
        char driverType[256] = {0};

        p = strchr(buffer, '\n');
        if (p != nullptr) {
            *p = '\0';
        }

        if (5 != sscanf(buffer, "%s %s %u %s %s",
                        driverName,
                        deviceName,
                        &deviceMajor,
                        driverMinor,
                        driverType)) {
            continue;
        }

        if (strncmp(driverType, "serial", strlen("serial")) != 0) {
            continue;
        }

        serialPortDevicesPrefixes.insert(deviceName);
    }

    std::set<std::string>::const_iterator it = serialPortDevicesPrefixes.begin();
    while (it != serialPortDevicesPrefixes.end()) {
        listSerialPortDevices(*it, serialPortDevices);
        it++;
    }

    fclose(fp);

    return true;
}

static bool ReadFdToString(int fd, std::string* content)
{
    struct stat sb;
    char buf[BUFSIZ] = {0};
    ssize_t n;

    content->clear();

    if (fstat(fd, &sb) != -1 && sb.st_size > 0) {
        content->reserve(sb.st_size);
    }

    while ((n = TEMP_FAILURE_RETRY(read(fd, &buf[0], sizeof(buf)))) > 0) {
        content->append(buf, n);
    }

    return (n == 0) ? true : false;
}

static bool ReadFileToString(const std::string& path, std::string* content)
{
    bool result;

    content->clear();

    int flags = O_RDONLY | O_CLOEXEC;

    int fd = TEMP_FAILURE_RETRY(open(path.c_str(), flags));
    if (fd == -1) {
        return false;
    }

    result = ReadFdToString(fd, content);

    close(fd);
    return result;
}

bool isFilesystemSupported(const std::string& fsType)
{
    std::string supported;
    if (!ReadFileToString(procFilesystems, &supported)) {
        return false;
    }

    return supported.find(fsType + "\n") != std::string::npos;
}

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif

#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

bool isMemfdSupported()
{
    int fd = -1;
    bool result = false;

    fd = syscall(SYS_memfd_create, "test_memfd", MFD_ALLOW_SEALING);
    if (fd < 0) {
        goto out;
    }

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) < 0) {
        goto out;
    }

    result = true;

out:
    if (fd >= 0) {
        close(fd);
    }

    return result;
}

std::string getIniSetting(const char* iniFile, const char* section, const char* key, const char* defaultSetting)
{
    CSimpleIniA ini;
    SI_Error rc;
    rc = ini.LoadFile(iniFile);
    if (rc < 0) { 
        syslog(LOG_ERR, "Can't load ini settings file: '%s'.", iniFile);
        return "";
    }
    ini.SetUnicode(true);

    std::string value = ini.GetValue(section, key, defaultSetting);
    syslog(LOG_DEBUG, "Get ini setting: [%s:%s]=%s", section, key, value.c_str());
    return value;
}

std::string getMacAddressByInterface(const char* interface)
{
    if (!interface) {
        return "";
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return "";
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, interface);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return "";
    }

    close(sock);

    unsigned char mac_addr[6];
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    char mac_addr_str[32] = {0};
    sprintf(mac_addr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    
    syslog(LOG_DEBUG, "MAC Address of %s: %s", interface, mac_addr_str);
    return std::string(mac_addr_str);
}

} // namespace kmre
