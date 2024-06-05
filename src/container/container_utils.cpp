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

#include "container_utils.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <mntent.h>
#include <sys/poll.h>
#include <sys/syslog.h>
#include <pwd.h>
#include <dirent.h>
#include <glibmm/keyfile.h>
#include <glibmm/fileutils.h>

namespace kmre {
namespace container {

static const std::string kmrePath = "/var/lib/kmre";
static const std::string legacyPath = "/var/lib/kydroid";

#define OVERLAY_DIRECTORIES_TYPE_NUMBER 3
static const char overlayDirectoryTypes[OVERLAY_DIRECTORIES_TYPE_NUMBER][16] = {
    "LowerDir",
    "MergedDir",
    "UpperDir",
};

static const std::string DOCKER_PATH = "/usr/bin/docker";

static std::string inspectContainer(const std::string& containerName, const std::string& format)
{
    std::vector<std::string> cmd;
    std::vector<std::string> output;
    std::string value;
    int ret = 0;

    cmd.push_back(DOCKER_PATH);
    cmd.push_back("inspect");
    cmd.push_back(containerName);
    cmd.push_back("--format");
    cmd.push_back(format);

    ret = ForkExecvp(cmd, output);
    if (ret < 0) {
        return value;
    }

    if (output.size() > 0) {
        value = output[0];
    }

    return value;
}

int getNumberOfCpus()
{
    std::vector<std::string> cmd;
    std::vector<std::string> output;
    int num = 0;
    int ret = 0;

    // /usr/bin/docker info --format '{{.NCPU}}'
    cmd.push_back(DOCKER_PATH);
    cmd.push_back("info");
    cmd.push_back("--format");
    cmd.push_back("'{{.NCPU}}'");

    ret = ForkExecvp(cmd, output);
    if (ret == 0 && output.size() > 0) {
        std::string numString = output[0];
        num = atoi(numString.c_str());
        if (num < 0) {
            num = 0;
        }
    }

    return num;
}

int updateContainerCpuNumber(const std::string &containerName, int num)
{
    std::vector<std::string> cmd;

    // /usr/bin/docker update --cpus <num> <containerName>
    cmd.push_back(DOCKER_PATH);
    cmd.push_back("update");
    cmd.push_back("--cpus");
    cmd.push_back(std::to_string(num));
    cmd.push_back(containerName);

    return ForkExecvp(cmd);
}

std::string inspectOverlayDirectories(const std::string& obj, const std::string& type)
{
    // obj is an image name or a container name

    std::vector<std::string> cmd;
    std::vector<std::string> output;
    std::string value;
    int ret = 0;

    cmd.push_back(DOCKER_PATH);
    cmd.push_back("inspect");
    cmd.push_back(obj);
    cmd.push_back("--format");
    cmd.push_back("'{{.GraphDriver.Data." + type + "}}'");

    ret = ForkExecvp(cmd, output);
    if (ret < 0) {
        return value;
    }

    if (output.size() > 0) {
        value = output[0];
    }

    return value;
}

std::string inspectOverlayDirectories(const std::string& obj)
{
    std::string output;
    std::string value;

    int i = 0;

    // docker inspect obj --format '{{.GraphDriver.Data.LowerDir}}'
    // docker inspect obj --format '{{.GraphDriver.Data.MergedDir}}'
    // docker inspect obj --format '{{.GraphDriver.Data.UpperDir}}'

    for (i = 0; i < OVERLAY_DIRECTORIES_TYPE_NUMBER; i++) {
        value = inspectOverlayDirectories(obj, overlayDirectoryTypes[i]);
        if (value.length() > 0) {
            output += (":" + value);
        }
    }

    return output;
}

std::string getDockerStorageDriver()
{

    std::vector<std::string> cmd;
    std::vector<std::string> out;
    int ret;

    // /usr/bin/docker info --format {{.Driver}}
    cmd.push_back(DOCKER_PATH);
    cmd.push_back("info");
    cmd.push_back("--format");
    cmd.push_back("{{.Driver}}");

    ret = ForkExecvp(cmd, out);

    if (ret == 0) {
        if (out.size() == 1) {
            return out[0];
        }
    }

    return std::string();
}

bool getContainerNetworkInformation(const std::string &containerName, ContainerNetworkInfo &info)
{
    std::string mode;

    mode = inspectContainer(containerName, "{{.HostConfig.NetworkMode}}");
    if ((mode == "default") || (mode == "bridge")) {
        info.mode = "bridge";
    } else if (mode == "host") {
        info.mode = "host";
    } else {
        info.mode = "unknown";
        return false;
    }

    info.ipAddress = inspectContainer(containerName, "{{.NetworkSettings.IPAddress}}");
    info.gateway = inspectContainer(containerName, "{{.NetworkSettings.Gateway}}");

    return true;
}

std::string getContainerCgroupnsMode(const std::string& containerName)
{
    std::string mode;

    mode = inspectContainer(containerName, "'{{.HostConfig.CgroupnsMode}}'");

    return mode;
}

int mountFixedDirectories(const std::string& containerName)
{
    std::string fuseSource;
    std::string fuseDest;
    std::string fuseKylinFileSource;
    std::string fuseKylinFileDest;
    std::string fuseKylinRemovableStorageSource;
    std::string fuseKylinRemovableStorageDest;
    std::string fuseKylinDataPartitionSource;
    std::string fuseKylinDataPartitionDest;
    std::string fuseKylinLogSource;
    std::string fuseKylinLogDest;
    std::string userName;
    std::string homeDir;
    int32_t uid;
    int ret = 0;

    if (!ParseContainerName(containerName, userName, uid)) {
        syslog(LOG_ERR, "ContainerUtils: Failed to parse container name %s.", containerName.c_str());
        return -1;
    }

    homeDir = getHomePathFromUid(uid);
    if (homeDir == "") {
        homeDir = "/home/" + userName;
    }
    fuseSource = kmrePath + "/" + containerName + "/data/media/0";
    fuseDest = kmrePath + "/data/" + containerName;
    if (homeDir.length() != 0) {
        fuseKylinFileSource = homeDir;
        fuseKylinFileDest = fuseSource + "/0-麒麟文件";
    }

    fuseKylinRemovableStorageSource = "/media";
    fuseKylinRemovableStorageDest = fuseSource + "/0-麒麟移动存储设备";

    fuseKylinDataPartitionSource = "/data";
    fuseKylinDataPartitionDest = fuseSource + "/0-麒麟数据分区";

    fuseKylinLogSource = "/var/log";
    fuseKylinLogDest = fuseSource + "/0-麒麟日志";

    if (isPathDir(fuseDest) && isPathDir(fuseSource)) {
        ret = FuseMount(fuseDest, fuseSource, uid, uid, AID_MEDIA_RW, AID_MEDIA_RW, true);
        if (ret != 0) {
            syslog(LOG_ERR, "ContainerUtils: Failed to mount with fuse for container %s.", containerName.c_str());
        }
    }

    if (isPathDir(fuseKylinFileDest) && isPathDir(fuseKylinFileSource)) {
        ret = FuseMount(fuseKylinFileDest, fuseKylinFileSource, AID_MEDIA_RW, AID_MEDIA_RW, uid, uid, false);
        if (ret != 0) {
            syslog(LOG_ERR, "ContainerUtils: Failed to mount kylin file directory with fuse for container %s.", containerName.c_str());
        }
    }

    if (isPathDir(fuseKylinRemovableStorageDest) && isPathDir(fuseKylinRemovableStorageSource)) {
        ret = FuseMount(fuseKylinRemovableStorageDest, fuseKylinRemovableStorageSource, AID_MEDIA_RW, AID_MEDIA_RW, uid, uid, false);
        if (ret != 0) {
            syslog(LOG_ERR, "ContainerUtils: Failed to mount kylin removable storage directory with fuse for container %s.", containerName.c_str());
        }
    }

    if (isPathDir(fuseKylinDataPartitionSource) && !isPathDir(fuseKylinDataPartitionDest)) {
        int err = 0;
        ret = mkdir(fuseKylinDataPartitionDest.c_str(), 0770);
        if (ret < 0) {
            err = errno;
            if (!isPathDir(fuseKylinDataPartitionDest)) {
                syslog(LOG_WARNING, "ContainerUtils: Failed to create media 0 data partition directory for container %s: %s.", containerName.c_str(), strerror(err));
            }
        }
        if (isPathDir(fuseKylinDataPartitionDest) && !isPathMounted(fuseKylinDataPartitionDest)) {
            ret = chmod(fuseKylinDataPartitionDest.c_str(), 0775);
            if (ret < 0) {
                syslog(LOG_WARNING, "ContainerUtils: Failed to change media 0 data partition directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
            }
            ret = chown(fuseKylinDataPartitionDest.c_str(), AID_MEDIA_RW, AID_MEDIA_RW);
            if (ret < 0) {
                syslog(LOG_WARNING, "ContainerUtils: Failed to change media 0 data partition directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
            }
        }
    } else if (!isPathDir(fuseKylinDataPartitionSource) && isPathDir(fuseKylinDataPartitionDest)) {
        rmdir(fuseKylinDataPartitionDest.c_str());
    }
    if (isPathDir(fuseKylinDataPartitionSource) && isPathDir(fuseKylinDataPartitionDest)) {
        ret = FuseMount(fuseKylinDataPartitionDest, fuseKylinDataPartitionSource, AID_MEDIA_RW, AID_MEDIA_RW, uid, uid, false);
        if (ret < 0) {
            syslog(LOG_ERR, "ContainerUtils: Failed to mount kylin data partition directory with fuse for container %s.", containerName.c_str());
        }
    }

    if (isPathDir(fuseKylinLogDest) && isPathDir(fuseKylinLogSource)) {
        ret = FuseMount(fuseKylinLogDest, fuseKylinLogSource, AID_MEDIA_RW, AID_MEDIA_RW, uid, uid, false);
        if (ret != 0) {
            syslog(LOG_ERR, "ContainerUtils: Failed to mount kylin log directory with fuse for container %s.", containerName.c_str());
        }
    }

    return ret;
}

void mountSharedBufferDirectory(const std::string& containerName)
{
    std::string userName;
    std::string sharedBufferDir;
    int32_t uid;

    if (ParseContainerName(containerName, userName, uid)) {
        sharedBufferDir = kmrePath + "/" + containerName + "/shared_buffer";
        std::string options = "mode=0700,uid=" + std::to_string(uid) + ",gid=" + std::to_string(uid);
        UnmountPathIfMounted(sharedBufferDir);
        unsigned long flags = MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME | MS_SILENT;
        MountPath(sharedBufferDir, "tmpfs", "tmpfs", flags, options);
    }
}

void unmountLegacyFixedDirectories(const std::string &userName, const int32_t& uid)
{
    std::string legacyIconsPath;
    std::string legacyScreenshotsPath;
    std::string legacyUser0Path;
    std::string legacyFuseDest;
    std::string legacyFuseKylinFileDest;
    std::string legacyFuseKylinRemovableStorageDest;
    std::string legacyFuseKylinDataPartitionDest;
    std::string legacyFuseKylinLogDest;
    std::string legacySharedBufferPath;

    // For legacy paths
    std::string legacyContainerName = LegacyContainerName(userName, uid);
    legacyIconsPath = legacyPath + "/" + legacyContainerName + "/data/local/icons";
    legacyScreenshotsPath = legacyPath + "/" + legacyContainerName + "/data/local/screenshots";
    legacyUser0Path = legacyPath + "/" + legacyContainerName + "/data/user/0";
    legacyFuseDest = legacyPath + "/data/" + legacyContainerName;
    legacyFuseKylinFileDest = legacyPath + "/" + legacyContainerName + "/data/media/0/0-麒麟文件";
    legacyFuseKylinRemovableStorageDest = legacyPath + "/" + legacyContainerName + "/data/media/0/0-麒麟移动存储设备";
    legacyFuseKylinDataPartitionDest = legacyPath + "/" + legacyContainerName + "/data/media/0/0-麒麟数据分区";
    legacyFuseKylinLogDest = legacyPath + "/" + legacyContainerName + "/data/media/0/0-麒麟日志";
    legacySharedBufferPath = legacyPath + "/" + legacyContainerName + "/shared_buffer";

    UnmountPathIfMounted(legacyIconsPath);
    UnmountPathIfMounted(legacyScreenshotsPath);
    UnmountPathIfMounted(legacyUser0Path);
    unlinkFuseLockFile(legacyFuseDest);
    UnmountPathIfMounted(legacyFuseDest);
    unlinkFuseLockFile(legacyFuseKylinFileDest);
    UnmountPathIfMounted(legacyFuseKylinFileDest);
    unlinkFuseLockFile(legacyFuseKylinRemovableStorageDest);
    UnmountPathIfMounted(legacyFuseKylinRemovableStorageDest);
    unlinkFuseLockFile(legacyFuseKylinDataPartitionDest);
    UnmountPathIfMounted(legacyFuseKylinDataPartitionDest);
    unlinkFuseLockFile(legacyFuseKylinLogDest);
    UnmountPathIfMounted(legacyFuseKylinLogDest);
    UnmountPathIfMounted(legacySharedBufferPath);

}

void unmountFixedDirectories(const std::string& containerName)
{
    std::string iconsPath;
    std::string screenshotsPath;
    std::string user0Path;
    std::string fuseDest;
    std::string fuseKylinFileDest;
    std::string fuseKylinRemovableStorageDest;
    std::string fuseKylinDataPartitionDest;
    std::string fuseKylinLogDest;
    std::string sharedBufferPath;

    std::string userName;
    int32_t uid;

    iconsPath = kmrePath + "/" + containerName + "/data/local/icons";
    screenshotsPath = kmrePath + "/" + containerName + "/data/local/screenshots";
    user0Path = kmrePath + "/" + containerName + "/data/user/0";
    fuseDest = kmrePath + "/data/" + containerName;
    fuseKylinFileDest = kmrePath + "/" + containerName + "/data/media/0/0-麒麟文件";
    fuseKylinRemovableStorageDest = kmrePath + "/" + containerName + "/data/media/0/0-麒麟移动存储设备";
    fuseKylinDataPartitionDest = kmrePath + "/" + containerName + "/data/media/0/0-麒麟数据分区";
    fuseKylinLogDest = kmrePath + "/" + containerName + "/data/media/0/0-麒麟日志";
    sharedBufferPath = kmrePath + "/" + containerName + "/shared_buffer";

    if (ParseContainerName(containerName, userName, uid)) {
        unmountLegacyFixedDirectories(userName, uid);
    }

    UnmountPathIfMounted(iconsPath);
    UnmountPathIfMounted(screenshotsPath);
    UnmountPathIfMounted(user0Path);
    unlinkFuseLockFile(fuseDest);
    UnmountPathIfMounted(fuseDest);
    unlinkFuseLockFile(fuseKylinFileDest);
    UnmountPathIfMounted(fuseKylinFileDest);
    unlinkFuseLockFile(fuseKylinRemovableStorageDest);
    UnmountPathIfMounted(fuseKylinRemovableStorageDest);
    unlinkFuseLockFile(fuseKylinDataPartitionDest);
    UnmountPathIfMounted(fuseKylinDataPartitionDest);
    unlinkFuseLockFile(fuseKylinLogDest);
    UnmountPathIfMounted(fuseKylinLogDest);
    UnmountPathIfMounted(sharedBufferPath);
}

static unsigned int dockerGetVersion(const std::string& format)
{
    std::vector<std::string> cmd;
    std::vector<std::string> output;
    std::string value;
    int ret = 0;
    unsigned int _major = 0;
    unsigned int _minor = 0;
    unsigned int _sub = 0;

    cmd.push_back(DOCKER_PATH);
    cmd.push_back("version");
    cmd.push_back("--format");
    cmd.push_back(format);

    ret = ForkExecvp(cmd, output);
    if (ret < 0) {
        return 0;
    }

    if (output.size() > 0) {
        value = output[0];
    }

    ret = sscanf(value.c_str(), "%u.%u.%u", &_major, &_minor, &_sub);
    if (ret < 2) {
        return 0;
    }

    return DOCKER_VERSION(_major, _minor, _sub);
}

unsigned int dockerClientVersion()
{
    return dockerGetVersion("'{{.Client.Version}}'");
}

unsigned int dockerServerVersion()
{
    return dockerGetVersion("'{{.Server.Version}}'");
}

} // namespace container
} // namespace kmre
