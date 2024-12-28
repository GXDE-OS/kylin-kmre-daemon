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

#include "kmre-server.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <string.h>
#include <errno.h>

#include <sys/syslog.h>

#include "utils.h"

#include <chrono>

namespace kmre {

std::string dbusCallSender;

static const char *unsupported_kernel[] = {
    "4.4.58",
};

static int kernel_check()
{
    struct utsname un;
    int n = 0;
    int i = 0;

    n = sizeof(unsupported_kernel) / sizeof(char*);

    if (uname(&un) != 0) {
        return -1;
    }

    for (i = 0; i < n; ++i) {
        if (strncmp(un.release, unsupported_kernel[i], strlen(unsupported_kernel[i])) == 0) {
            return -1;
        }
    }

    return 0;
}

static const std::string KMRE_DATA_PATH = "/usr/share/kmre/kmre-data.tar";
static const std::string KMRE_DATA_CHECK_FILE_NAME = ".kmre-data-check";
static const std::string kmrePath = "/var/lib/kmre";
static const std::string fusePrefixPath = kmrePath + "/data";

static const std::string KMRE_STARTAPP = "/usr/bin/startapp";
static const std::string KMRE_MANAGER = "/usr/bin/kylin-kmre-manager";
static const std::string KMRE_WINDOW = "/usr/bin/kylin-kmre-window";
static const std::string KMRE_SETTINGS = "/usr/bin/kylin-kmre-settings";
static const std::string SOFTWARE_CENTER = "/usr/bin/kylin-software-center";

KmreServer::KmreServer(DBus::Connection &connection)
    : DBus::ObjectAdaptor(connection, KMRE_SERVER_PATH),
      mContainerManager(nullptr),
      mKernelSupported(false),
      mDBusDaemonProxy(connection),
      mSystemdManagerProxy(connection),
      mKydroidDaemonProxy(connection)
{
    mContainerManager = new container::ContainerManager(this);

    syslog(LOG_DEBUG, "KmreServer: Check kernel release version.");
    if (kernel_check() < 0) {
        mKernelSupported = false;
        syslog(LOG_CRIT, "KmreServer: Unsupported kernel.");
    } else {
        mKernelSupported = true;
    }

    if (serviceExists("haveged.service")) {
        if (!isServiceRunning("haveged.service")) {
            startSystemdService("haveged.service");
        }
    }
}

KmreServer::~KmreServer()
{
    if (mContainerManager) {
        delete mContainerManager;
    }
}

void KmreServer::prepareData(const std::string& containerPath)
{
    std::vector<std::string> cmd;
    std::string checkFilePath;
    int ret = 0;

    if (!isPathRegularFile(KMRE_DATA_PATH)) {
        return;
    }

    if (!isPathReadable(KMRE_DATA_PATH)) {
        syslog(LOG_WARNING, "KmreServer: Data file exists, but it is not readable.");
        return;
    }

    // tar -xp --keep-newer-files -f /usr/share/kmre/kmre-data.tar -C containerPath
    cmd.push_back("/bin/tar");
    cmd.push_back("-xp");
    cmd.push_back("--keep-newer-files");
    cmd.push_back("-f");
    cmd.push_back(KMRE_DATA_PATH);
    cmd.push_back("-C");
    cmd.push_back(containerPath + "/");

    syslog(LOG_DEBUG, "KmreServer: Prepare default data for container %s", basename((const char*)containerPath.c_str()));
    ret = ForkExecvp(cmd);

    checkFilePath = containerPath + "/data/" + KMRE_DATA_CHECK_FILE_NAME;
    if (ret == 0) {
        CreateFile(checkFilePath, 0640);
    } else {
        syslog(LOG_WARNING, "KmreServer: Failed to prepare data for container %s.", basename((const char*)containerPath.c_str()));
    }
}

void KmreServer::checkAndLogDBusSender(const std::string &method)
{
    (void) method;
#ifdef DEBUG_DBUS_METHOD
    uint32_t pid;
    uint32_t uid;
    std::string comm;

    mDBusDaemonProxy.GetSenderPid(dbusCallSender, pid);
    mDBusDaemonProxy.GetSenderUid(dbusCallSender, uid);
    mDBusDaemonProxy.GetSenderComm(dbusCallSender, comm);

    syslog(LOG_DEBUG, "Method %s is called by process pid:%u uid:%u comm:%s", method.c_str(), pid, uid, comm.c_str());
#endif
}

#define MAX_ENVIRON_SIZE (1024 * 1024)

bool KmreServer::checkEnviron(int pid)
{
    if (pid <= 0) {
        syslog(LOG_ERR, "[%s] Invaliable process '%d'.", __func__, pid);
        return false;
    }

    char envFilePath[128] = {0};
    snprintf(envFilePath, sizeof(envFilePath) - 1, "/proc/%d/environ", pid);

    FILE* fp = fopen(envFilePath, "rb");
    if (!fp) {
        syslog(LOG_ERR, "[%s] Can't open env file of process '%d'.", __func__, pid);
        return false;
    }

    char* buf = (char*)malloc(MAX_ENVIRON_SIZE);
    if (buf == NULL) {
        printf("Malloc env buf failed!\n");
        syslog(LOG_ERR, "[%s] Malloc buffer for environ failed!", __func__);
	    fclose(fp);
        return false;
    }

    size_t length = fread(buf, 1, MAX_ENVIRON_SIZE - 1, fp);
    buf[length] = '\0';
    fclose(fp);
    //syslog(LOG_DEBUG, "[%s] Read environ file '%ld' bytes.", __func__, length);

    bool envPassed = true;
    size_t counter = 0;
    char *pStr = buf;

    while (counter < length) {
        size_t len = strlen(pStr);
        if (len > 0) {
            //syslog(LOG_DEBUG, "[%s] Env: '%s'", __func__, pStr);
            /*if ((strncmp(pStr, "LD_PRELOAD=", strlen("LD_PRELOAD=")) == 0) ||
                (strncmp(pStr, "LD_LIBRARY_PATH=", strlen("LD_LIBRARY_PATH=")) == 0) ||
                (strncmp(pStr, "LD_AUDIT=", strlen("LD_AUDIT=")) == 0)) {

                syslog(LOG_ERR, "[%s] Invalid environ are set in process %d.", __func__, pid);
                envPassed = false;
                break;
            }*/
        }

        pStr += len + 1;
        counter += len + 1;
    }

    free(buf);
    return envPassed;
}

bool KmreServer::checkWhiteList(int pid, const std::vector<std::string>& whiteList) 
{
    if (pid <= 0) {
        syslog(LOG_ERR, "[%s] Invaliable process '%d'.", __func__, pid);
        return false;
    }

    char exeFilePath[128] = {0};
    snprintf(exeFilePath, sizeof(exeFilePath) - 1, "/proc/%d/exe", pid);

    char resolvedPath[PATH_MAX];
    char* result = realpath(exeFilePath, resolvedPath);
    
    if (result == NULL) {
        syslog(LOG_ERR, "[%s] Can't get realpath of process '%d'.", __func__, pid);
        return false;
    } 
    else {
        //syslog(LOG_DEBUG, "[%s] The realpath of process '%d' is '%s'.", __func__, pid, resolvedPath);
        for (const auto& whitePath : whiteList) {
            if (resolvedPath == whitePath) {
                return true;
            }
        }

        // just for debug, must be removed at release version
        // if (strcmp(resolvedPath, "/usr/bin/d-feet") == 0) {
        //     return true;
        // }
        // if (strncmp(resolvedPath, "/usr/bin/python", strlen("/usr/bin/python")) == 0) {
        //     std::string comm;
        //     mDBusDaemonProxy.GetSenderComm(dbusCallSender, comm);
        //     //syslog(LOG_DEBUG, "[%s] Sender comm: '%s'.", __func__, comm.c_str());
        //     if (strncmp(comm.c_str(), "d-feet", strlen("d-feet")) == 0) {
        //         return true;
        //     }
        // }
    }

    syslog(LOG_WARNING, "[%s] The process '%d' (%s) is not in white list.", __func__, pid, resolvedPath);
    return false;
}

void KmreServer::checkCallerAllowed(const std::string &method, const std::vector<std::string>& whiteList) 
{
    uint32_t pid;
    mDBusDaemonProxy.GetSenderPid(dbusCallSender, pid);

    if(!checkEnviron(pid)){
        throw DBus::ErrorLimitsExceeded("dbus method control,env forbidden");// don't change the error message !
    }
    
    /*if (!checkWhiteList(pid, whiteList)) {
        throw DBus::ErrorAccessDenied("dbus method control,operation not permitted");// don't change the error message !
    }*/
}

bool KmreServer::checkServices()
{
    if (!checkServiceStatusAndStart("containerd.service")) {
        return false;
    }

    if (!checkServiceStatusAndStart("docker.socket")) {
        return false;
    }

    if (!checkServiceStatusAndStart("docker.service")) {
        return false;
    }

    return true;
}

bool KmreServer::checkServiceStatusAndStart(const std::string &serviceName)
{
    int count = 0;

    if (!isServiceRunning(serviceName)) {
        if (!serviceExists(serviceName)) {
            syslog(LOG_WARNING, "KmreServer: Service %s doesn't exist.", serviceName.c_str());
            ServiceNotFound(serviceName);
            return false;
        }
    } else {
        return true;
    }

    auto start = std::chrono::system_clock::now();
    do {
        if (count++ == 10) {
            break;
        }
        auto end = std::chrono::system_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        //fprintf(stderr, "duration %ld\n", duration.count());
        if (duration.count() > 6000) {
            break;
        }
#ifdef FORCE_UNMASK_SYSTEMD_SERVICE
        unmaskSystemdService(serviceName);
#endif
        startSystemdService(serviceName);
        usleep(500 * 1000);
    } while (!isServiceRunning(serviceName));

    if (!isServiceRunning(serviceName)) {
        syslog(LOG_WARNING, "KmreServer: Failed to start service %s.", serviceName.c_str());
        ServiceStartFailed(serviceName);
    } else {
        return true;
    }

    return false;
}


bool KmreServer::serviceExists(const std::string &serviceName)
{
    DBus::Path path;
    std::string loadState;
    std::string activeStatus;
    std::string subStatus;
    bool isActive = false;

    if (!mSystemdManagerProxy.GetUnitInformation(serviceName, path, isActive, loadState, activeStatus, subStatus)) {
        if (!mSystemdManagerProxy.GetUnitInformationLegacy(serviceName, path, isActive, loadState, activeStatus, subStatus)) {
            return false;
        }
    }

    if (loadState == "loaded") {
        return true;
    }

    return false;
}

bool KmreServer::isServiceRunning(const std::string &serviceName)
{
    DBus::Path path;
    std::string loadState;
    std::string activeStatus;
    std::string subStatus;
    bool isActive = false;

    if (!mSystemdManagerProxy.GetUnitInformation(serviceName, path, isActive, loadState, activeStatus, subStatus)) {
        if (!mSystemdManagerProxy.GetUnitInformationLegacy(serviceName, path, isActive, loadState, activeStatus, subStatus)) {
            return false;
        }
    }

    return isActive;
}

bool KmreServer::stopKydroidContainer(const std::string &userName, int32_t &uid)
{
    return mKydroidDaemonProxy.StopContainer(userName, uid);
}

int32_t KmreServer::_Prepare(const std::string &userName, const int32_t &uid)
{
    std::string legacyContainer;
    std::string container;
    std::string mntPath;
    std::string socketsPath;
    std::string checkDataPath;
    std::string dataPath;
    std::string localPath;
    std::string configPath;
    std::string preinstallPath;
    std::string fuseDest;
    std::string mediaPath;
    std::string media0Path;
    std::string kylinFilePath;
    std::string kylinRemovableStoragePath;
    std::string kylinLogPath;
    std::string containerName;
    std::string appPath;
    std::string sharedBufferPath;
    std::string shareDataPath;
    struct stat sb;
    int ret;
    int err;

    legacyContainer = LegacyContainerPath(userName, uid);
    container = ContainerPath(userName, uid);
    containerName = ContainerName(userName, uid);
    mntPath = container + "/mnt";
    socketsPath = container + "/sockets";
    checkDataPath = container + "/data/" + KMRE_DATA_CHECK_FILE_NAME;
    dataPath = container + "/data";
    localPath = dataPath + "/local";
    configPath = localPath + "/config";
    preinstallPath = localPath + "/preinstall";
    mediaPath = container + "/data/media";
    media0Path = mediaPath + "/0";
    kylinFilePath = media0Path + "/0-麒麟文件";
    kylinRemovableStoragePath = media0Path + "/0-麒麟移动存储设备";
    kylinLogPath = media0Path + "/0-麒麟日志";
    appPath = dataPath + "/app";
    sharedBufferPath = container + "/shared_buffer";
    shareDataPath = media0Path + "/share_data";

    syslog(LOG_DEBUG, "KmreServer: Prepare directories for kmre.");
    // make kmre directory
    ret = mkdir(kmrePath.c_str(), 0755);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(kmrePath)) {
            syslog(LOG_CRIT, "KmreServer: Failed to create directory for kmre: %s.", strerror(err));
        }
    }

    // make container directory or make a symbol link to legacy container path
    if (isPathDir(legacyContainer)) {
        symlink(legacyContainer.c_str(), container.c_str());
    } else {
        if (isPathSymlink(container.c_str(), false)) {
            unlink(container.c_str());
        }

        ret = mkdir(container.c_str(), 0751);
        if (ret < 0) {
            err = errno;
            if (!isPathDir(container)) {
                syslog(LOG_CRIT, "KmreServer: Failed to create directory for container %s: %s.", containerName.c_str(), strerror(err));
            }
        }
        ret = chmod(container.c_str(), 0751);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
        }
        ret = chown(container.c_str(), uid, uid);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
        }
    }

    // make container mnt directory
    ret = mkdir(mntPath.c_str(), 0755);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(mntPath)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create mnt directory for container %s: %s.", containerName.c_str(), strerror(err));
        }
    }
    ret = chown(mntPath.c_str(), 0, 1000);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change mnt directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
    }

    // make sockets path
    ret = mkdir(socketsPath.c_str(), 0777);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(socketsPath)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create sockets directory for container %s: %s.", containerName.c_str(), strerror(err));
        }
    }
    ret = chmod(socketsPath.c_str(), 0777);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change sockets directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
    }

    // check android data and prepare data
    if (stat(checkDataPath.c_str(), &sb) != 0) {
        prepareData(container);
    }

    // prepare data path
    ret = mkdir(dataPath.c_str(), 0771);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(dataPath)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create data directory for container %s: %s.", containerName.c_str(), strerror(err));
        }
    }
    ret = chmod(dataPath.c_str(), 0771);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change data directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
    }
    ret = chown(dataPath.c_str(), 1000, 1000);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change data directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
    }

    // prepare app path
    ret = mkdir(appPath.c_str(), 0771);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(appPath)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create app directory for container %s: %s.", containerName.c_str(), strerror(errno));
        }
    }
    ret = chmod(appPath.c_str(), 0771);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change app directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
    }
    ret = chown(appPath.c_str(), 1000, 1000);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change app directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
    }

    // prepare local path
    ret = mkdir(localPath.c_str(), 0755);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(localPath)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create local directory for container %s: %s.", containerName.c_str(), strerror(err));
        }
    }
    ret = chmod(localPath.c_str(), 0755);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change local directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
    }

    ret = mkdir(configPath.c_str(), 0755);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(configPath)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create config directory for container %s: %s.", containerName.c_str(), strerror(err));
        }
    }
    ret = chmod(configPath.c_str(), 0755);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change config directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
    }
    ret = chown(configPath.c_str(), uid, uid);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change config directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
    }

    ret = mkdir(preinstallPath.c_str(), 0777);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(preinstallPath)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create preinstall directory for container %s: %s.", containerName.c_str(), strerror(err));
        }
    }
    ret = chmod(preinstallPath.c_str(), 0777);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change preinstall directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
    }
    ret = chown(preinstallPath.c_str(), uid, uid);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change preinstall directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
    }

    // fuse mount destination
    fuseDest = fusePrefixPath + "/" + containerName;
    ret = mkdir(fusePrefixPath.c_str(), 0755);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(fusePrefixPath)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create fuse directory: %s.", strerror(err));
        }
    }
    ret = chmod(fusePrefixPath.c_str(), 0755);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change fuse directory mode: %s.", strerror(errno));
    }

    if (!isPathDir(fuseDest)) {
        ret = mkdir(fuseDest.c_str(), 0750);
        if (ret < 0) {
            err = errno;
            if (!isPathDir(fuseDest)) {
                syslog(LOG_WARNING, "KmreServer: Failed to create fuse directory for container %s: %s.", containerName.c_str(), strerror(err));
            }
        }
    }
    if (isPathDir(fuseDest) && !isPathMounted(fuseDest)) {
        ret = chmod(fuseDest.c_str(), 0750);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change fuse directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
        }
        ret = chown(fuseDest.c_str(), uid, uid);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change fuse directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
        }
    }

    // fuse mount source
    ret = mkdir(mediaPath.c_str(), 0770);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(mediaPath)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create media directory for container %s: %s.", containerName.c_str(), strerror(err));
        }
    }
    ret = chmod(mediaPath.c_str(), 0770);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change media directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
    }
    ret = chown(mediaPath.c_str(), AID_MEDIA_RW, AID_MEDIA_RW);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change media directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
    }
    ret = mkdir(media0Path.c_str(), 0770);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(media0Path)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create media 0 directory for container %s: %s.", containerName.c_str(), strerror(err));
        }
    }
    ret = chmod(media0Path.c_str(), 0770);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change media 0 directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
    }
    ret = chown(media0Path.c_str(), AID_MEDIA_RW, AID_MEDIA_RW);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change media 0 directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
    }

    if (!isPathDir(kylinFilePath)) {
        ret = mkdir(kylinFilePath.c_str(), 0770);
        if (ret < 0) {
            err = errno;
            if (!isPathDir(kylinFilePath)) {
                syslog(LOG_WARNING, "KmreServer: Failed to create media 0 kylin file directory for container %s: %s.", containerName.c_str(), strerror(err));
            }
        }
    }
    if (isPathDir(kylinFilePath) && !isPathMounted(kylinFilePath)) {
        ret = chmod(kylinFilePath.c_str(), 0775);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change media 0 kylin file directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
        }
        ret = chown(kylinFilePath.c_str(), AID_MEDIA_RW, AID_MEDIA_RW);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change media 0 kylin file directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
        }
    }

    if (!isPathDir(kylinRemovableStoragePath)) {
        ret = mkdir(kylinRemovableStoragePath.c_str(), 0770);
        if (ret < 0) {
            err = errno;
            if (!isPathDir(kylinRemovableStoragePath)) {
                syslog(LOG_WARNING, "KmreServer: Failed to create media 0 removable storage directory for container %s: %s.", containerName.c_str(), strerror(err));
            }
        }
    }
    if (isPathDir(kylinRemovableStoragePath) && !isPathMounted(kylinRemovableStoragePath)) {
        ret = chmod(kylinRemovableStoragePath.c_str(), 0775);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change media 0 removable storage directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
        }
        ret = chown(kylinRemovableStoragePath.c_str(), AID_MEDIA_RW, AID_MEDIA_RW);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change media 0 removable storage directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
        }
    }

    if (!isPathDir(kylinLogPath)) {
        ret = mkdir(kylinLogPath.c_str(), 0770);
        if (ret < 0) {
            err = errno;
            if (!isPathDir(kylinLogPath)) {
                syslog(LOG_WARNING, "KmreServer: Failed to create media 0 log directory for container %s: %s.", containerName.c_str(), strerror(err));
            }
        }
    }
    if (isPathDir(kylinLogPath) && !isPathMounted(kylinLogPath)) {
        ret = chmod(kylinLogPath.c_str(), 0775);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change media 0 log directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
        }
        ret = chown(kylinLogPath.c_str(), AID_MEDIA_RW, AID_MEDIA_RW);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change media 0 log directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
        }
    }

    if (!isPathDir(sharedBufferPath)) {
        ret = mkdir(sharedBufferPath.c_str(), 0700);
        if (ret < 0) {
            err = errno;
            if (!isPathDir(sharedBufferPath)) {
                syslog(LOG_WARNING, "KmreServer: Failed to create shared buffer directory for container %s: %s.", containerName.c_str(), strerror(err));
            }
        }
    }
    if (isPathDir(sharedBufferPath) && !isPathMounted(sharedBufferPath)) {
        ret = chmod(sharedBufferPath.c_str(), 0700);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change shared buffer directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
        }
        ret = chown(sharedBufferPath.c_str(), uid, uid);
        if (ret < 0) {
            syslog(LOG_WARNING, "KmreServer: Failed to change shared buffer owner for container %s: %s.", containerName.c_str(), strerror(errno));
        }
    }

    ret = mkdir(shareDataPath.c_str(), 0775);
    if (ret < 0) {
        err = errno;
        if (!isPathDir(shareDataPath)) {
            syslog(LOG_WARNING, "KmreServer: Failed to create media 0 share data directory for container %s: %s.", containerName.c_str(), strerror(err));
        }
    }
    ret = chmod(shareDataPath.c_str(), 0775);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change media 0 share data directory mode for container %s: %s.", containerName.c_str(), strerror(errno));
    }
    ret = chown(shareDataPath.c_str(), AID_MEDIA_RW, AID_MEDIA_RW);
    if (ret < 0) {
        syslog(LOG_WARNING, "KmreServer: Failed to change media 0 share data directory owner for container %s: %s.", containerName.c_str(), strerror(errno));
    }

    return 0;
}

int32_t KmreServer::Prepare(const std::string &userName, const int32_t &uid)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP, KMRE_WINDOW, KMRE_MANAGER});

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return -1;
    }

    return _Prepare(_userName, uid);
}

int32_t KmreServer::StartContainer(const std::string &userName, const int32_t &uid, const int32_t &width, const int32_t &height)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP});

    if (!checkServices()) {
        return -1;
    }

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return -1;
    }

    _Prepare(_userName, uid);
/*
    if (!mKernelSupported) {
        fprintf(stderr, "Unsupported kernel.\n");
        syslog(LOG_DEBUG, "KmreServer: Unsupported kernel.");
        return -1;
    }
*/

    if (!mContainerManager->IsImageReady()) {
        return -1;
    }

    syslog(LOG_DEBUG, "KmreServer: Start container %s.", ContainerName(_userName, uid).c_str());
    return mContainerManager->StartContainer(_userName, uid, width, height);
}

int32_t KmreServer::StartContainerSilently(const std::string &userName, const int32_t &uid)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP});

    if (!checkServices()) {
        return -1;
    }

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return -1;
    }

    _Prepare(_userName, uid);

    if (!mContainerManager->IsImageReady()) {
        return -1;
    }

    syslog(LOG_DEBUG, "KmreServer: Start container %s silently.", ContainerName(_userName, uid).c_str());

    return mContainerManager->StartContainerSilently(_userName, uid);
}

int32_t KmreServer::ChangeContainerRuntimeStatus(const std::string &userName, const int32_t &uid)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP});

    if (!checkServices()) {
        return -1;
    }

    if (!mContainerManager->IsImageReady()) {
        return -1;
    }

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return -1;
    }

    syslog(LOG_DEBUG, "KmreServer: Change container %s runtime status.", ContainerName(_userName, uid).c_str());
    return mContainerManager->ChangeContainerRuntimeStatus(_userName, uid);
}

int32_t KmreServer::StopContainer(const std::string &userName, const int32_t &uid)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP, KMRE_SETTINGS, KMRE_WINDOW, KMRE_MANAGER});

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return -1;
    }

    syslog(LOG_DEBUG, "KmreServer: Stop container %s.", ContainerName(_userName, uid).c_str());
    return mContainerManager->StopContainer(_userName, uid);
}

void KmreServer::SetFocusOnContainer(const std::string &userName, const int32_t &uid, const int32_t &onFocus)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {});

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return;
    }

    mContainerManager->SetFocusOnContainer(_userName, uid, onFocus);
}

void KmreServer::SetPropOfContainer(const std::string &userName, const int32_t &uid, const std::string &prop, const std::string &value)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP, KMRE_SETTINGS, KMRE_WINDOW, KMRE_MANAGER});

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return;
    }

    //syslog(LOG_DEBUG, "Method %s: prop %s value %s", __FUNCTION__, prop.c_str(), value.c_str());
    mContainerManager->SetPropOfContainer(_userName, uid, prop, value);
}

std::string KmreServer::GetPropOfContainer(const std::string &userName, const int32_t &uid, const std::string &prop)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP, KMRE_SETTINGS, KMRE_WINDOW, KMRE_MANAGER, SOFTWARE_CENTER});

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return "";
    }

    //syslog(LOG_DEBUG, "Method %s: prop %s", __FUNCTION__, prop.c_str());
    return mContainerManager->GetPropOfContainer(_userName, uid, prop);
}

void KmreServer::SetDefaultPropOfContainer(const std::string &userName, const int32_t &uid, const std::string &prop, const std::string &value)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP, KMRE_SETTINGS, KMRE_WINDOW, KMRE_MANAGER});

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return;
    }

    //syslog(LOG_DEBUG, "Method %s: prop %s value %s", __FUNCTION__, prop.c_str(), value.c_str());
    mContainerManager->SetDefaultPropOfContainer(_userName, uid, prop, value);
}

std::string KmreServer::GetDefaultPropOfContainer(const std::string &userName, const int32_t &uid, const std::string &prop)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP, KMRE_SETTINGS, KMRE_WINDOW, KMRE_MANAGER, SOFTWARE_CENTER});

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return "";
    }

    //syslog(LOG_DEBUG, "Method %s: prop %s", __FUNCTION__, prop.c_str());
    return mContainerManager->GetDefaultPropOfContainer(_userName, uid, prop);
}

std::string KmreServer::GetContainerNetworkInformation(const std::string &userName, const int32_t &uid)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_SETTINGS});

    std::string _userName = PrepareUserName(userName);

    if (!isUserNameValid(_userName)) {
        syslog(LOG_WARNING, "_userName is invalid: %s", _userName.c_str());
        return "";
    }

    //syslog(LOG_DEBUG, "Method %s", __FUNCTION__);
    return mContainerManager->GetContainerNetworkInformation(_userName, uid);
}

void KmreServer::SetGlobalEnvironmentVariable(const std::string &key, const std::string &value)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_SETTINGS, KMRE_MANAGER});

    //syslog(LOG_DEBUG, "Method %s: key %s value %s", __FUNCTION__, key.c_str(), value.c_str());
    mContainerManager->SetGlobalEnvironmentVariable(key, value);
}

void KmreServer::LoadImage()
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP});

    if (!checkServices()) {
        return;
    }

    syslog(LOG_DEBUG, "KmreServer: Load container image.");
    return mContainerManager->LoadImage();
}

uint32_t KmreServer::IsImageReady()
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_STARTAPP});

    if (!checkServices()) {
        return 0;
    }

    bool ready = mContainerManager->IsImageReady();

    if (ready) {
        return 1;
    }

    return 0;
}

std::map<std::string, std::string> KmreServer::GetAllContainersAndImages(const std::string &userName, const int32_t &uid)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_SETTINGS});

    std::map<std::string, std::string> result;
    if (!checkServices()) {
        return result;
    }

    result["images"] = mContainerManager->GetAllImages();
    result["containers"] = mContainerManager->GetAllContainers();
    result["current"] = mContainerManager->GetCurrentContainerAndImage();

    return result;
}

bool KmreServer::SwitchImage(const std::string &repo, const std::string &tag)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_SETTINGS});

    bool result = false;

    return result;
}

bool KmreServer::RemoveOneContainer(const std::string &container)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_SETTINGS});

    if (!checkServices()) {
        return false;
    }

    bool result = false;

    return result;
}

bool KmreServer::RemoveOneImage(const std::string &container, const std::string &image)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_SETTINGS});

    if (!checkServices()) {
        return false;
    }

    bool result = false;
    result = mContainerManager->RemoveOneImage(container, image);

    return result;
}

void KmreServer::ComponentsUpgrade(const std::string &args)
{
    checkAndLogDBusSender(__FUNCTION__);
    checkCallerAllowed(__FUNCTION__, {KMRE_SETTINGS});

    mContainerManager->ComponentsUpgrade(args);
}

} // namespace kmre
