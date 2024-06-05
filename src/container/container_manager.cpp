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

#include "container_manager.h"
#include "container.h"

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <sstream>
#include <algorithm>
#include <functional>
#include <sys/syslog.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>

#include "kmre-server.h"
#include "property-map.h"
#include "rfkillprocessor.h"
#include "container_utils.h"

#define DISABLE_OTHER_ANDROID_ENVIRONMENT_CHECK 1

#define KMRE_USE_MEMFD_PROP "sys.use_memfd"

static bool fbMatched(const char* fbName)
{
    FILE* fp = NULL;
    char line[256] = {0};
    bool matched = false;

    fp = fopen("/proc/fb", "r");
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strcasestr(line, fbName)) {
            matched = true;
            break;
        }
    }

    fclose(fp);

    return matched;
}

namespace kmre {
namespace container {

static const std::string dockerPath = "/usr/bin/docker";
static const std::string kmrePath = "/var/lib/kmre";
static const std::string legacyPath = "/var/lib/kydroid";
static const std::string formatInspectImage = "'{{.Config.Image}}'";
static const std::string formatInspectRunning = "'{{.State.Running}}'";
static const std::string DEFAULT_IMAGE_REPO = "kmre2";
static const std::string CONTAINER_IMAGE_PATH = "/usr/share/kmre/kmre-container-image.tar";
static const std::string kmreGlobalEnvPath = "/var/lib/kmre/kmre-global-env";
static const std::string KYLIN_KMRE_DAEMON_PATH = "/usr/bin/kylin-kmre-daemon";

static int defaultNumberOfCpus = 4;

#ifndef DISABLE_OTHER_ANDROID_ENVIRONMENT_CHECK
static bool noOtherAndroidEnvironment()
{
    if (isKernelModuleLoaded("asg_xdroid") ||
        isKernelModuleLoaded("ashmem_xdroid") ||
        isKernelModuleLoaded("binder_xdroid") ||
        isKernelModuleLoaded("binder_linux")) {
        return false;
    }

    if (isPathCharDevice("/dev/asg_xdroid") ||
        isPathCharDevice("/dev/ashmem_xdroid") ||
        isPathCharDevice("/dev/binder_xdroid")) {
        return false;
    }

    return true;
}
#endif



ContainerManager::ContainerManager(KmreServer *server)
    : mServer(server),
      mThreadLoadImage(nullptr),
      mImageLoading(false),
      mStopLoading(false),
      mRfkillProcessor(nullptr)
{
    syslog(LOG_DEBUG, "ContainerManager: Loading image information.");
    mImageRepo = ImageRepo();
    mImageTag = ImageTag();
    mImageVersion = ImageVersion();

    // ensure that directory /var/lib/kmre exists
    mkdir(kmrePath.c_str(), 0755);
    chmod(kmrePath.c_str(), 0755);

    mGlobalEnv.setPropertyFilePath(kmreGlobalEnvPath);
    if (fbMatched("amdgpudrmfb")) {
        mGlobalEnv.addProperty("AMD_DEBUG", "nodma");
        mGlobalEnv.addProperty("R600_DEBUG", "nodma");
    }

    mGlobalEnv.addProperty("QT_QPA_PLATFORMTHEME", "ukui");

    mGlobalEnv.saveProperties(0644);

    // Now we really want to use a certain image from image configuration.
    /*
    if (mImageRepo.empty() || mImageRepo.length() == 0) {
        syslog(LOG_WARNING, "ContainerManager: Failed to load image repo name, uses the default one.");
        mImageRepo = DEFAULT_IMAGE_REPO;

        auto imageInfos = listImageInfo();
        if (imageInfos.size() > 0) {
            mImageRepo = imageInfos[0].GetRepo();
            mImageTag = imageInfos[0].GetTag();
        }

        if (!mImageRepo.empty() && mImageRepo.length() != 0 && !mImageTag.empty() && mImageTag.length() != 0) {
            mImageVersion = mImageRepo + ":" + mImageTag;
        }
    }
    */

    syslog(LOG_INFO, "ContainerManager: Image information: imageRepo=%s imageTag=%s image=%s.", mImageRepo.c_str(), mImageTag.c_str(), mImageVersion.c_str());

    syslog(LOG_DEBUG, "ContainerManager: Initialize containers.");
    initializeContainers();
    mThreadLoadImage = new std::thread(std::bind(&ContainerManager::loadImageProcessor, this));

    mRfkillProcessor = new RfkillProcessor();
    if (mRfkillProcessor == nullptr) {
        syslog(LOG_ERR, "ContainerManager: Failed to create RfkillProcessor.");
    }

    if (mRfkillProcessor) {
        if (mRfkillProcessor->initialize() < 0) {
            syslog(LOG_ERR, "ContainerManager: Failed to initialize RfkillProcessor.");
        } else {
            mRfkillProcessor->start();
        }
    }
}

ContainerManager::~ContainerManager()
{
    if (mRfkillProcessor) {
        mRfkillProcessor->stop();
        mRfkillProcessor->closeDown();
        mRfkillProcessor->wait();
        delete mRfkillProcessor;
        mRfkillProcessor = nullptr;
    }

    auto iter = mPropertiesMaps.begin();
    while (iter != mPropertiesMaps.end()) {
        if (iter->second) {
            delete iter->second;
        }
        iter = mPropertiesMaps.erase(iter);
    }
    mPropertiesMaps.clear();

    if (mThreadLoadImage) {
        mStopLoading = true;
        if (mThreadLoadImage->joinable()) {
            mThreadLoadImage->join();
        }

        delete mThreadLoadImage;
    }
}

const std::string& ContainerManager::GetImageVersion()
{
    if (mImageVersion.length() <= 0) {
        mImageVersion = ImageVersion();
    }

    return mImageVersion;
}

const std::string& ContainerManager::GetImageRepo()
{
    if (mImageRepo.length() <= 0) {
        mImageRepo = ImageRepo();
    }

    return mImageRepo;
}

const std::string& ContainerManager::GetImageTag()
{
    if (mImageTag.length() <= 0) {
        mImageTag = ImageTag();
    }

    return mImageTag;
}

bool ContainerManager::isImageConfigurationReady()
{
    if (isStringValid(GetImageRepo()) && isStringValid(GetImageTag()) && isStringValid(GetImageVersion())) {
        return true;
    }

    return false;
}

std::shared_ptr<Container> ContainerManager::findContainer(const std::string &containerName)
{
    for (std::shared_ptr<Container> c : mContainers) {
        if (c->getContainerName() == containerName) {
            return c;
        }
    }

    return nullptr;
}

bool ContainerManager::insertContainer(const std::string &containerName, const std::string& image, bool privileged)
{
    bool result = true;
    std::string userName;
    int32_t uid;

    auto c = findContainer(containerName);
    if (c)
        return true;

    result = ParseContainerName(containerName, userName, uid);
    if (!result)
        return result;

    mContainers.push_back(std::make_shared<Container>(Container(userName, uid, image, *this, privileged)));

    return result;
}

void ContainerManager::initializeContainers()
{
    std::string image;
    auto infos = ListContainerInfo();

    for (auto info : infos) {
        image = info.imageRepo + ":" + info.imageTag;
        insertContainer(info.name, image);
    }

}

int32_t ContainerManager::stopContainer(const std::string &containerName, bool shouldEmit)
{
    std::vector<std::string> cmd;
    int32_t ret;

    auto c = findContainer(containerName);
    if (c) {
        ret = c->stop();
    } else {
        // docker stop containerName -t 1
        cmd.push_back(dockerPath);
        cmd.push_back("stop");
        cmd.push_back(containerName);
        cmd.push_back("-t");
        cmd.push_back("1");

        ret = ForkExecvp(cmd);

        unmountFixedDirectories(containerName);
    }

    if ((ret == 0) && shouldEmit) {
        mServer->Stopped(containerName);
    }

    if (ret != 0) {
        syslog(LOG_WARNING, "ContainerManager: Failed to stop container %s.", containerName.c_str());
    }

    return ret;
}

static void setCg2BpfForContainer(const std::string& containerName, bool useCg2Bpf)
{
    FILE* fp = nullptr;
    std::string path = ContainerNameToPath(containerName) + "/data/.cg2_bpf_enabled";

    fp = fopen(path.c_str(), "w");
    if (!fp) {
        return;
    }

    if (useCg2Bpf &&
            (kernelVersion() >= KVER(5, 4, 0)) &&
            isKernelConfigEnabled("CONFIG_BPF") &&
            isKernelConfigEnabled("CONFIG_BPF_JIT") &&
            isKernelConfigEnabled("CONFIG_BPF_SYSCALL") &&
            isKernelConfigEnabled("CONFIG_CGROUP_BPF") &&
            isKernelConfigEnabled("CONFIG_HAVE_EBPF_JIT") &&
            isKernelConfigEnabled("CONFIG_NETFILTER_XT_MATCH_BPF") &&
            isFilesystemSupported("cgroup2") &&
            isFilesystemSupported("bpf") &&
            ("private" == getContainerCgroupnsMode(containerName))) {
        fwrite("true", sizeof(char), strlen("true"), fp);
    } else {
        fwrite("false", sizeof(char), strlen("false"), fp);
    }

    fclose(fp);
}

int32_t ContainerManager::startContainer(const std::string &containerName, int32_t width, int32_t height)
{
    std::vector<std::string> cmd;
    int32_t ret;
    PropertyMap* propertyMap = nullptr;

    stopKydroidContainers();

    auto iter = mPropertiesMaps.find(containerName);
    if (iter != mPropertiesMaps.end()) {
        propertyMap = iter->second;
    } else {
        propertyMap = new PropertyMap();
        propertyMap->setPropertyFilePath(ContainerNameToPath(containerName) + "/data/local.prop");
        propertyMap->loadProperties();
        mPropertiesMaps.insert({ containerName, propertyMap });
    }

    if (propertyMap) {
        propertyMap->addProperty("sys.disable_epollwakeup", "true");
        propertyMap->addProperty("sys.disable_wake_alarm", "true");
        propertyMap->saveProperties();
    }

    setCg2BpfForContainer(containerName, true);

    auto c = findContainer(containerName);
    if (c) {
        if (propertyMap) {
            if (c->usesAshmemDevice()) {
                if (propertyMap->hasProperty(KMRE_USE_MEMFD_PROP)) {
                    propertyMap->removeProperty(KMRE_USE_MEMFD_PROP);
                    propertyMap->saveProperties();
                }
            } else {
                if (!isMemfdSupported()) {
                    syslog(LOG_ERR, "ContainerManager: Memfd is not supported.");
                }
                propertyMap->addProperty(KMRE_USE_MEMFD_PROP, "true");
                propertyMap->saveProperties();
            }
        }
        ret = c->start();
    } else {
        // docker start containerName
        if ((ret = Container::start(containerName)) != 0) {
            return ret;
        }
    }

    usleep(500000);

    if (!isContainerRunning(containerName)) {
        syslog(LOG_WARNING, "ContainerManager: Command to start container %s has been executed, but container seems not running.", containerName.c_str());
    } else {
        mountSharedBufferDirectory(containerName);
        syslog(LOG_INFO, "ContainerManager: Container %s is running now.", containerName.c_str());
    }

    return ret;
}

int32_t ContainerManager::exclusivelyStartContainer(const std::string &containerName, int32_t width, int32_t height)
{
    int num = 0;
    int ret = 0;
    syslog(LOG_DEBUG, "ContainerManager: Start container %s exclusively.", containerName.c_str());
    stopOtherContainer(containerName);
    createContainer(containerName);

#ifndef DISABLE_OTHER_ANDROID_ENVIRONMENT_CHECK
    if (!noOtherAndroidEnvironment()) {
        syslog(LOG_WARNING, "ContainerManager: Other Android environment detected.");
        return 0;
    }
#endif

    ret = startContainer(containerName, width, height);
    num = getNumberOfCpus();
    if (num == 0) {
        num = defaultNumberOfCpus;
    }

    return ret;
}

void ContainerManager::destroyContainer(const std::string &containerName)
{
    std::vector<std::string> cmd;

    syslog(LOG_DEBUG, "ContainerManager: Destroy container %s.", containerName.c_str());
    // First of all, stop container
    stopContainer(containerName, false);

    // Then destroy container
    cmd.push_back(dockerPath);
    cmd.push_back("rm");
    cmd.push_back(containerName);

    ForkExecvp(cmd);
}

int32_t ContainerManager::inspectContainer(const std::string &containerName, const std::string &format, std::vector<std::string> &output)
{
    std::vector<std::string> cmd;
    int32_t ret;

    output.clear();
    // docker inspect --format '${format}' containerName
    cmd.push_back(dockerPath);
    cmd.push_back("inspect");
    cmd.push_back("--format");
    cmd.push_back(format);
    cmd.push_back(containerName);

    ret = ForkExecvp(cmd, output);

    return ret;
}

void ContainerManager::stopOtherContainer(const std::string &containerName)
{
    const std::string& imageRepo = GetImageRepo();
    auto infos = ListContainerInfo();
    for (auto info : infos) {
        if (info.imageRepo == imageRepo) {
            if (info.name != containerName) {
                stopContainer(info.name, true);
            }
        }
    }
}

void ContainerManager::createContainer(const std::string &containerName)
{
    std::string userName;
    int32_t uid;
    bool result;
    int32_t ret;
    std::string runningState;
    bool isRunning = false;
    bool imageMatched = false;
    bool recreate = false;
    std::vector<std::string> output;
    const std::string& image = GetImageVersion();

    syslog(LOG_DEBUG, "ContainerManager: Create container %s.", containerName.c_str());

    // Get running status
    ret = inspectContainer(containerName, formatInspectRunning, output);
    if (ret == 0 && output.size() > 0) {
        runningState = output[0];
        if (runningState.compare("true") == 0) {
            isRunning = true;
        }
    }

    ret = inspectContainer(containerName, formatInspectImage, output);
    if (ret == 0 && output.size() > 0) {
        if (output[0] == image) {
            imageMatched = true;
        }
    }

    std::shared_ptr<Container> c = findContainer(containerName);
    if (!c) {
        result = ParseContainerName(containerName, userName, uid);
        if (!result) {
            syslog(LOG_ERR, "ContainerManager: Failed to create container %s: container name cannot be parsed.", containerName.c_str());
            return;
        }

        c = std::make_shared<Container>(Container(userName, uid, image, *this));
        if (!c) {
            syslog(LOG_ERR, "ContainerManager: Failed to initialize container %s.", containerName.c_str());
            return;
        }
        mContainers.push_back(c);
    }

    recreate = c->shouldRecreate();
    if (!imageMatched || recreate) {
        if (isRunning) {
            c->stop();
        }

        destroyContainer(containerName);
        c->setImage(image);
        ret = c->create();
        if (ret != 0) {
            syslog(LOG_ERR, "ContainerManager: Failed to create container %s.", containerName.c_str());
        }
    }
}

std::string ContainerManager::getPropOfContainer(const std::string &containerName, const std::string &prop)
{
    std::vector<std::string> cmd;
    std::vector<std::string> output;
    std::string value;
    int32_t ret;

    // docker exec containerName /system/bin/getprop prop
    cmd.push_back(dockerPath);
    cmd.push_back("exec");
    cmd.push_back(containerName);
    cmd.push_back("/system/bin/getprop");
    cmd.push_back(prop);

    ret = ForkExecvpWithTimeout(cmd, output, 5000);
    if (ret == 0 && output.size() > 0) {
        value = output[0];
    }

    return value;
}

std::string ContainerManager::GetPropOfContainer(const std::string &userName, const int32_t &uid, const std::string prop)
{
    std::string containerName = ContainerName(userName, uid);
    return getPropOfContainer(containerName, prop);
}

void ContainerManager::setPropOfContainer(const std::string &containerName, const std::string &prop, const std::string &value)
{
    std::vector<std::string> cmd;

    // docker exec  containerName /system/bin/setprop prop value
    cmd.push_back(dockerPath);
    cmd.push_back("exec");
    cmd.push_back(containerName);
    cmd.push_back("/system/bin/setprop");
    cmd.push_back(prop);
    cmd.push_back(value);

    ForkExecvp(cmd);
}

void ContainerManager::SetPropOfContainer(const std::string &userName, const int32_t &uid, const std::string &prop, const std::string &value)
{
    std::string containerName = ContainerName(userName, uid);
    setPropOfContainer(containerName, prop, value);
}

void ContainerManager::SetDefaultPropOfContainer(const std::string &userName, const int32_t &uid, const std::string &prop, const std::string &value)
{
    std::string containerName = ContainerName(userName, uid);
    std::string containerPath = ContainerPath(userName, uid);
    std::string propFilePath = containerPath + "/data/local.prop";
    PropertyMap* propertyMap = nullptr;

    auto iter = mPropertiesMaps.find(containerName);
    if (iter != mPropertiesMaps.end()) {
        propertyMap = iter->second;
    } else {
        propertyMap = new PropertyMap();
        propertyMap->setPropertyFilePath(propFilePath);
        propertyMap->loadProperties();
        mPropertiesMaps.insert({ containerName, propertyMap });
    }

    if (propertyMap) {
        propertyMap->addProperty(prop, value);
    }

}

std::string ContainerManager::GetDefaultPropOfContainer(const std::string &userName, const int32_t &uid, const std::string prop)
{
    std::string containerName = ContainerName(userName, uid);
    std::string containerPath = ContainerPath(userName, uid);
    std::string propFilePath = containerPath + "/data/local.prop";
    PropertyMap* propertyMap = nullptr;
    std::string value;

    auto iter = mPropertiesMaps.find(containerName);
    if (iter != mPropertiesMaps.end()) {
        propertyMap = iter->second;
        if (propertyMap) {
            value = propertyMap->getProperty(prop);
        }
    } else {
        propertyMap = new PropertyMap();
        propertyMap->setPropertyFilePath(propFilePath);
        propertyMap->loadProperties();
        mPropertiesMaps.insert({ containerName, propertyMap });
        value = propertyMap->getProperty(prop);
    }

    return value;
}

std::string ContainerManager::GetContainerNetworkInformation(const std::string &userName, const int32_t &uid)
{
    ContainerNetworkInfo info;
    std::string infoStr;

    Json::Value obj(Json::objectValue);
    Json::FastWriter writer;

    std::string containerName = ContainerName(userName, uid);
    if (!getContainerNetworkInformation(containerName, info)) {
        obj["NetworkMode"] = "unknown";
        obj["IPAddress"] = "";
        obj["Gateway"] = "";
        infoStr = writer.write(obj);
    } else {
        obj["NetworkMode"] = info.mode;
        obj["IPAddress"] = info.ipAddress;
        obj["Gateway"] = info.gateway;
        infoStr = writer.write(obj);
    }

    return infoStr;
}

void ContainerManager::SetFocusOnContainer(const std::string &userName, const int32_t &uid, const int32_t &onFocus)
{
    const std::string prop = "is_kmre_on_focus";
    const std::string value = std::to_string(onFocus);
    std::string containerName = ContainerName(userName, uid);

    setPropOfContainer(containerName, prop, value);
}

int32_t ContainerManager::StartContainer(const std::string &userName, int32_t uid, int32_t width, int32_t height)
{
    std::string containerName = ContainerName(userName, uid);
    syslog(LOG_DEBUG, "ContainerManager: Start container %s.", containerName.c_str());
    return exclusivelyStartContainer(containerName, width, height);
}

int32_t ContainerManager::StartContainerSilently(const std::string &userName, int32_t uid, int32_t width, int32_t height)
{
    std::string containerName = ContainerName(userName, uid);

    auto infoList = ListContainerInfo(false);
    if (infoList.size() > 0) {
        return 0;
    }

    createContainer(containerName);

#ifndef DISABLE_OTHER_ANDROID_ENVIRONMENT_CHECK
    if (!noOtherAndroidEnvironment()) {
        syslog(LOG_WARNING, "ContainerManager: Other Android environment detected.");
        return 0;
    }
#endif


    startContainer(containerName, width, height);
    updateContainerCpuNumber(containerName, 1);

    return 0;
}

int32_t ContainerManager::ChangeContainerRuntimeStatus(const std::string &userName, int32_t uid)
{
    int ret = 0;
    int num = 0;

    std::string containerName = ContainerName(userName, uid);

    if (isContainerRunning(containerName)) {
        num = getNumberOfCpus();
        if (num == 0) {
            num = defaultNumberOfCpus;
        }

        updateContainerCpuNumber(containerName, num);
    } else {
        updateContainerCpuNumber(containerName, 1);
    }

    return ret;
}

int32_t ContainerManager::StopContainer(const std::string &userName, int32_t uid)
{
    std::string containerName = ContainerName(userName, uid);
    syslog(LOG_DEBUG, "ContainerManager: Stop container %s.", containerName.c_str());
    return stopContainer(containerName, true);
}

std::vector<ContainerInfo> ContainerManager::ListContainerInfo(bool listAll)
{
    std::vector<std::string> cmd;
    std::vector<std::string> output;
    std::vector<ContainerInfo> infos;
    int ret;

    const std::string& imageRepo = GetImageRepo();

    // docker ps -a --format '{{.Names}},{{.ID}},{{.Image}}'
    cmd.push_back(dockerPath);
    cmd.push_back("ps");

    if (listAll) {
        cmd.push_back("-a");
    }

    cmd.push_back("--format");
    cmd.push_back("'{{.Names}},{{.ID}},{{.Image}}'");

    ret = ForkExecvp(cmd, output);
    if (ret != 0) {
        return infos;
    }

    for (auto s : output) {
        // containerName,id,imageRepo:imageTag
        auto ss = split(s, ',');
        if ( ss.size() != 3) {
            continue;
        }
        auto image = split(ss[2], ':');
        if(image.size() != 2){
            continue;
        }
        /*
         * ss[0]: containerName
         * image[0]: imageRepo
         * image[1]: imageTag
         */
        if (image[0] == imageRepo) {
            infos.push_back({ss[0], image[0], image[1]});
        }

    }

    return infos;
}

bool ContainerManager::isContainerRunning(const std::string &containerName)
{
    auto infos = ListContainerInfo(false);
    for (auto info : infos) {
        if (info.name == containerName) {
            return true;
        }
    }

    return false;
}

std::vector<ImageInfo> ContainerManager::listImageInfo()
{
    std::vector<std::string> cmd;
    std::vector<std::string> output;
    std::vector<ImageInfo> infos;
    int ret;

    const std::string& imageRepo = GetImageRepo();

    // docker images --format '{{.Tag}}' imageRepo
    cmd.push_back(dockerPath);
    cmd.push_back("images");
    cmd.push_back("--format");
    cmd.push_back("'{{.Tag}}'");
    cmd.push_back(imageRepo);

    ret = ForkExecvp(cmd, output);
    if (ret != 0) {
        return infos;
    }

    for (auto tag : output) {
        // For example: v1.0-190729.3
        uint32_t versionMajor;
        uint32_t versionMinor;
        uint32_t date;
        uint32_t revision;

        ret = sscanf(tag.c_str(), "v%u.%u-%u.%u", &versionMajor, &versionMinor, &date, &revision);
        if (ret != 4) {
            continue;
        }

        ImageInfo info(imageRepo, tag, versionMajor, versionMinor, date, revision);
        infos.push_back(info);
    }

    std::sort(infos.begin(), infos.end());
    std::reverse(infos.begin(), infos.end());

    return infos;
}

std::vector<ImageMeta> ContainerManager::listAllImagesDescriptions()
{
    std::vector<std::string> cmd;
    std::vector<std::string> output;
    std::vector<ImageMeta> infos;
    int ret;

    // docker images --format {{.Repository}}:{{.Tag}},{{.Repository}},{{.Tag}},{{.ID}},{{.CreatedAt}},{{.Size}}
    cmd.push_back(dockerPath);
    cmd.push_back("images");
    cmd.push_back("--format");
    cmd.push_back("'{{.Repository}}:{{.Tag}},{{.Repository}},{{.Tag}},{{.ID}},{{.CreatedAt}},{{.Size}}'");

    ret = ForkExecvp(cmd, output);
    if (ret != 0) {
        return infos;
    }

    for (auto line : output) {
        // For example: kmre2:v2.0-210121.10,kmre2,v2.0-210121.10,22c2fbf8145b,2021-01-21 11:24:57 +0800 CST,1.16GB
        auto ss = split(line, ',');
        if (ss.size() != 6) {
            continue;
        }
        if (ss[1] == "kmre2" || ss[1] == "kydroid2" || ss[1] == "kydroid3") {
            infos.push_back({ss[3], ss[0], ss[1], ss[2], ss[4], ss[5]});
        }
    }

    return infos;
}

void ContainerManager::loadImage(const std::string& imagePath)
{
    std::vector<std::string> cmd;
    int ret = -1;

    // docker load -i /path/to/kmre/docker/image

    if (!isPathRegularFile(imagePath)) {
        mServer->ImageFileNotFound();
        syslog(LOG_WARNING, "ContainerManager: Image file doesn't exist.");
        return;
    }

    cmd.push_back(dockerPath);
    cmd.push_back("load");
    cmd.push_back("-i");
    cmd.push_back(imagePath);

    ret = ForkExecvp(cmd);

    if (ret == 0) {
        if (IsImageReady()) {
            mServer->ImageLoaded(1);
            syslog(LOG_INFO, "ContainerManager: Image loaded.");
        } else {
            mServer->ImageNotMatched();
            syslog(LOG_WARNING, "ContainerManager: Loaded image doesn't match configuration.");
        }
    } else {
        mServer->ImageLoadFailed();
        syslog(LOG_ERR, "ContainerManager: Failed to load image.");
    }
}

void ContainerManager::loadImageProcessor()
{
    while (!mStopLoading) {
        if (!mImageLoading) {
            sleep(1);
            continue;
        }

        loadImage(CONTAINER_IMAGE_PATH);
        mImageLoading.exchange(false);
    }
}

void ContainerManager::SetGlobalEnvironmentVariable(const std::string &key, const std::string &value)
{
    std::string globalValue;
    globalValue = mGlobalEnv.getProperty(key);

    if (value != globalValue) {
        mGlobalEnv.addProperty(key, value);
        mGlobalEnv.saveProperties(0644);
    }
}

void ContainerManager::LoadImage()
{
    if (!isImageConfigurationReady()) {
        syslog(LOG_WARNING, "ContainerManager: Image configuration not found.");
        mServer->ImageConfNotFound();
        return;
    }

    syslog(LOG_DEBUG, "ContainerManager: Try to load image.");
    if (IsImageReady()) {
        mServer->ImageLoaded(1);
        syslog(LOG_DEBUG, "ContainerManager: Image is already loaded.");
        return;
    }

    if (mImageLoading) {
        syslog(LOG_DEBUG, "ContainerManager: Loading image currently.");
        return;
    }

    mImageLoading.exchange(true);
}

bool ContainerManager::IsImageReady()
{
    bool imageFound = false;
    std::vector<ImageInfo> infos;

    const std::string& imageRepo = GetImageRepo();
    const std::string& imageTag = GetImageTag();
    const std::string& imageVersion = GetImageVersion();

    if (!isStringValid(imageRepo) || !isStringValid(imageTag) || !isStringValid(imageVersion)) {
        syslog(LOG_WARNING, "ContainerManager: Image configuration not found.");
        mServer->ImageConfNotFound();
        return false;
    }

    infos = listImageInfo();
    for (auto info : infos) {
        if (imageRepo == info.GetRepo() && imageTag == info.GetTag()) {
            imageFound = true;
            break;
        }
    }

    return imageFound;
}

void ContainerManager::checkAndAddOverlayDirectory(const std::string &path, std::set<std::string>& overlayDirectories, bool update)
{
    std::string systemPath = path + "/system";
    if (isPathDir(systemPath)) {
        if (mAllOverlayDirectories.find(path) == mAllOverlayDirectories.end()) {
            mAllOverlayDirectories.insert(path);
            if (update) {
                overlayDirectories.insert(path);
            }
        }
    }
}

void ContainerManager::getOverlayDirectoriesForImage()
{
    std::string value;
    const std::string& image = GetImageVersion();

    value = inspectOverlayDirectories(image);
    if (value.length() <= 0) {
        return;
    }

    auto ss = split(value, ':');
    for (auto s : ss) {
        checkAndAddOverlayDirectory(s, mImageOverlayDirectories, false);
    }
}

void ContainerManager::getOverlayDirectoriesForContainers()
{
    std::string value;

    for (std::shared_ptr<Container> c : mContainers) {
        value = inspectOverlayDirectories(c->getContainerName());
        if (value.length() <= 0) {
            continue;
        }

        auto ss = split(value, ':');
        for (auto s : ss) {
            checkAndAddOverlayDirectory(s, mContainerOverlayDirectories, false);
        }
    }
}

std::string ContainerManager::GetAllImages()
{
    std::string value;

    std::vector<ImageMeta> infos = listAllImagesDescriptions();
    if (infos.size() > 0) {
        Json::Value objs(Json::arrayValue);
        int index=0;
        for (auto elem : infos) {
            Json::Value v;
            elem.toJson(v);
            objs[index] = v;
            index++;
        }

        Json::FastWriter writer;
        value = writer.write(objs);

        return value;
    }

    return value;
}

std::string ContainerManager::GetAllContainers()
{
    std::string value;
    //auto infos = ListContainerInfo();
    std::vector<std::string> cmd;
    std::vector<std::string> output;
    std::vector<ContainerInfo> infos;
    int ret;

    // docker ps -a --format '{{.Names}},{{.ID}},{{.Image}}'
    cmd.push_back(dockerPath);
    cmd.push_back("ps");
    cmd.push_back("-a");
    cmd.push_back("--format");
    cmd.push_back("'{{.Names}},{{.ID}},{{.Image}}'");

    ret = ForkExecvp(cmd, output);
    if (ret == 0) {
        for (auto s : output) {
            // containerName,id,imageRepo:imageTag
            auto ss = split(s, ',');
            if ( ss.size() != 3) {
                continue;
            }
            auto image = split(ss[2], ':');
            if(image.size() != 2){
                continue;
            }
            /*
             * ss[0]: containerName
             * image[0]: imageRepo
             * image[1]: imageTag
             */
            if (image[0] == "kmre2" || image[0] == "kydroid2" || image[0] == "kydroid3") {
                infos.push_back({ss[0], image[0], image[1]});
            }
        }
    }

    if (infos.size() > 0) {
        Json::Value objs(Json::arrayValue);
        int index=0;
        for (auto elem : infos) {
            Json::Value v;
            elem.toJson(v);
            objs[index] = v;
            index++;
        }

        Json::FastWriter writer;
        value = writer.write(objs);

        return value;
    }

    return value;
}

std::string ContainerManager::GetCurrentContainerAndImage()
{
    std::string value;

    ContainerInfo info;
    info.name = GetImageVersion();
    info.imageRepo = GetImageRepo();
    info.imageTag = GetImageTag();

    Json::Value item = Json::Value::null;
    info.toJson(item);

    Json::FastWriter writer;
    value = writer.write(item);

    return value;
}

// container: 代表镜像绑定的容器名， image: 代表镜像名
bool ContainerManager::RemoveOneImage(const std::string &container, const std::string &image)
{
    int ret = -1;
    std::vector<std::string> stop_cmd;
    std::vector<std::string> rm_cmd;
    std::vector<std::string> rmi_cmd;

    if (image.empty()) {
        return false;
    }

    if (!container.empty()) {
        // docker stop kmre-1000-kylin -t 1
        stop_cmd.push_back(dockerPath);
        stop_cmd.push_back("stop");
        stop_cmd.push_back(container);
        stop_cmd.push_back("-t");
        stop_cmd.push_back("1");
        ret = ForkExecvp(stop_cmd);

        // docker rm kmre-1000-kylin
        rm_cmd.push_back(dockerPath);
        rm_cmd.push_back("rm");
        rm_cmd.push_back(container);
        ret = ForkExecvp(rm_cmd);
    }

    // docker rmi kmre2:v2.0-210121.10
    rmi_cmd.push_back(dockerPath);
    rmi_cmd.push_back("rmi");
    rmi_cmd.push_back(image);

    ret = ForkExecvp(rmi_cmd);
    if (ret == 0) {
        mServer->ImageRemoved(image, true);
        return true;
    } else {
        mServer->ImageRemoved(image, false);
        return false;
    }
}

void ContainerManager::ComponentsUpgrade(const std::string &args)
{
    mServer->ComponentsUpgradeFinished(args);
}

static bool ParseKydroidContainerName(const std::string& containerName, std::string& userName, int32_t& uid)
{
    int32_t _uid = -1;
    int ret = 0;
    char buffer[1024] = {0};

    ret = sscanf(containerName.c_str(), "kydroid-%d-%s", &_uid, buffer);
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

std::vector<std::string> ContainerManager::runningKydroidContainers()
{
    std::vector<std::string> names;
    std::vector<std::string> cmd;
    std::vector<std::string> output;
    int ret;
    const char* prefix = "kydroid-";
    size_t len = strlen(prefix);

    // docker ps -a --format '{{.Names}}'
    cmd.push_back(dockerPath);
    cmd.push_back("ps");

    cmd.push_back("--format");
    cmd.push_back("'{{.Names}}'");

    ret = ForkExecvp(cmd, output);
    if (ret != 0) {
        return names;
    }

    for (auto name : output) {
        if (strncmp(name.c_str(), prefix, len) == 0) {
            names.push_back(name);
        }
    }

    return names;
}

static void killKydroidDisplayWindows()
{
    std::vector<std::string> cmd;

    // killall kydroid-display-window
    cmd.push_back("/usr/bin/killall");
    cmd.push_back("kydroid-display-window");

    ForkExecvp(cmd);

}

static void stopKydroidContainer(const std::string& container)
{
    std::vector<std::string> cmd;
    std::string userName;
    int32_t uid;

    // docker stop container -t 1
    cmd.push_back(dockerPath);
    cmd.push_back("stop");
    cmd.push_back(container);
    cmd.push_back("-t");
    cmd.push_back("1");

    ForkExecvp(cmd);

    if (ParseKydroidContainerName(container, userName, uid)) {
        unmountLegacyFixedDirectories(userName, uid);
    }
}

void ContainerManager::stopKydroidContainers()
{
    std::string userName;
    int uid;
    std::vector<std::string> kydroidContainers = runningKydroidContainers();

    for (std::string container : kydroidContainers) {
        if (ParseKydroidContainerName(container, userName, uid)) {
            if (!mServer->stopKydroidContainer(userName, uid)) {
                stopKydroidContainer(container);
            }
        }
    }

    if (kydroidContainers.size() > 0) {
        killKydroidDisplayWindows();
    }
}

} // namespace container
} // namespace kmre
