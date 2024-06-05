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

#include "container.h"
#include "container_manager.h"
#include "utils.h"
#include "container_utils.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/statvfs.h>
#include <fcntl.h>

#include <sys/syslog.h>

#include <vector>
#include <algorithm>
#include <regex>

#define CONTAINER_DEVICE_RESERVED          0
#define CONTAINER_DEVICE_AUDIO1            1
#define CONTAINER_DEVICE_DSP1              2
#define CONTAINER_DEVICE_MIXER             3
#define CONTAINER_DEVICE_MIXER1            4
#define CONTAINER_DEVICE_SND               5
#define CONTAINER_DEVICE_VIDEO0            6
#define CONTAINER_DEVICE_DRI               7
#define CONTAINER_DEVICE_VIDEO1            8
#define CONTAINER_DEVICE_VIDEO2            9
#define CONTAINER_DEVICE_VIDEO3            10
#define CONTAINER_DEVICE_ION               11
#define CONTAINER_DEVICE_TUN               12
#define CONTAINER_DEVICE_ASHMEM            13

#if defined(__x86_64) || defined(__x86_64__) || defined(__amd64) || defined(__amd64__)
static const std::string hostArchitecture = "amd64";
#endif

#if defined(__i386) || defined(__i386__) || defined(__i686) || defined(__i686__)
static const std::string hostArchitecture = "i386";
#endif

#if defined(__aarch64__)
static const std::string hostArchitecture = "arm64";
#endif

#if defined(__arm__)
static const std::string hostArchitecture = "armhf";
#endif

#if defined(__mips__)
#if defined(__LP64__)
static const std::string hostArchitecture = "mips64el";
#else
static const std::string hostArchitecture = "mipsel";
#endif
#endif

#if defined(__sw_64__)
static const std::string hostArchitecture = "sw64";
#endif

#define BUF_SIZE 4096

static const std::string dockerPath = "/usr/bin/docker";
static const std::string kmrePath = "/var/lib/kmre";
static const std::string fusePrefixPath = kmrePath + "/data";
static const std::string kmreSharePath = "/usr/share/kmre";

static const std::string legacyPath = "/var/lib/kydroid";
static const std::string legacyFusePrefixPath = legacyPath + "/data";

namespace kmre {
namespace container {

Container::Container(const std::string &userName, int32_t uid, const std::string image, ContainerManager& manager, bool privileged)
    : mUserName(userName),
      mUid(uid),
      mImageVersion(image),
      mPrivileged(privileged),
      mContainerManager(manager),
      mUsePrivateCgroupns(false),
      mCgroupnsMode(""),
      mCurrentNetworkMode("default"),
      mNewNetworkMode("default"),
      mSettingFile("/home/" + userName + "/.config/kmre/kmre.ini")
{
    mContainerPath = ContainerPath(mUserName, mUid);
    mContainerName = ContainerName(mUserName, mUid);

    checkDockerVersion();

    initializeOptDevices();
    initializeSerialPortDevices();
    makeConfiguration();
}

Container::~Container()
{}

int32_t Container::start(const std::string &containerName)
{
    std::vector<std::string> cmd;
    int32_t ret;

    syslog(LOG_DEBUG, "Container: Start container %s.", containerName.c_str());
    cmd.push_back(dockerPath);
    cmd.push_back("start");
    cmd.push_back(containerName);

    ret = ForkExecvp(cmd);
    if (ret != 0) {
        syslog(LOG_ERR, "Container: Failed to start container %s.", containerName.c_str());
        return ret;
    }

    ret = mountFixedDirectories(containerName);

    return ret;
}

int32_t Container::start()
{
    return start(mContainerName);
}

int32_t Container::stop()
{
    std::vector<std::string> cmd;
    int32_t ret;

    syslog(LOG_DEBUG, "Container: Stop container %s.", mContainerName.c_str());

    cmd.push_back(dockerPath);
    cmd.push_back("stop");
    cmd.push_back(mContainerName);
    cmd.push_back("-t");
    cmd.push_back("1");

    ret = ForkExecvp(cmd);

    unmountFixedDirectories(mContainerName);

    return ret;
}

int32_t Container::create()
{
    int32_t ret = 0;
    std::string mntPath = mContainerPath + "/mnt";
    std::string socketsPath = mContainerPath + "/sockets";
    std::vector<std::string> cmd;

    if (mImageVersion.empty() || mImageVersion.length() == 0) {
        syslog(LOG_ERR, "Container: Image version is invalid.");
        return -1;
    }

    mkdir(mntPath.c_str(), 0755);
    chmod(mntPath.c_str(), 0755);
    chown(mntPath.c_str(), 0, 1000);

    mkdir(socketsPath.c_str(), 0755);
    chmod(socketsPath.c_str(), 0777);

    makeCreateCommand(cmd);
    // syslog(LOG_DEBUG, "----------------------- Container create cmd:");
    // for (const auto& str : cmd) {
    //     syslog(LOG_DEBUG, "%s", str.c_str());
    // }
    // syslog(LOG_DEBUG, "-----------------------");

    ret = ForkExecvp(cmd);

    if (ret == 0) {
        writeOptDeviceBitmask();
        writeSerialPortDeviceChecksum();
        updateNetworkMode();
    }

    return ret;
}

void Container::addDeviceConf(const std::string &device, const std::string &containerDevice, const std::string perm)
{
    std::pair<std::string, Specification> dev(device, { containerDevice, perm });
    mConfig.devices.push_back(dev);
}

void Container::addDeviceConfIfExist(const std::string &device, const std::string &containerDevice, int fileType, const std::string perm)
{
    if (!isPathFileType(device, fileType)) {
        return;
    }

    addDeviceConf(device, containerDevice, perm);
    auto d = mOptDevices.find(device);
    if (d != mOptDevices.end()) {
        mDeviceBitmask.set(d->second.bitIndex);
    }
}

void Container::addDeviceConfIfExist(const OptDevice &optDevice)
{
    if (!isPathFileType(optDevice.pathOnHost, optDevice.fileType)) {
        return;
    }

    addDeviceConf(optDevice.pathOnHost, optDevice.pathOnContainer, optDevice.perm);
    mDeviceBitmask.set(optDevice.bitIndex);
}

void Container::refreshOptDeviceBitmask()
{
    // Reset bitmask.
    mDeviceBitmask.reset();

    auto iter = mOptDevices.begin();
    while (iter != mOptDevices.end()) {
        OptDevice& optDevice = iter->second;
        if (isPathFileType(optDevice.pathOnHost, optDevice.fileType)) {
            mDeviceBitmask.set(optDevice.bitIndex);
        }
        ++iter;
    }
}

void Container::refreshSerialPortDeviceChecksum()
{
    std::string totalString;

    mSerialPortDeviceChecksum.clear();

    auto iter = mSerialPortDevices.begin();
    while (iter != mSerialPortDevices.end()) {
        if (isPathCharDevice(*iter)) {
            totalString += *iter;
        }

        iter++;
    }

    mSerialPortDeviceChecksum = sha512sum(totalString.c_str(), totalString.length());
}

void Container::addVolumeConf(const std::string &volume, const std::string &containerVolume, const std::string perm)
{
    std::pair<std::string, Specification> vol(volume, { containerVolume, perm });
    mConfig.volumes.push_back(vol);
}

void Container::addBindMountConf(const std::string &source, const std::string &target, const std::string &propagation)
{
    BindMount bm( {source, target, propagation} );
    mConfig.bindMounts.push_back(bm);
}

void Container::addTmpfsConf(const std::string &dest, const std::string &mode, uint32_t size)
{
    TmpfsSpec ts( {dest, mode, size} );
    mConfig.tmpfs.push_back(ts);
}

void Container::initializeOptDevices()
{
    //mOptDevices.insert({"/dev/audio1", {"/dev/audio1", "/dev/audio1", "rwm", CONTAINER_DEVICE_AUDIO1, S_IFCHR}});
    //mOptDevices.insert({"/dev/dsp1", {"/dev/dsp1", "/dev/dsp1", "rwm", CONTAINER_DEVICE_DSP1, S_IFCHR}});
    //mOptDevices.insert({"/dev/mixer", {"/dev/mixer", "/dev/mixer", "rwm", CONTAINER_DEVICE_MIXER, S_IFCHR}});
    //mOptDevices.insert({"/dev/mixer1", {"/dev/mixer1", "/dev/mixer1", "rwm", CONTAINER_DEVICE_MIXER1, S_IFCHR}});
    //mOptDevices.insert({"/dev/snd", {"/dev/snd", "/dev/snd", "rwm", CONTAINER_DEVICE_SND, S_IFDIR}});
    mOptDevices.insert({"/dev/video0", {"/dev/video0", "/dev/video0", "rwm", CONTAINER_DEVICE_VIDEO0, S_IFCHR}});
    mOptDevices.insert({"/dev/dri", {"/dev/dri", "/dev/dri", "rwm", CONTAINER_DEVICE_DRI, S_IFDIR}});
    mOptDevices.insert({"/dev/video1", {"/dev/video1", "/dev/video1", "rwm", CONTAINER_DEVICE_VIDEO1, S_IFCHR}});
    mOptDevices.insert({"/dev/video2", {"/dev/video2", "/dev/video2", "rwm", CONTAINER_DEVICE_VIDEO2, S_IFCHR}});
    mOptDevices.insert({"/dev/video3", {"/dev/video3", "/dev/video3", "rwm", CONTAINER_DEVICE_VIDEO3, S_IFCHR}});
    mOptDevices.insert({"/dev/ion", {"/dev/ion", "/dev/ion", "rwm", CONTAINER_DEVICE_ION, S_IFCHR}});
    mOptDevices.insert({"/dev/net/tun", {"/dev/net/tun", "/dev/tun", "rwm", CONTAINER_DEVICE_TUN, S_IFCHR}});
    mOptDevices.insert({"/dev/ashmem", {"/dev/ashmem", "/dev/ashmem", "rwm", CONTAINER_DEVICE_ASHMEM, S_IFCHR}});
}

void Container::initializeSerialPortDevices()
{
    getSerialPortDevices(mSerialPortDevices);
    refreshSerialPortDeviceChecksum();
}

void Container::makeConfiguration()
{
    mConfig.bindMounts.clear();
    mConfig.devices.clear();
    mConfig.tmpfs.clear();
    mConfig.volumes.clear();

    /* For binder devices */
    if (isPathCharDevice("/dev/binders/binder0") &&
            isPathCharDevice("/dev/binders/binder1") &&
            isPathCharDevice("/dev/binders/binder2")) {
        addDeviceConf("/dev/binders/binder0", "/dev/binder");
        addDeviceConf("/dev/binders/binder1", "/dev/hwbinder");
        addDeviceConf("/dev/binders/binder2", "/dev/vndbinder");
    } else {
        addDeviceConf("/dev/binder", "/dev/binder");
        addDeviceConf("/dev/hwbinder", "/dev/hwbinder");
        addDeviceConf("/dev/vndbinder", "/dev/vndbinder");
    }

    /* For mandatory devices */
    addDeviceConf("/dev/input", "/dev/input");
    //addDeviceConf("/dev/ashmem", "/dev/ashmem");
    addDeviceConf("/dev/fuse", "/dev/fuse");
    //addDeviceConf("/dev/ion", "/dev/ion");
    //addDeviceConf("/dev/kmsg", "/dev/kmsg");


    /* For optional device */
    auto iter = mOptDevices.begin();
    while (iter != mOptDevices.end()) {
        addDeviceConfIfExist(iter->second);
        ++iter;
    }

    /* For serial port device */
    auto serialIter = mSerialPortDevices.begin();
    while (serialIter != mSerialPortDevices.end()) {
        addDeviceConfIfExist(*serialIter, *serialIter, S_IFCHR);
        serialIter++;
    }

    /* For volumes */
    addVolumeConf(mContainerPath + "/acct/", "/acct/");
    addVolumeConf(mContainerPath + "/cache/", "/cache/");
    addVolumeConf(mContainerPath + "/config/", "/config/");
    //addVolumeConf(mContainerPath + "/data/", "/data/");
    addVolumeConf(mContainerPath + "/mnt/", "/mnt/");
    addVolumeConf(mContainerPath + "/storage/", "/storage/");
    addVolumeConf(mContainerPath + "/sockets/", "/sockets/");

    /* For bind mount */
    addBindMountConf(mContainerPath + "/data/", "/data/", "rshared");

    /* For tmpfs */
    addTmpfsConf("/data/local/icons", "0666", 134217728);
    addTmpfsConf("/data/local/screenshots", "0666", 134217728);
}

void Container::makeCreateCommand(std::vector<std::string>& cmd)
{
    cmd.clear();
    // docker create
    cmd.push_back(dockerPath);
    cmd.push_back("create");

    // --name container_name
    cmd.push_back("--name");
    cmd.push_back(mContainerName);

    // for cgroup namespace
    if (mUsePrivateCgroupns) {
        cmd.push_back("--cgroupns");
        cmd.push_back("private");
    }

    // for network mode (bridge mode default)
    if (isPathRegularFile(mSettingFile)) {
        cmd.push_back("-v");
        cmd.push_back(mSettingFile + ":" + "/etc/kmre.ini");
    }
    if (mNewNetworkMode == "host") {
        cmd.push_back("--network");
        cmd.push_back("host");
    }

    std::string arg;
    // for devices
    for (auto device : mConfig.devices) {
        arg = "--device=" + device.first + ":" + device.second.spec + ":" + device.second.perm;
        cmd.push_back(arg);
    }

    // for volumes
    for (auto volume : mConfig.volumes) {
        arg = volume.first + ":" + volume.second.spec + ":" +volume.second.perm;
        cmd.push_back("-v");
        cmd.push_back(arg);
    }

    /*
     * for stop timeout
     * --stop-timeout 1
     */
    cmd.push_back("--stop-timeout");
    cmd.push_back("1");

    /* for security
     * --cap-add ALL
     * --security-opt apparmor=unconfined
     * --security-opt seccomp=unconfined
     */
    cmd.push_back("--cap-add");
    cmd.push_back("ALL");
    cmd.push_back("--security-opt");
    cmd.push_back("apparmor=unconfined");
    cmd.push_back("--security-opt");
    cmd.push_back("seccomp=unconfined");

    /* Set PATH environment variables */
    cmd.push_back("--env");
    cmd.push_back("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/system/bin:/system/xbin");

    // for bind mount
    // --mount type=bind,source=${source},target=${target},bind-propagation=${propagation}
    for (auto mount : mConfig.bindMounts) {
        arg = "type=bind,source=" + mount.source + ",target=" + mount.target + ",bind-propagation=" + mount.propagation;
        cmd.push_back("--mount");
        cmd.push_back(arg);
    }

    // for tmpfs
    // --mount type=tmpfs,destination=${dest},tmpfs-mode=${mode},tmpfs-size=${size}
    for (auto fs : mConfig.tmpfs) {
        arg = "type=tmpfs,destination=" + fs.dest + ",tmpfs-mode=" + fs.mode + ",tmpfs-size=" + std::to_string(fs.size);
        cmd.push_back("--mount");
        cmd.push_back(arg);
    }

    // --tty=true
    cmd.push_back("--tty=true");

    // --dns=xxx.xxx.xxx.xxx
    cmd.push_back("--dns=114.114.114.114");

    // image version
    cmd.push_back(mImageVersion);

    // init program
    cmd.push_back("/init.kmre");
}

void Container::writeOptDeviceBitmask()
{
    FILE *fp = nullptr;
    std::string path = mContainerPath + "/.opt_device_bitmask";
    std::string str;

    fp = fopen(path.c_str(), "w");
    if (!fp) {
        return;
    }

    str = mDeviceBitmask.to_string('0', '1');
    fwrite(str.c_str(), sizeof(char), strlen(str.c_str()), fp);

    fclose(fp);
}

void Container::writeSerialPortDeviceChecksum()
{
    FILE* fp = nullptr;
    std::string path = mContainerPath + "/.serial_port_device_checksum";

    fp = fopen(path.c_str(), "w");
    if (!fp) {
        return;
    }

    fwrite(mSerialPortDeviceChecksum.c_str(), sizeof(char), mSerialPortDeviceChecksum.length(), fp);

    fclose(fp);
}

bool Container::shouldRecreateWithOptDevice()
{
    std::string path = mContainerPath + "/.opt_device_bitmask";
    char buff[BUF_SIZE] = {0};
    FILE *fp = nullptr;
    size_t size = 0;
    std::string str;
    std::string bitmaskString;
    bool recreate = true;

    fp = fopen(path.c_str(), "r");
    if (!fp) {
        return recreate;
    }

    size = fread(buff, sizeof(char), sizeof(buff), fp);
    if (size == 0) {
        goto out;
    }

    str = buff;

    refreshOptDeviceBitmask();
    bitmaskString = mDeviceBitmask.to_string('0', '1');

    if (str == bitmaskString) {
        recreate = false;
    }

out:
    if (fp) {
        fclose(fp);
    }

    return recreate;
}

bool Container::shouldRecreateWithSerialPortDevice()
{
    std::string path = mContainerPath + "/.serial_port_device_checksum";
    char buff[BUF_SIZE] = {0};
    FILE* fp = nullptr;
    size_t size = 0;
    std::string str;
    bool recreate = true;

    fp = fopen(path.c_str(), "r");
    if (!fp) {
        return recreate;
    }

    size = fread(buff, sizeof(char), sizeof(buff), fp);
    if (size == 0) {
        goto out;
    }

    str = buff;

    refreshSerialPortDeviceChecksum();
    if (str == mSerialPortDeviceChecksum) {
        recreate = false;
    }

out:
    if (fp) {
        fclose(fp);
    }

    return recreate;
}

bool Container::shouldRecreate()
{
    bool recreate = true;

    recreate = shouldRecreateWithNetworkMode();// this func must be called

    recreate |= shouldRecreateWithOptDevice() ||
        shouldRecreateWithSerialPortDevice() ||
        shouldRecreateWithCgroupns();

    if (recreate) {
        makeConfiguration();
    }

    return recreate;
}

bool Container::usesAshmemDevice()
{
    return mDeviceBitmask.test(CONTAINER_DEVICE_ASHMEM);
}

void Container::checkDockerVersion()
{
    unsigned int clientVersion = 0;
    unsigned int serverVersion = 0;

    clientVersion = dockerClientVersion();
    serverVersion = dockerServerVersion();

    mUsePrivateCgroupns =
        (clientVersion >= DOCKER_VERSION(20, 10, 0)) &&
        (serverVersion >= DOCKER_VERSION(20, 10, 0));
}

void Container::updateCgroupnsMode()
{
    mCgroupnsMode = getContainerCgroupnsMode(mContainerName);
}

bool Container::shouldRecreateWithCgroupns()
{
    if (mUsePrivateCgroupns) {
        updateCgroupnsMode();
        return mCgroupnsMode != "private";
    }

    return false;
}

std::string Container::getNetworkModeSetting()
{
    std::string setting = "default";

    // get network mode setting
    std::string mode = kmre::getIniSetting(mSettingFile.c_str(), "network", "mode", "default");
    if ((mode == "bridge") || (mode == "host")) {
        setting = mode;
    }

    syslog(LOG_DEBUG, "Container network mode setting: '%s'.", setting.c_str());
    return setting;
}

std::string Container::getCurrentNetworkMode()
{
    std::string mode = "default";
    std::vector<std::string> cmd;
    std::vector<std::string> output;

    cmd.push_back(dockerPath);
    cmd.push_back("inspect");
    cmd.push_back("--format='{{.HostConfig.NetworkMode}}'");
    cmd.push_back(mContainerName);

    if (ForkExecvp(cmd, output) == 0) {
        if (output.size() > 0) {
            std::string tmp = output[0];
            if ((tmp == "bridge") || (tmp == "host")) {
                mode = tmp;
            }
        }
    }

    syslog(LOG_DEBUG, "Current container network mode: '%s'.", mode.c_str());
    return mode;
}

bool Container::shouldRecreateWithNetworkMode()
{
    mCurrentNetworkMode = getCurrentNetworkMode(),
    mNewNetworkMode = getNetworkModeSetting();

    // default == bridge
    if (((mNewNetworkMode == "host") && (mCurrentNetworkMode != "host")) ||
        ((mCurrentNetworkMode == "host") && (mNewNetworkMode != "host"))) {
        syslog(LOG_DEBUG, "Container network mode changed to '%s'.", mNewNetworkMode.c_str());
        return true;
    }

    return false;
}

void Container::updateNetworkMode()
{
    mCurrentNetworkMode = mNewNetworkMode;

    // delete container virtual network device 'wlan0' after network mode switched to 'bridge'
    const char* containerVirtualNetworkDevice = "wlan0";
    if (mCurrentNetworkMode != "host") {
        // get network device setting
        std::string device = kmre::getIniSetting(mSettingFile.c_str(), "network", "device");
        if (!device.empty()) {
            std::string device_mac = kmre::getMacAddressByInterface(device.c_str());
            std::string wlan0_mac = kmre::getMacAddressByInterface(containerVirtualNetworkDevice);
            if ((!wlan0_mac.empty()) && (device_mac == wlan0_mac)) {
                syslog(LOG_INFO, "Try to delete container virtual network device '%s'.", containerVirtualNetworkDevice);
                
                std::vector<std::string> cmd;
                cmd.push_back("/usr/bin/ip");
                cmd.push_back("link");
                cmd.push_back("delete");
                cmd.push_back(containerVirtualNetworkDevice);

                if (ForkExecvp(cmd) != 0) {
                    syslog(LOG_ERR, "Failed to delete container virtual network device '%s'.", containerVirtualNetworkDevice);
                }
            }
        }
    }
}

} // namespace container
} // namespace kmre
