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

#ifndef KMRE_CONTAINER_CONTAINER_H
#define KMRE_CONTAINER_CONTAINER_H

#include <stdint.h>
#include <string>
#include <vector>
#include <list>
#include <utility>
#include <map>
#include <bitset>
#include <set>

#define OPTIONAL_DEVICE_MAX 20

namespace kmre {
namespace container {

class ContainerManager;

class Container
{
public:

    struct Specification
    {
        std::string spec;
        std::string perm;
    };

    struct TmpfsSpec
    {
        std::string dest;
        std::string mode;
        uint32_t size;
    };

    struct BindMount
    {
        std::string source;
        std::string target;
        std::string propagation;
    };

    struct OptDevice
    {
        std::string pathOnHost;
        std::string pathOnContainer;
        std::string perm;
        uint32_t bitIndex;
        int fileType;
    };

    struct ContainerConfiguration
    {
        std::vector<std::pair<std::string, Specification> > devices;
        std::vector<std::pair<std::string, Specification> > volumes;
        std::vector<TmpfsSpec> tmpfs;
        std::vector<BindMount> bindMounts;
    };

    Container(const std::string& userName, int32_t uid, const std::string image, ContainerManager& manager, bool privileged = false);
    ~Container();

    static int32_t start(const std::string &containerName);
    int32_t start();
    int32_t stop();
    int32_t create();
    bool shouldRecreate();
    void setImage(const std::string& image) { mImageVersion = image; }
    std::string getImage() { return mImageVersion; }
    std::string getContainerName() { return mContainerName; }
    std::string getNetworkMode() {return mCurrentNetworkMode;}

    bool usesAshmemDevice();

private:
    void addDeviceConf(const std::string& device, const std::string& containerDevice, const std::string perm = std::string("rwm"));
    void addDeviceConfIfExist(const std::string& device, const std::string& containerDevice, int fileType, const std::string perm = std::string("rwm"));
    void addDeviceConfIfExist(const OptDevice& optDevice);
    void addVolumeConf(const std::string& volume, const std::string& containerVolume, const std::string perm = std::string("rw"));
    void addTmpfsConf(const std::string &dest, const std::string &mode, uint32_t size);
    void addBindMountConf(const std::string &source, const std::string &target, const std::string &propagation);
    void makeConfiguration();
    void makeCreateCommand(std::vector<std::string>& cmd);
    void initializeOptDevices();
    void initializeSerialPortDevices();
    void refreshOptDeviceBitmask();
    void refreshSerialPortDeviceChecksum();
    void writeOptDeviceBitmask();
    void writeSerialPortDeviceChecksum();
    bool shouldRecreateWithOptDevice();
    bool shouldRecreateWithSerialPortDevice();

    void checkDockerVersion();
    void updateCgroupnsMode();
    bool shouldRecreateWithCgroupns();
    bool shouldRecreateWithNetworkMode();
    void updateNetworkMode();
    std::string getNetworkModeSetting();
    std::string getCurrentNetworkMode();

    std::string mUserName;
    int32_t mUid;
    std::string mContainerPath;
    std::string mContainerName;
    std::string mImageVersion;
    bool mPrivileged;
    ContainerConfiguration mConfig;
    std::bitset<OPTIONAL_DEVICE_MAX> mDeviceBitmask;
    std::map<std::string, OptDevice> mOptDevices;
    ContainerManager& mContainerManager;
    std::string mUpperDir;

    std::string mSerialPortDeviceChecksum;
    std::set<std::string> mSerialPortDevices;

    bool mUsePrivateCgroupns;
    std::string mCgroupnsMode;
    std::string mNewNetworkMode;
    std::string mCurrentNetworkMode;
    const std::string mSettingFile;

};

} // namespace container
} // namespace kmre

#endif // KMRE_CONTAINER_CONTAINER_H
