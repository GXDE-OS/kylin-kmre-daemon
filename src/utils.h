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

#ifndef _KMRE_UTILS_H_
#define _KMRE_UTILS_H_

#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>
#include <set>
#include <cstdint>

#if !defined(AID_MEDIA_RW)
#define AID_MEDIA_RW 1023
#endif

#define KVER(a, b, c) ((a)*65536 + (b)*256 + (c))

// DISALLOW_COPY_AND_ASSIGN disallows the copy and operator= functions. It goes in the private:
// declarations in a class.
#if !defined(DISALLOW_COPY_AND_ASSIGN)
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
    TypeName(const TypeName&) = delete;  \
    void operator=(const TypeName&) = delete
#endif

#define barrier() asm volatile("" : : : "memory")

namespace kmre {

enum {
    CPU_TYPE_UNKNOWN = -1,
    CPU_TYPE_MAX
};

std::vector<std::string> split(const std::string &s, char delim);

int32_t ForkExecvp(const std::vector<std::string>& args);
int32_t ForkExecvp(const std::vector<std::string>& args,
        std::vector<std::string>& output);
pid_t ForkExecvpAsync(const std::vector<std::string>& args);
int32_t ForkExecvpWithTimeout(const std::vector<std::string>& args, std::vector<std::string>& output, int timeout = -1);

std::string LegacyContainerPath(const std::string& user, const int32_t& uid);
std::string LegacyContainerName(const std::string& user, const int32_t& uid);
std::string LegacyContainerNameToPath(const std::string& name);
std::string ContainerPath(const std::string& user, const int32_t& uid);
std::string ContainerName(const std::string& user, const int32_t& uid);
std::string ContainerNameToPath(const std::string& name);

std::string ImageRepo();
std::string ImageTag();
std::string ImageVersion();

bool ParseContainerName(const std::string& containerName, std::string& userName, int32_t& uid);
std::string PrepareUserName(const std::string& userName);
bool ParseImageVersion(const std::string& imageVersion, std::string& repo, std::string& tag);

void CreateFile(const std::string& path, int mode);

bool isPathMounted(const std::string& path);
bool isPathMountedWithType(const std::string& path, const std::string& type);
int UnmountPathIfMounted(const std::string& path);
int32_t FuseMount(const std::string& destination, const std::string& source, int32_t uid, int32_t gid, int32_t set_uid, int32_t set_gid, bool allow_delete = false);
int32_t MountPath(const std::string& destination, const std::string& source, const std::string& fsType, const unsigned long flags, const std::string& options);
void unlinkFuseLockFile(const std::string& mountpoint);

typedef bool (*FileTypeCheckFunc)(const std::string& path, bool dereference);

bool isPathSymlink(const std::string& path, bool dereference = true);
bool isPathDir(const std::string& path, bool dereference = true);
bool isPathCharDevice(const std::string& path, bool dereference = true);
bool isPathRegularFile(const std::string& path, bool dereference = true);
bool isPathFileType(const std::string& path, mode_t fileType, bool dereference = true);
bool isPathReadable(const std::string& path);
bool pathExists(const std::string& path);

bool isKernelModuleLoaded(const std::string& moduleName);
bool isVirtWifiModuleLoaded();
void loadModule(const std::string& moduleName);
void prepareModules();

void rfkillUnblockDeviceByIndex(uint32_t index);
void rfkillUnblockAllVirtualDevices();
bool isRfkillVirtualDeviceByIndex(uint32_t index);

std::string sha512sum(const void* data, size_t size);

bool isStringValid(const std::string& str);
bool isUserNameValid(const std::string& userName);

std::string getHomePathFromUid(uid_t uid);

bool getProcessNameByPid(uint32_t pid, std::string &comm);

// check systemd services
int startSystemdService(const std::string &service);
int unmaskSystemdService(const std::string &service);

bool isRsyncAvailable();
int rsyncFilesUnderPath(const std::string& target, const std::string& source);

bool getSerialPortDevices(std::set<std::string>& serialPortDevices);

bool isFilesystemSupported(const std::string& fsType);
void loadKernelConfigs();
bool isKernelConfigEnabled(const std::string& config);
uint32_t kernelVersion();

bool isMemfdSupported();
std::string getIniSetting(const char* iniFile, const char* section, const char* key, const char* defaultSetting = "");
std::string getMacAddressByInterface(const char* interface);

} // namespace kmre

#endif // _KMRE_UTILS_H_
