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

#ifndef KMRE_CONTAINER_UTILS_H
#define KMRE_CONTAINER_UTILS_H

#include <string>

#define DOCKER_VERSION(a, b, c) ((a)*65536 + (b)*256 + (c))

namespace kmre {
namespace container {

struct ContainerNetworkInfo
{
    std::string mode;
    std::string ipAddress;
    std::string gateway;
};

// For start container silently
int getNumberOfCpus();
int updateContainerCpuNumber(const std::string& containerName, int num);

std::string inspectOverlayDirectories(const std::string& obj, const std::string& type);
std::string inspectOverlayDirectories(const std::string& obj);

std::string getDockerStorageDriver();

bool getContainerNetworkInformation(const std::string& containerName, ContainerNetworkInfo& info);
std::string getContainerCgroupnsMode(const std::string& containerName);

int mountFixedDirectories(const std::string& containerName);
void mountSharedBufferDirectory(const std::string& containerName);
void unmountLegacyFixedDirectories(const std::string &userName, const int32_t& uid);
void unmountFixedDirectories(const std::string& containerName);

unsigned int dockerClientVersion();
unsigned int dockerServerVersion();

} // namespace container
} // namespace kmre

#endif // KMRE_CONTAINER_UTILS_H
