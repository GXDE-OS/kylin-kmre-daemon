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

#ifndef KMRE_CONTAINER_MANAGER_H
#define KMRE_CONTAINER_MANAGER_H

#include <dirent.h>
#include <string>
#include <stdint.h>
#include <memory>
#include <thread>
#include <atomic>
#include <map>

#include "utils.h"
#include "container.h"
#include "image-info.h"
#include "property-map.h"

namespace kmre {

class KmreServer;
class RfkillProcessor;

namespace container {

struct ContainerInfo
{
    std::string name;
    std::string imageRepo;
    std::string imageTag;

    void toJson(Json::Value &value)
    {
        value["name"] = Json::Value(name);
        value["repo"] = Json::Value(imageRepo);
        value["tag"] = Json::Value(imageTag);
    }
};

class ContainerManager
{
public:

    friend class Container;

    ContainerManager(KmreServer* server);
    ~ContainerManager();

    int32_t StartContainer(const std::string& userName, int32_t uid, int32_t width, int32_t height);
    int32_t StartContainerSilently(const std::string& userName, int32_t uid, int32_t width = 1920, int32_t height = 1080);
    int32_t ChangeContainerRuntimeStatus(const std::string& userName, int32_t uid);
    int32_t StopContainer(const std::string& userName, int32_t uid);
    void SetFocusOnContainer(const std::string& userName, const int32_t& uid, const int32_t& onFocus);
    void SetPropOfContainer(const std::string& userName, const int32_t& uid, const std::string& prop, const std::string& value);
    void SetDefaultPropOfContainer(const std::string& userName, const int32_t& uid, const std::string& prop, const std::string& value);
    std::string GetPropOfContainer(const std::string& userName, const int32_t& uid, const std::string prop);
    std::string GetDefaultPropOfContainer(const std::string& userName, const int32_t& uid, const std::string prop);
    std::string GetContainerNetworkInformation(const std::string& userName, const int32_t& uid);
    void SetGlobalEnvironmentVariable(const std::string &key, const std::string &value);
    void LoadImage();
    bool IsImageReady();

    std::string GetAllImages();
    std::string GetAllContainers();
    std::string GetCurrentContainerAndImage();
    bool RemoveOneImage(const std::string &container, const std::string &image);
    void ComponentsUpgrade(const std::string &args);

private:


    std::vector<ContainerInfo> ListContainerInfo(bool listAll = true);
    std::shared_ptr<Container> findContainer(const std::string& containerName);
    bool insertContainer(const std::string& containerName, const std::string& image, bool privileged = false);
    void initializeContainers();
    void stopOtherContainer(const std::string& containerName);
    int32_t stopContainer(const std::string& containerName, bool shouldEmit = false);
    void destroyContainer(const std::string& containerName);
    void createContainer(const std::string& containerName);
    int32_t inspectContainer(const std::string& containerName, const std::string& format, std::vector<std::string>& output);
    int32_t startContainer(const std::string& containerName, int32_t width, int32_t height);
    int32_t exclusivelyStartContainer(const std::string& containerName, int32_t width, int32_t height);
    void setPropOfContainer(const std::string& containerName, const std::string& prop, const std::string& value);
    std::string getPropOfContainer(const std::string& containerName, const std::string& prop);
    void loadImageProcessor();
    void loadImage(const std::string& imagePath);
    std::vector<ImageInfo> listImageInfo();
    std::vector<ImageMeta> listAllImagesDescriptions();
    bool isContainerRunning(const std::string& containerName);

    // Every image and container has its own overlay directories, under which some executable programs should be labeled.
    void getOverlayDirectoriesForImage();
    void getOverlayDirectoriesForContainers();
    void checkAndAddOverlayDirectory(const std::string& path, std::set<std::string>& overlayDirectories, bool update);

    // for image check
    const std::string& GetImageRepo();
    const std::string& GetImageTag();
    const std::string& GetImageVersion();
    bool isImageConfigurationReady();

    // Stop running kydroid containers
    std::vector<std::string> runningKydroidContainers();
    void stopKydroidContainers();

    std::string mImageRepo;
    std::string mImageTag;
    std::string mImageVersion;
    std::string mCurrentRunningContainer;
    std::vector<std::shared_ptr<Container>> mContainers;
    KmreServer* mServer;
    std::thread *mThreadLoadImage;
    std::atomic<bool> mImageLoading;
    bool mStopLoading;
    std::map<std::string, PropertyMap*> mPropertiesMaps;
    RfkillProcessor* mRfkillProcessor;
    PropertyMap mGlobalEnv;

    // all overlay directories
    std::set<std::string> mAllOverlayDirectories;

    // overlay directories for newly loaded image.
    std::set<std::string> mImageOverlayDirectories;

    // overlay directories for newly created container
    std::set<std::string> mContainerOverlayDirectories;

};

} // namespace container
} // namespace kmre

#endif // KMRE_CONTAINER_MANAGER_H
