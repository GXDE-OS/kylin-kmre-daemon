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

#ifndef _KMRE_SERVER_H_
#define _KMRE_SERVER_H_

#include <dbus-c++/dbus.h>
#include "kmre-server-glue.h"
#include "container/container_manager.h"
#include "dbus-daemon-proxy.h"
#include "systemd-service-proxy.h"
#include "kydroid-daemon-proxy.h"

#define KMRE_SERVER_NAME  "cn.kylinos.Kmre"
#define KMRE_SERVER_PATH  "/cn/kylinos/Kmre"

namespace kmre {

class KmreServer
    : public cn::kylinos::Kmre_adaptor,
    public DBus::IntrospectableAdaptor,
    public DBus::ObjectAdaptor
{
public:

    KmreServer(DBus::Connection &connection);
    ~KmreServer();

    virtual int32_t Prepare(const std::string& userName, const int32_t& uid) override;
    virtual int32_t StartContainer(const std::string& userName, const int32_t& uid, const int32_t& width, const int32_t& height) override;
    virtual int32_t StartContainerSilently(const std::string& userName, const int32_t& uid) override;
    virtual int32_t ChangeContainerRuntimeStatus(const std::string& userName, const int32_t& uid) override;
    virtual int32_t StopContainer(const std::string& userName, const int32_t& uid) override;
    virtual void SetFocusOnContainer(const std::string& userName, const int32_t& uid, const int32_t& onFocus) override;
    virtual void SetPropOfContainer(const std::string& userName, const int32_t& uid, const std::string& prop, const std::string& value) override;
    virtual std::string GetPropOfContainer(const std::string& userName, const int32_t& uid, const std::string& prop) override;
    virtual void SetDefaultPropOfContainer(const std::string& userName, const int32_t& uid, const std::string& prop, const std::string& value) override;
    virtual std::string GetDefaultPropOfContainer(const std::string& userName, const int32_t& uid, const std::string& prop) override;
    virtual std::string GetContainerNetworkInformation(const std::string& userName, const int32_t& uid) override;
    virtual void SetGlobalEnvironmentVariable(const std::string &key, const std::string &value) override;
    virtual void LoadImage() override;
    virtual uint32_t IsImageReady() override;
    virtual std::map< std::string, std::string > GetAllContainersAndImages(const std::string& user, const int32_t& uid) override;
    virtual bool SwitchImage(const std::string& repo, const std::string& tag) override;
    virtual bool RemoveOneContainer(const std::string& container) override;
    virtual bool RemoveOneImage(const std::string& container, const std::string& image) override;
    virtual void ComponentsUpgrade(const std::string &args) override;

private:
    friend class container::ContainerManager;

    int32_t _Prepare(const std::string& userName, const int32_t& uid);
    void prepareData(const std::string& containerPath);

    /*
    for dbus method call. Containerd and dockerd should be on for some call.
    method                                 need containerd and dockerd                 comment
    ------------------------------------------------------------------------------------------------------------------
    SetDefaultPropOfContainer              no
    GetDefaultPropOfContainer              no
    SetPropOfContainer                     no
    Prepare                                no
    GetPropOfContainer                     no
    SetGlobalEnvironmentVariable           no
    SetFocusOnContainer                    no
    StopContainerer                        no                                          but should always emit signal?
    SwitchImage                            no                                          for now (not implemented)
    IsImageReady                           yes
    StartContainerSilently                 yes
    ChangeContainerRuntimeStatus           yes
    LoadImage                              yes
    StartContainer                         yes
    GetAllContainersAndImages              yes
    RemoveOneContainer                     yes
    RemoveOneImage                         yes
    */

    void checkCallerAllowed(const std::string &method, const std::vector<std::string>& whiteList);
    bool checkEnviron(int pid);
    bool checkWhiteList(int pid, const std::vector<std::string>& whiteList);
    void checkAndLogDBusSender(const std::string &method);
    bool checkServices();
    bool checkServiceStatusAndStart(const std::string &serviceName);
    bool serviceExists(const std::string &serviceName);
    bool isServiceRunning(const std::string &serviceName);

    bool stopKydroidContainer(const std::string& user, int32_t& uid);

    container::ContainerManager *mContainerManager;
    std::string mRunningContainer;
    bool mKernelSupported;
    DBusDaemonProxy mDBusDaemonProxy;
    SystemdManagerProxy mSystemdManagerProxy;
    KydroidDaemonProxy mKydroidDaemonProxy;

};

} // namespace kmre

#endif // _KMRE_SERVER_H_
