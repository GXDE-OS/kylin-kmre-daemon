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

#include "systemd-service-proxy.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

namespace kmre {

static const std::string kInterface = "org.freedesktop.systemd1.Unit";

SystemdManagerProxy::SystemdManagerProxy(DBus::Connection &connection)
    : DBus::InterfaceProxy("org.freedesktop.systemd1.Manager"),
      DBus::ObjectProxy(connection, "/org/freedesktop/systemd1", "org.freedesktop.systemd1")
{
}

DBus::Path SystemdManagerProxy::GetUnitPath(const std::string &unitName)
{
    DBus::Path path;
    DBus::CallMessage call;

    startSystemdService(unitName);

    call.member("GetUnit");
    DBus::MessageIter writer = call.writer();
    writer << unitName;

    try {
        DBus::Message reply = invoke_method(call);
        if (!reply.is_error()) {
            DBus::MessageIter reader = reply.reader();
            reader >> path;
        }
    } catch (DBus::Error& e) {
        ; // Do nothing
    }

    return path;
}

bool SystemdManagerProxy::GetUnitInformation(const std::string &unitName, DBus::Path &path, bool &isActive, std::string &loadState, std::string &activeState, std::string &subState)
{
    std::vector<DBus::Struct<
            std::string,
            std::string,
            std::string,
            std::string,
            std::string,
            std::string,
            DBus::Path,
            uint32_t,
            std::string,
            DBus::Path>> result;
    std::vector<std::string> unitNames;
    DBus::CallMessage call;

    unitNames.push_back(unitName);

    call.member("ListUnitsByNames");
    DBus::MessageIter writer = call.writer();
    writer << unitNames;

    try {
        DBus::Message reply = invoke_method(call);
        if (!reply.is_error()) {
            DBus::MessageIter reader = reply.reader();
            reader >> result;

            if (result.size() > 0) {
                loadState = result[0]._3;
                if (loadState == "loaded") {
                    path = result[0]._7;
                    activeState = result[0]._4;
                    subState = result[0]._5;
                    if (activeState == "active" && (subState == "running" || subState == "listening")) {
                        isActive = true;
                    } else {
                        isActive = false;
                    }

                    return true;
                }
            }
        }
    } catch (DBus::Error& e) {
        ; // Do nothing
    }

    return false;
}

bool SystemdManagerProxy::GetUnitInformationLegacy(const std::string &unitName, DBus::Path &path, bool &isActive, std::string &loadState, std::string &activeState, std::string &subState)
{
    DBus::Path unitPath;

    auto iter = mUnits.find(unitName);
    if (iter == mUnits.end()) {
        unitPath = GetUnitPath(unitName);
        if (unitPath.length() <= 0) {
            return false;
        }

        mUnits[unitName] = new SystemUnitProxy(conn(), unitName, unitPath);
        iter = mUnits.find(unitName);
        if (iter == mUnits.end()) {
            return false;
        }
    }

    loadState = (*iter).second->GetPropertyValue(kInterface, "LoadState");
    activeState = (*iter).second->GetPropertyValue(kInterface, "ActiveState");
    subState = (*iter).second->GetPropertyValue(kInterface, "SubState");

    if (loadState == "loaded") {
        if (activeState == "active" && (subState == "running" || subState == "listening")) {
            isActive = true;
        } else {
            isActive = false;
        }

        return true;
    }

    return false;
}

SystemUnitProxy::SystemUnitProxy(DBus::Connection &connection, const std::string& unitName, const DBus::Path &path)
    : DBus::InterfaceProxy("org.freedesktop.DBus.Properties"),
      DBus::ObjectProxy(connection, path, "org.freedesktop.systemd1"),
      mUnitName(unitName)
{
}

std::string SystemUnitProxy::GetPropertyValue(const std::string &interface, const std::string &property)
{
    DBus::Variant var;
    DBus::CallMessage call;

    call.member("Get");
    DBus::MessageIter writer = call.writer();
    writer << interface;
    writer << property;

    try {
        DBus::Message reply = invoke_method(call);
        if (!reply.is_error()) {
            DBus::MessageIter reader = reply.reader();
            reader >> var;
            std::string value = var;
            return value;
        }
    } catch (DBus::Error& e) {
        ; // Do nothing
    }

    return std::string();
}

} // namespace kmre
