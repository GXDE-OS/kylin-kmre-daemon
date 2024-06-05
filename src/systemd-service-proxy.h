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

#ifndef __DEMO_SYSTEMD_LISTEN_H
#define __DEMO_SYSTEMD_LISTEN_H

#include <dbus-c++/dbus.h>
#include <vector>
#include <set>
#include <map>
#include <string>
#include <atomic>

namespace kmre {

class SystemUnitProxy : public DBus::InterfaceProxy, public DBus::ObjectProxy
{
public:
    SystemUnitProxy(DBus::Connection& connection, const std::string& unitName, const DBus::Path& path);
    std::string GetPropertyValue(const std::string& interface, const std::string& property);

private:
    std::string mUnitName;
};

class SystemdManagerProxy : public DBus::InterfaceProxy, public DBus::ObjectProxy
{
public:
    SystemdManagerProxy(DBus::Connection &connection);

    bool GetUnitInformation(const std::string &unitName, DBus::Path &path, bool &isActive, std::string &loadState, std::string &activeState, std::string &subState);
    bool GetUnitInformationLegacy(const std::string &unitName, DBus::Path &path, bool &isActive, std::string &loadState, std::string &activeState, std::string &subState);

private:
    DBus::Path GetUnitPath(const std::string& unitName);

    std::map<std::string, DBus::RefPtr<SystemUnitProxy>> mUnits;
};

} // namespace kmre

#endif // __DEMO_SYSTEMD_LISTEN_H
