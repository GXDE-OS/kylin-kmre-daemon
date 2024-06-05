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

#ifndef DBUSDAEMONPROXY_H
#define DBUSDAEMONPROXY_H

#include <dbus-c++/dbus.h>
#include <string>
#include <stdint.h>
#include <sys/types.h>

namespace kmre {

class DBusDaemonProxy : public DBus::InterfaceProxy, public DBus::ObjectProxy
{
public:
    DBusDaemonProxy(DBus::Connection &connection);

    bool GetSenderPid(const std::string &sender, uint32_t &pid);
    bool GetSenderUid(const std::string &sender, uint32_t &uid);
    bool GetSenderComm(const std::string &sender, std::string &comm);
};

} // namesapce kmre

#endif // DBUSDAEMONPROXY_H
