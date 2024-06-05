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

#include "dbus-daemon-proxy.h"
#include "utils.h"

namespace kmre {

DBusDaemonProxy::DBusDaemonProxy(DBus::Connection &connection)
    : DBus::InterfaceProxy("org.freedesktop.DBus"),
      DBus::ObjectProxy(connection, "/org/freedesktop/DBus", "org.freedesktop.DBus")
{

}

bool DBusDaemonProxy::GetSenderUid(const std::string &sender, uint32_t &uid)
{
    DBus::CallMessage call;

    call.member("GetConnectionUnixUser");
    DBus::MessageIter writer = call.writer();

    writer << sender;

    try {
        DBus::Message reply = invoke_method(call);
        if (!reply.is_error()) {
            DBus::MessageIter reader = reply.reader();
            reader >> uid;
            return true;
        }
    } catch (DBus::Error& e) {
        ; // Do nothing
    }

    return false;
}

bool DBusDaemonProxy::GetSenderPid(const std::string &sender, uint32_t &pid)
{
    DBus::CallMessage call;

    call.member("GetConnectionUnixProcessID");
    DBus::MessageIter writer = call.writer();

    writer << sender;

    try {
        DBus::Message reply = invoke_method(call);
        if (!reply.is_error()) {
            DBus::MessageIter reader = reply.reader();
            reader >> pid;
            return true;
        }
    } catch (DBus::Error& e) {
        ; // Do nothing
    }

    return false;
}

bool DBusDaemonProxy::GetSenderComm(const std::string &sender, std::string &comm)
{
    uint32_t pid = 0;

    if (!GetSenderPid(sender, pid)) {
        return false;
    }

    return kmre::getProcessNameByPid(pid, comm);
}

} // namespace kmre
