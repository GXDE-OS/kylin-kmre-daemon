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

#include "kydroid-daemon-proxy.h"
#include "utils.h"

namespace kmre {

KydroidDaemonProxy::KydroidDaemonProxy(DBus::Connection &connection)
    : DBus::InterfaceProxy("cn.kylinos.Kydroid"),
      DBus::ObjectProxy(connection, "/cn/kylinos/Kydroid", "cn.kylinos.Kydroid")
{

}

bool KydroidDaemonProxy::StopContainer(const std::string &user, const int32_t &uid)
{
    DBus::CallMessage call;
    int result;
    int ret = false;

    call.member("StopContainer");
    DBus::MessageIter writer = call.writer();

    writer << user;
    writer << uid;

    try {
        DBus::Message reply = invoke_method(call);
        if (!reply.is_error()) {
            DBus::MessageIter reader = reply.reader();
            reader >> result;
            ret = true;
        }
    } catch (DBus::Error& e) {
        ; // Do nothing
    }

    return ret;
}

} // namespace kmre
