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

#include "utils.h"
#include "rfkill_unblock_task.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syslog.h>
#include <stdio.h>

static const std::string RFKILL_PATH = "/usr/sbin/rfkill";

namespace kmre {
namespace utils {

RfkillUnblockTask::RfkillUnblockTask(uint32_t index)
    : AsyncTask("RfkillUnblock")
    , mIndex(index)
{

}

RfkillUnblockTask::~RfkillUnblockTask()
{

}

void RfkillUnblockTask::makeCommand()
{

    mCommand.clear();
    mCommand.push_back(RFKILL_PATH);
    mCommand.push_back("unblock");
    mCommand.push_back(std::to_string(mIndex));
}

} // namespace utils
} // namespace kmre
