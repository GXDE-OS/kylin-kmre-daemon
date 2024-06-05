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
#include "async_task.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syslog.h>
#include <stdio.h>


namespace kmre {
namespace utils {

AsyncTask::AsyncTask(const std::string& taskName)
    : mPid(0)
    , mIsFinished(false)
    , mTaskName(taskName)
{

}

AsyncTask::~AsyncTask()
{
    this->wait();
}

void AsyncTask::wait()
{
    if (mThread.joinable()) {
        mThread.join();
    }
}

void AsyncTask::start()
{
    mIsFinished = false;
    mThread = std::thread(&AsyncTask::run, this);
}

int AsyncTask::doWork()
{
    int status = 0;
    int ret = -1;

    if (mCommand.size() == 0) {
        goto out;
    }

    mPid = ForkExecvpAsync(mCommand);
    if (mPid == -1) {
        goto out;
    }

    while (true) {
        if (waitpid(mPid, &status, WNOHANG) == mPid) {
            if (WIFEXITED(status)) {
                ret = (WEXITSTATUS(status) == 0) ? 0 : -1;
                break;
            } else {
                break;
            }
        }

        usleep(500000);
    }

out:
    mIsFinished = true;

    return ret;
}

void AsyncTask::run()
{
    int ret = 0;

    makeCommand();

    //syslog(LOG_DEBUG, "AsyncTask: Start async task %s.", mTaskName.c_str());
    ret = doWork();
    if (ret != 0) {
        //syslog(LOG_WARNING, "AsyncTask: Async task %s returns %d.", mTaskName.c_str(), ret);
    } else {
        //syslog(LOG_INFO, "AsyncTask: Async task %s is done.", mTaskName.c_str());
    }

}

} // namespace utils
} // namespace kmre
