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

#ifndef KMRE_UTILS_ASYNC_TASK_H
#define KMRE_UTILS_ASYNC_TASK_H

#include <string>
#include <vector>
#include <thread>

namespace kmre {
namespace utils {


class AsyncTask {
public:
    AsyncTask(const std::string& taskName);
    virtual ~AsyncTask();

    void start();
    bool isFinished() { return mIsFinished; }
    void wait();

protected:
    virtual void makeCommand() = 0;
    std::vector<std::string> mCommand;

private:
    int doWork();
    void run();

    pid_t mPid;
    std::thread mThread;
    bool mIsFinished;
    std::string mTaskName;
};

} // namespace utils
} // namespace kmre


#endif //KMRE_UTILS_ASYNC_TASK_H
