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

#ifndef KMRE_DAEMON_RFKILL_PROCECCOR_H
#define KMRE_DAEMON_RFKILL_PROCECCOR_H

#include <thread>

#include <linux/rfkill.h>

namespace kmre {

class RfkillProcessor
{
public:

    RfkillProcessor();
    ~RfkillProcessor();

    int initialize();
    void start();
    void stop();
    void closeDown();
    void wait();

private:

    class RfkillHelper
    {
    public:
        RfkillHelper();
        ~RfkillHelper();

        int initialize();
        void closeDown();

        int readOneEvent(struct rfkill_event& event);
        void processEvent(const struct rfkill_event& event);

    private:
        bool isDeviceVirtualByIndex(uint32_t index);
        bool isDeviceWlan(const struct rfkill_event& event);
        bool shouldUnblockDevice(const struct rfkill_event& event);
        int unblockDeviceByIndex(uint32_t index);
        int unblockDevice(const struct rfkill_event& event);
        int rfkillReadOnlyOpen();
        int rfkillWriteOnlyOpen();
        int writeOneEvent(const struct rfkill_event& event);

        int mReadOnlyFd;
        int mWriteOnlyFd;
    };

    void run();

    std::thread mThread;
    bool mStop;
    bool mIsRunning;
    bool mInitialized;
    RfkillHelper mRfkillHelper;

};

}

#endif // KMRE_DAEMON_RFKILL_PROCECCOR_H
