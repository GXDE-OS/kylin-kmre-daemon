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

#include "rfkillprocessor.h"
#include "utils.h"

#include <linux/rfkill.h>
#include <sys/syslog.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <string>

#define _PATH_DEV_RFKILL "/dev/rfkill"

static int read_fully(int fd, void *buf, size_t len)
{
    if (!buf) {
        return -1;  // do not allow NULL buf in that implementation
    }
    size_t res = len;
    while (res > 0) {
        ssize_t stat = read(fd, (char *)(buf) + len - res, res);
        if (stat > 0) {
            res -= stat;
            continue;
        }
        if (stat == 0 || errno != EINTR) { // client shutdown or error
            return -1;
        }
    }
    return len;
}

static int read_fully_poll(int fd, void *buf, size_t len)
{
    struct pollfd pollfds[1];
    int timeout;
    int err;

    timeout = 200; // 200 milliseconds

    pollfds[0].fd = fd;
    pollfds[0].events = POLLIN | POLLPRI;

    err = poll(pollfds, 1, timeout);
    if (err <= 0) {
        // return error or timeout
        return err;
    }

    return read_fully(fd, buf, len);
}

static int write_fully(int fd, const void *buffer, size_t size)
{

    size_t res = size;
    int retval = 0;

    while (res > 0) {
        ssize_t stat = write(fd, (const char *)buffer + (size - res), res);
        if (stat < 0) {
            if (errno != EINTR) {
                retval =  stat;
                break;
            }
        } else {
            res -= stat;
        }
    }
    return retval;
}



namespace kmre {

RfkillProcessor::RfkillProcessor()
    : mStop(false)
    , mIsRunning(false)
    , mInitialized(false)
{

}

RfkillProcessor::~RfkillProcessor()
{
    this->stop();
    mRfkillHelper.closeDown();
    this->wait();
}

void RfkillProcessor::wait()
{
    if (mThread.joinable()) {
        mThread.join();
    }
}

void RfkillProcessor::stop()
{
    mStop = true;
}

void RfkillProcessor::closeDown()
{
    mRfkillHelper.closeDown();
}

void RfkillProcessor::start()
{
    if (!mInitialized) {
        return;
    }

    if (mIsRunning) {
        return;
    }

    mIsRunning = true;
    mStop = false;
    mThread = std::thread(&RfkillProcessor::run, this);
}

int RfkillProcessor::initialize()
{
    int ret;

    ret = mRfkillHelper.initialize();
    if (ret < 0) {
        return ret;
    }

    mInitialized = true;

    return 0;
}

void RfkillProcessor::run()
{
    int ret;
    struct rfkill_event event;

    if (!mInitialized) {
        goto out;
    }

    while (!mStop) {
        ret = mRfkillHelper.readOneEvent(event);
        if (ret < 0) {
            // error on read
            break;
        } else if (ret == 0) {
            // timeout
            continue;
        } else {
            mRfkillHelper.processEvent(event);
        }
    }

out:
    mIsRunning = false;
}

RfkillProcessor::RfkillHelper::RfkillHelper()
    : mReadOnlyFd(-1)
    , mWriteOnlyFd(-1)
{

}

RfkillProcessor::RfkillHelper::~RfkillHelper()
{
    closeDown();
}

int RfkillProcessor::RfkillHelper::initialize()
{
    if (mReadOnlyFd == -1) {
        mReadOnlyFd = rfkillReadOnlyOpen();
    }

    if (mWriteOnlyFd == -1) {
        mWriteOnlyFd = rfkillWriteOnlyOpen();
    }

    if (mReadOnlyFd < 0 || mWriteOnlyFd < 0) {
        closeDown();
        return -1;
    }

    return 0;
}

void RfkillProcessor::RfkillHelper::closeDown()
{
    if (mReadOnlyFd != -1) {
        close(mReadOnlyFd);
        mReadOnlyFd = -1;
    }

    if (mWriteOnlyFd != -1) {
        close(mWriteOnlyFd);
        mWriteOnlyFd = -1;
    }
}

int RfkillProcessor::RfkillHelper::rfkillReadOnlyOpen()
{
    int fd;

    fd = open(_PATH_DEV_RFKILL, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        syslog(LOG_ERR, "RfkillHelper: Failed to open %s with mode O_RDONLY", _PATH_DEV_RFKILL);
        return -1;
    }

    return fd;
}

int RfkillProcessor::RfkillHelper::rfkillWriteOnlyOpen()
{
    int fd;

    fd = open(_PATH_DEV_RFKILL, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        syslog(LOG_ERR, "RfkillHelper: Failed to open %s with mode O_WRONLY", _PATH_DEV_RFKILL);
        return -1;
    }

    return fd;
}

int RfkillProcessor::RfkillHelper::readOneEvent(struct rfkill_event& event)
{
    return read_fully_poll(mReadOnlyFd, &event, sizeof(struct rfkill_event));
}

bool RfkillProcessor::RfkillHelper::isDeviceVirtualByIndex(uint32_t index)
{
    return isRfkillVirtualDeviceByIndex(index);
}

bool RfkillProcessor::RfkillHelper::isDeviceWlan(const struct rfkill_event& event)
{
    return (event.type == RFKILL_TYPE_WLAN);
}

int RfkillProcessor::RfkillHelper::writeOneEvent(const struct rfkill_event& event)
{
    return write_fully(mWriteOnlyFd, &event, sizeof(struct rfkill_event));
}

int RfkillProcessor::RfkillHelper::unblockDeviceByIndex(uint32_t index)
{
    int ret;
    struct rfkill_event event;

    memset(&event, 0, sizeof(struct rfkill_event));

    event.op = RFKILL_OP_CHANGE;
    event.idx = index;
    event.soft = 0;

    ret = writeOneEvent(event);
    if (ret < 0) {
        rfkillUnblockDeviceByIndex(index);
    }

    return ret;
}

int RfkillProcessor::RfkillHelper::unblockDevice(const struct rfkill_event& event)
{
    if (event.soft == 0) {
        // No need to unblock this device
        return 0;
    }

    return unblockDeviceByIndex(event.idx);
}

bool RfkillProcessor::RfkillHelper::shouldUnblockDevice(const rfkill_event& event)
{
    return (isDeviceWlan(event) && isDeviceVirtualByIndex(event.idx));
}

void RfkillProcessor::RfkillHelper::processEvent(const struct rfkill_event& event)
{
    if (shouldUnblockDevice(event)) {
        unblockDevice(event);
    }
}

} // namespace kmre
