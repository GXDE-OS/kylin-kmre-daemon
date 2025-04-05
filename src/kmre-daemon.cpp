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

#include "kmre-server.h"
#include "utils.h"

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <limits.h>
#include <sys/stat.h>

#include <sys/syslog.h>
#include <sys/prctl.h>

#include <thread>

#define LOG_IDENT "KMRE_kylin-kmre-daemon"

static const std::string DKMS_MODULE_BINDER_KMRE = "kmre-binder";
static const std::string DKMS_MODULE_BINDER = "binder_linux";
static const std::string DKMS_MODULE_ASHMEM = "kmre-ashmem";
static const std::string DKMS_MODULE_VIRTWIFI = "kmre-virtwifi";
static const std::string KERNEL_MODULE_VIRTWIFI = "virt_wifi";
static const std::string KERNEL_MODULE_ASHMEM = "ashmem_linux";
static const std::string BINDER_PATH = "/dev/binder";

using kmre::isPathCharDevice;
using kmre::loadModule;
using kmre::isKernelModuleLoaded;

static void try_load_binder_module()
{
    if (!isPathCharDevice("/dev/binder") || !isPathCharDevice("/dev/hwbinder") || !isPathCharDevice("/dev/vndbinder")) {
        loadModule(DKMS_MODULE_BINDER);
	loadModule("binder");
        loadModule(DKMS_MODULE_BINDER_KMRE);
    }
}

static void try_load_ashmem_module() {
    if (!isPathCharDevice("/dev/ashmem")) {
        loadModule(DKMS_MODULE_ASHMEM);
    }

    usleep(1 * 1000 * 1000);

    if (!isPathCharDevice("/dev/ashmem")) {
        loadModule(KERNEL_MODULE_ASHMEM);
    }
}

static void try_load_virtwifi_module() {
    usleep(500 * 1000);
    prctl(PR_SET_NAME, "load-virtwifi");

    if (isKernelModuleLoaded("kmre_virtwifi") || isKernelModuleLoaded("virt_wifi")) {
        return;
    }

    usleep(2 * 1000 * 1000); // Delayed for 2 seconds.

    if (!isKernelModuleLoaded("cfg80211")) {
        loadModule("cfg80211");
        usleep(1 * 1000 * 1000);
    }

    if (!isKernelModuleLoaded("kmre_virtwifi")) {
        loadModule(DKMS_MODULE_VIRTWIFI);
    }

    usleep(1 * 1000 * 1000);

    if ((!isKernelModuleLoaded("kmre_virtwifi"))) {
        loadModule(KERNEL_MODULE_VIRTWIFI);
    }
}

static void prepareTracefs()
{
    if (!kmre::isPathMountedWithType("/sys/kernel/tracing", "tracefs")) {
        kmre::MountPath("/sys/kernel/tracing", "tracefs", "tracefs", 0, "nosuid,nodev,noexec");
    }

    if (!kmre::isPathMountedWithType("/sys/kernel/debug/tracing", "tracefs")) {
        kmre::MountPath("/sys/kernel/debug/tracing", "tracefs", "tracefs", 0, "nosuid,nodev,noexec");
    }
}

static DBus::BusDispatcher dispatcher;

int main(int argc, char** argv)
{
    struct stat sb;
    bool noDevice = false;

    openlog(LOG_IDENT, LOG_NDELAY | LOG_NOWAIT | LOG_PID, LOG_USER);

    DBus::default_dispatcher = &dispatcher;

    DBus::Connection conn = DBus::Connection::SystemBus();
    if (conn.has_name(KMRE_SERVER_NAME)) {
        closelog();
        return 0;
    }
    conn.request_name(KMRE_SERVER_NAME);

    syslog(LOG_DEBUG, "main: kylin-kmre-daemon is starting.");

    syslog(LOG_DEBUG, "main: Check and try to load necessary module.");
    try_load_binder_module();
    try_load_ashmem_module();

    std::thread t(try_load_virtwifi_module);
    t.detach();

    if (stat(BINDER_PATH.c_str(), &sb) < 0) {
        noDevice = true;
    } else {
        if (!S_ISCHR(sb.st_mode)) {
            noDevice = true;
        }
    }

    prepareTracefs();

    if (noDevice) {
        syslog(LOG_CRIT, "main: Failed to load binder module.");
    } else {
        syslog(LOG_INFO, "main: Binder module loaded.");
    }

    kmre::KmreServer server(conn);

    kmre::prepareModules();

    kmre::loadKernelConfigs();

    syslog(LOG_DEBUG, "main: kylin-kmre-daemon is running.");
    dispatcher.enter();

    closelog();
    return 0;
}
