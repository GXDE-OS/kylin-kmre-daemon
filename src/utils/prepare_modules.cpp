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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/syslog.h>

#include <set>
#include <string>
#include <algorithm>
#include <map>
#include <memory>

#define PROC_MODULES_PATH "/proc/modules"
#define BUF_SIZE 1024

//#ifndef DEBUG_KERNEL_CONFIGS
//#define DEBUG_KERNEL_CONFIGS
//#endif

static const char neededModules[][64] = {
    "bluetooth",
    "configfs",
    "inet_diag",
    "ip6table_filter",
    "ip6table_mangle",
    "ip6table_raw",
    "ip6_tables",
    "ip6t_REJECT",
    "iptable_filter",
    "iptable_mangle",
    "iptable_mangle",
    "iptable_nat",
    "iptable_raw",
    "ip_tables",
    "ipt_MASQUERADE",
    "ipt_REJECT",
    "nf_conntrack",
    "nf_conntrack_ipv4",
    "nf_conntrack_ipv6",
    "nf_conntrack_netlink",
    "nf_defrag_ipv4",
    "nf_defrag_ipv6",
    "nf_defrag_ipv6",
    "nf_nat",
    "nf_nat_ipv4",
    "nf_nat_masquerade_ipv4",
    "nfnetlink",
    "nfnetlink_log",
    "nf_reject_ipv4",
    "nf_reject_ipv6",
    "tcp_diag",
    "x_tables",
    "xt_addrtype",
    "xt_CHECKSUM",
    "xt_connmark",
    "xt_conntrack",
    "xt_IDLETIMER",
    "xt_mark",
    "xt_NFLOG",
    "xt_owner",
    "xt_policy",
    "xt_TCPMSS",
    "xt_tcpudp",
    "xt_u32",
    "xt_bpf",
};

namespace kmre {

enum
{
    KERNEL_CONFIG_NO = 0,
    KERNEL_CONFIG_MODULE,
    KERNEL_CONFIG_YES,
};

static std::set<std::string> loadedModuleSet;

static std::set<std::string, std::greater<std::string> > kernelConfigsToCheck {
    "CONFIG_BPF",
    "CONFIG_HAVE_EBPF_JIT",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_JIT",
    "CONFIG_CGROUP_BPF",
    "CONFIG_NETFILTER_XT_MATCH_BPF",
};
static std::map<std::string, int> kernelConfigs;

static void updateModulesLoaded()
{
    FILE* fp = nullptr;
    char line[1024] = {0};

    fp = fopen(PROC_MODULES_PATH, "r");
    if (fp == nullptr) {
        return;
    }

    while (fgets(line, sizeof(line), fp) != nullptr) {
        char* p = line;
        while (p != nullptr && *p != '\0' && !isspace(*p)) {
            p++;
        }

        *p = '\0';
        loadedModuleSet.insert(line);
    }

    fclose(fp);
}

static bool shouldLoadModule(const char* module)
{
    std::set<std::string>::const_iterator it = loadedModuleSet.find(module);
    return (it == loadedModuleSet.end());
}

static void checkAndLoadModule(const char* module)
{
    if (shouldLoadModule(module)) {
        loadModule(module);
        usleep(10000);
        updateModulesLoaded();
    }
}

bool isKernelModuleLoaded(const std::string& moduleName)
{
    updateModulesLoaded();
    return !shouldLoadModule(moduleName.c_str());
}

bool isVirtWifiModuleLoaded()
{
    static bool moduleLoaded = false;

    if (moduleLoaded) {
        return true;
    }

    moduleLoaded = (isKernelModuleLoaded("kmre_virtwifi") || isKernelModuleLoaded("virt_wifi"));
    return moduleLoaded;
}

void prepareModules()
{
    unsigned int i = 0;

    updateModulesLoaded();
    for (i = 0; i < sizeof(neededModules) / 64; i++) {
        checkAndLoadModule(neededModules[i]);
    }
}

#ifdef DEBUG_KERNEL_CONFIGS
void dumpKernelConfigs()
{
    std::map<std::string, int>::const_iterator it = kernelConfigs.begin();
    while (it != kernelConfigs.end()) {
        syslog(LOG_DEBUG, "%s %d", it->first.c_str(), it->second);
        it++;
    }
}
#endif

void loadKernelConfigs()
{
    char path[1024] = {0};
    char buf[1024] = {0};
    struct utsname un;

    if (kernelConfigsToCheck.begin() == kernelConfigsToCheck.end()) {
        return;
    }

    if (uname(&un) != 0) {
        return;
    }

    snprintf(path, sizeof(path), "/boot/config-%s", un.release);

    std::unique_ptr<FILE, decltype(&fclose)> f(fopen(path, "r"), fclose);
    if (!f) {
        return;
    }

    FILE* fp = f.get();

    while (fgets(buf, sizeof(buf), fp)) {
        if (strncmp(buf, "CONFIG", 6) != 0) {
            continue;
        }

        std::set<std::string>::iterator it = kernelConfigsToCheck.begin();
        if (it == kernelConfigsToCheck.end()) {
            break;
        }

        while (it != kernelConfigsToCheck.end()) {
            size_t len = strlen((*it).c_str());
            if (strncmp(buf, (*it).c_str(), len) == 0) {
                if (len + 2 < sizeof(buf)) {
                    if (buf[len] == '=') {
                        if (buf[len + 1] == 'y') {
                            kernelConfigs.insert({ *it, KERNEL_CONFIG_YES });
                        } else if (buf[len + 1] == 'm') {
                            kernelConfigs.insert({ *it, KERNEL_CONFIG_MODULE });
                        } else {
                            kernelConfigs.insert({ *it, KERNEL_CONFIG_NO });
                        }
                        it = kernelConfigsToCheck.erase(it);
                        break;
                    }
                }
            }

            it++;
        }
    }

    std::set<std::string>::iterator it = kernelConfigsToCheck.begin();
    while (it != kernelConfigsToCheck.end()) {
        kernelConfigs.insert({ *it, KERNEL_CONFIG_NO });
        it++;
    }

#ifdef DEBUG_KERNEL_CONFIGS
    dumpKernelConfigs();
#endif

    kernelConfigsToCheck.clear();
}

static bool _isKernelConfigEnabled(const std::string& config)
{
    std::map<std::string, int>::const_iterator it = kernelConfigs.find(config);
    if (it != kernelConfigs.end()) {
        return it->second >= KERNEL_CONFIG_MODULE;
    }

    return false;
}

bool isKernelConfigEnabled(const std::string& config)
{
    std::map<std::string, int>::const_iterator it = kernelConfigs.find(config);
    if (it == kernelConfigs.end()) {
        kernelConfigsToCheck.insert(config);
        loadKernelConfigs();
    } else {
        return it->second >= KERNEL_CONFIG_MODULE;
    }

    return _isKernelConfigEnabled(config);
}

static uint32_t _kernelVersion()
{
    struct utsname buf;
    int ret = uname(&buf);
    if (ret) {
        return 0;
    }

    uint32_t kver_major;
    uint32_t kver_minor;
    uint32_t kver_sub;
    char dummy;
    ret = sscanf(buf.release, "%u.%u.%u%c", &kver_major, &kver_minor, &kver_sub, &dummy);
    if (ret < 3) {
        return 0;
    }

    return KVER(kver_major, kver_minor, kver_sub);
}

uint32_t kernelVersion()
{
    static uint32_t kver = _kernelVersion();
    return kver;
}

} // namespace kmre
