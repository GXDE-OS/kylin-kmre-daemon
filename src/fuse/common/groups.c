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

#include "groups.h"

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <grp.h>

int get_groups_from_uid(uid_t uid, gid_t group, gid_t* groups, int* ngroups)
{
    char buf[1024];
    struct passwd pwd;
    struct passwd* result = NULL;

    if (ngroups == NULL) {
        return -1;
    }

    if (getpwuid_r(uid, &pwd, buf, sizeof(buf), &result) != 0) {
        *ngroups = 0;
        return -1;
    }

    if (getgrouplist(pwd.pw_name, group, groups, ngroups) < 0) {
        return -1;
    }

    return 0;
}
