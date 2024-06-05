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

#include "lock_file.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>


static int open_lockfile(const char* path)
{
    int fd;
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if(fd < 0) {
        return fd;
    }
    fchmod(fd, 0644);

    return fd;
}

static int try_lockfile(int fd)
{
    int ret;

    ret = flock(fd, LOCK_EX | LOCK_NB);

    return ret;
}

int test_lockfile(const char* path)
{
    int fd;
    int ret;

    fd = open_lockfile(path);
    if(fd < 0) {
        return -1;
    }

    ret = try_lockfile(fd);
    if(ret < 0) {
        close(fd);
        return -1;
    }

    return 0;
}

void slash_to_underline(const char* in, char* out)
{
    char* p;

    strcpy(out, in);

    p = out;
    while (*p != '\0') {
        if (*p == '/') {
            *p = '_';
        }
        ++p;
    }
}
