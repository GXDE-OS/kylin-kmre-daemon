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

#ifndef _KMRE_LOCK_FILE_H_
#define _KMRE_LOCK_FILE_H_

#define LOCKFILE_PREFIX "/var/lib/kmre/.lock"

#ifdef __cplusplus
extern "C" {
#endif

int test_lockfile(const char* path);
void slash_to_underline(const char* in, char* out);

#ifdef __cplusplus
}
#endif

#endif // _KMRE_LOCK_FILE_H_
