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

#ifndef KMRE_UTILS_LOAD_MODULE_TASK_H
#define KMRE_UTILS_LOAD_MODULE_TASK_H

#include "utils/async_task.h"

namespace kmre {
namespace utils {

class LoadModuleTask : public AsyncTask {
public:
    LoadModuleTask(const std::string& module);
    ~LoadModuleTask();


private:
    std::string mModule;

    virtual void makeCommand() override;

    DISALLOW_COPY_AND_ASSIGN(LoadModuleTask);

};

} // namespace utils
} // namespace kmre

#endif  // KMRE_UTILS_LOAD_MODULE_TASK_H
