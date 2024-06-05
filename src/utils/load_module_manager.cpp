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

#include "utils/load_module_manager.h"
#include "utils/load_module_task.h"

namespace kmre {
namespace utils {

LoadModuleManager::Garbo LoadModuleManager::garbo;
std::mutex LoadModuleManager::lock;
LoadModuleManager* LoadModuleManager::m_pInstance = nullptr;

LoadModuleManager* LoadModuleManager::getInstance()
{
    if (nullptr == m_pInstance) {
        std::lock_guard<std::mutex> _l(lock);
        if (nullptr == m_pInstance) {
            m_pInstance = new LoadModuleManager;
        }
    }

    return m_pInstance;
}

LoadModuleManager::LoadModuleManager()
{

}

LoadModuleManager::~LoadModuleManager()
{
    std::lock_guard<std::mutex> _l(mLock);
    std::vector<LoadModuleTask*>::iterator iter = mTasks.begin();
    while (iter != mTasks.end()) {
        (*iter)->wait();
        delete *iter;
        iter++;
    }

    mTasks.clear();
}

void LoadModuleManager::loadModule(const std::string &module)
{
    LoadModuleTask* task = new LoadModuleTask(module);

    {
        std::lock_guard<std::mutex> _l(mLock);
        mTasks.push_back(task);
    }

    task->start();

    usleep(10000);
    barrier();

    {
        std::lock_guard<std::mutex> _l(mLock);
        std::vector<LoadModuleTask*>::iterator iter = mTasks.begin();
        while (iter != mTasks.end()) {
            if ((*iter)->isFinished() == true) {
                (*iter)->wait();
                delete *iter;
                iter = mTasks.erase(iter);
            } else {
                iter++;
            }
        }
    }
}

} // namespace utils
} // namespace kmre
