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

#include "utils/rfkill_unblock_manager.h"
#include "utils/rfkill_unblock_task.h"

namespace kmre {
namespace utils {

RfkillUnblockManager::Garbo RfkillUnblockManager::garbo;
std::mutex RfkillUnblockManager::lock;
RfkillUnblockManager* RfkillUnblockManager::m_pInstance = nullptr;

RfkillUnblockManager* RfkillUnblockManager::getInstance()
{
    if (nullptr == m_pInstance) {
        std::lock_guard<std::mutex> _l(lock);
        if (nullptr == m_pInstance) {
            m_pInstance = new RfkillUnblockManager;
        }
    }

    return m_pInstance;
}

RfkillUnblockManager::RfkillUnblockManager()
{

}

RfkillUnblockManager::~RfkillUnblockManager()
{
    std::lock_guard<std::mutex> _l(mLock);
    std::vector<RfkillUnblockTask*>::iterator iter = mTasks.begin();
    while (iter != mTasks.end()) {
        (*iter)->wait();
        delete *iter;
        iter++;
    }

    mTasks.clear();
}

void RfkillUnblockManager::unblockDeviceByIndex(uint32_t index)
{
    RfkillUnblockTask* task = new RfkillUnblockTask(index);

    {
        std::lock_guard<std::mutex> _l(mLock);
        mTasks.push_back(task);
    }

    task->start();

    usleep(10000);
    barrier();

    {
        std::lock_guard<std::mutex> _l(mLock);
        std::vector<RfkillUnblockTask*>::iterator iter = mTasks.begin();
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
