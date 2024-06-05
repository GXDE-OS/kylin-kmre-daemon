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

#ifndef KMRE_UTILS_RFKILL_UNBLOCK_MANAGER_H
#define KMRE_UTILS_RFKILL_UNBLOCK_MANAGER_H

#include "utils.h"

#include <string>
#include <vector>
#include <mutex>


namespace kmre {
namespace utils {

class RfkillUnblockTask;

class RfkillUnblockManager
{
public:
    void unblockDeviceByIndex(uint32_t index);

    static RfkillUnblockManager* getInstance();

private:

    RfkillUnblockManager();
    ~RfkillUnblockManager();

    static RfkillUnblockManager* m_pInstance;

    class Garbo
    {
    public:
        ~Garbo()
        {
            if (RfkillUnblockManager::m_pInstance) {
                delete RfkillUnblockManager::m_pInstance;
                RfkillUnblockManager::m_pInstance = nullptr;
            }
        }
    };

    static Garbo garbo;
    static std::mutex lock;


    std::mutex mLock;
    std::vector<RfkillUnblockTask*> mTasks;

    DISALLOW_COPY_AND_ASSIGN(RfkillUnblockManager);
};

} // namespace utils
} // namespace kmre

#endif // KMRE_UTILS_RFKILL_UNBLOCK_MANAGER_H
