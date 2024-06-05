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

#include "property-map.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace kmre {
namespace container {

static bool isStringValid(const std::string& str)
{
    const char* p = nullptr;

    p = str.c_str();
    if (p == nullptr) {
        return false;
    }

    if (strchr(p, '#')) {
        return false;
    }

    if (strchr(p, '=')) {
        return false;
    }

    return true;
}

static bool isKeyValid(const std::string& key)
{
    const char* p = nullptr;
    const char* q = nullptr;

    if (key.length() == 0) {
        return false;
    }

    if (!isStringValid(key)) {
        return false;
    }

    p = key.c_str();
    q = p;

    while (*q != '\0') {
        if (!isalnum(*q)) {
            if (*q != '.' && *q != '-' && *q != '_') {
                return false;
            }
        }
        q++;
    }

    return true;
}

static bool isValueValid(const std::string& value)
{
    const char* p = nullptr;
    const char* q = nullptr;

    if (value.length() == 0) {
        return true;
    }

    if (!isStringValid(value)) {
        return false;
    }

    p = value.c_str();
    q = p;

    while (*q != '\0') {
        if (!isalnum(*q)) {
            if (isblank(*q)) {
                return false;
            }

            if (iscntrl(*q)) {
                return false;
            }

            if (isspace(*q)) {
                return false;
            }
        }
        q++;
    }

    return true;
}

PropertyMap::PropertyMap()
{

}

PropertyMap::~PropertyMap()
{
    mPropertyMap.clear();
}

PropertyMap::PropertyMap(const PropertyMap &map)
    : mPropertyFilePath(map.mPropertyFilePath)
    , mPropertyMap(map.mPropertyMap)
{
}

void PropertyMap::operator =(const PropertyMap &map)
{
    mPropertyFilePath = map.mPropertyFilePath;
    mPropertyMap = map.mPropertyMap;
}

void PropertyMap::addProperty(const std::string &key, const std::string &value)
{
    if (!isKeyValid(key) || !isValueValid(value)) {
        return;
    }

    Properties::iterator it = mPropertyMap.find(key);
    if (it != mPropertyMap.end()) {
        it->second = value;
    } else {
        mPropertyMap.insert({ key, value });
    }
}

std::string PropertyMap::getProperty(const std::string &key)
{
    std::string value;

    Properties::iterator it = mPropertyMap.find(key);
    if (it != mPropertyMap.end()) {
        value = it->second;
    }

    return value;
}

void PropertyMap::removeProperty(const std::string &key)
{
    Properties::iterator it = mPropertyMap.find(key);
    if (it != mPropertyMap.end()) {
        it = mPropertyMap.erase(it);
    }
}

void PropertyMap::loadProperties()
{
    FILE* fp = nullptr;
    char buffer[1024] = {0};
    std::string key;
    std::string value;

    if (mPropertyFilePath.length() == 0) {
        return;
    }

    fp = fopen(mPropertyFilePath.c_str(), "r");
    if (fp == nullptr) {
        return;
    }

    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        char* p;
        p = strchr(buffer, '\n');
        if (p != nullptr) {
            *p = '\0';
        }

        p = strchr(buffer, '#');
        if (p != nullptr) {
            *p = '\0';
        }

        p = strchr(buffer, '=');
        if (p == nullptr) {
            continue;
        } else {
            *p++ = '\0';
        }

        key = std::string(buffer);
        value = std::string(p);

        this->addProperty(key, value);
    }

    /* filter some properties */
    this->removeProperty("ro.drm.primary.major");
    this->removeProperty("ro.drm.primary.minor");
    this->removeProperty("ro.drm.render.major");
    this->removeProperty("ro.drm.render.minor");

    fclose(fp);
}

void PropertyMap::saveProperties(int mode)
{
    FILE* fp = nullptr;

    if (mPropertyFilePath.length() == 0) {
        return;
    }

    fp = fopen(mPropertyFilePath.c_str(), "w");
    if (fp == nullptr) {
        return;
    }

    Properties::const_iterator it = mPropertyMap.begin();
    while (it != mPropertyMap.end()) {
        fprintf(fp, "%s=%s\n", it->first.c_str(), it->second.c_str());
        it++;
    }

    fclose(fp);

    chmod(mPropertyFilePath.c_str(), mode);
}

bool PropertyMap::hasProperty(const std::string &key)
{
    Properties::iterator it = mPropertyMap.find(key);
    return (it != mPropertyMap.end());
}

} // namespace container
} // namespace kmre
