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

#ifndef KMRE_CONTAINER_PROPERTY_MAP_H
#define KMRE_CONTAINER_PROPERTY_MAP_H

#include <map>
#include <utility>
#include <string>

namespace kmre {
namespace container {

typedef std::map<std::string, std::string> Properties;

class PropertyMap
{
public:
    PropertyMap();
    PropertyMap(const PropertyMap& map);
    ~PropertyMap();

    void addProperty(const std::string& key, const std::string& value);
    std::string getProperty(const std::string& key);
    void removeProperty(const std::string& key);
    void loadProperties();
    void saveProperties(int mode = 0600);
    bool hasProperty(const std::string& key);

    void setPropertyFilePath(const std::string& path) { mPropertyFilePath = path; }
    void operator =(const PropertyMap& map);

private:


    std::string mPropertyFilePath;
    Properties mPropertyMap;
};


} // namespace container
} // namespace kmre

#endif // KMRE_CONTAINER_PROPERTY_MAP_H
