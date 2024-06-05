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

#ifndef _KMRE_IMAGE_INFO_H_
#define _KMRE_IMAGE_INFO_H_

#include <string>
#include <stdint.h>
#include <jsoncpp/json/json.h>

namespace kmre {

namespace container {

class ImageMeta {
public:
    std::string m_imageId;
    std::string m_name;
    std::string m_repo;
    std::string m_tag;
    std::string m_created;
    std::string m_size;

    void toJson(Json::Value &value)
    {
        value["id"] = Json::Value(m_imageId);
        value["name"] = Json::Value(m_name);
        value["repo"] = Json::Value(m_repo);
        value["tag"] = Json::Value(m_tag);
        value["created"] = Json::Value(m_created);
        value["size"] = Json::Value(m_size);
    }
};

class ImageInfo
{
public:
    ImageInfo(const std::string& repo, const std::string& tag, uint32_t major, uint32_t minor, uint32_t date, uint32_t revision);

    bool operator ==(const ImageInfo& rhs);
    bool operator !=(const ImageInfo& rhs);
    bool operator >(const ImageInfo& rhs);
    bool operator >=(const ImageInfo& rhs);
    bool operator <(const ImageInfo& rhs);
    bool operator <=(const ImageInfo& rhs);

    std::string GetRepo() { return mRepo; }
    std::string GetTag() { return mTag; }
    uint32_t GetMajor() { return mMajor; }
    uint32_t GetMinor() { return mMinor; }
    uint32_t GetDate() { return mDate; }
    uint32_t GetRevision() { return mRevision; }

    void toJson(Json::Value &value)
    {
        value["repo"] = Json::Value(this->GetRepo());
        value["tag"] = Json::Value(this->GetTag());
        value["major"] = Json::Value(this->GetMajor());
        value["minor"] = Json::Value(this->GetMinor());
        value["date"] = Json::Value(this->GetDate());
        value["revision"] = Json::Value(this->GetRevision());
    }

private:
    ImageInfo();
    std::string mRepo;
    std::string mTag;
    uint32_t mMajor;
    uint32_t mMinor;
    uint32_t mDate;
    uint32_t mRevision;

};

} // namespace container
} // namespace kmre
#endif // _KMRE_IMAGE_INFO_H_
