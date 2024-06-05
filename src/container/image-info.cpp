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

#include "image-info.h"

namespace kmre {
namespace container {

ImageInfo::ImageInfo(const std::string &repo, const std::string &tag, uint32_t major, uint32_t minor, uint32_t date, uint32_t revision)
    : mRepo(repo),
      mTag(tag),
      mMajor(major),
      mMinor(minor),
      mDate(date),
      mRevision(revision)
{}

bool ImageInfo::operator ==(const ImageInfo& rhs)
{
    return (mMajor == rhs.mMajor)
            && (mMinor == rhs.mMinor)
            && (mDate == rhs.mDate)
            && (mRevision == rhs.mRevision);
}

bool ImageInfo::operator !=(const ImageInfo& rhs)
{
    return !operator ==(rhs);
}

bool ImageInfo::operator >(const ImageInfo& rhs)
{
    if (mMajor > rhs.mMajor) {
        return true;
    } else if (mMajor < rhs.mMajor) {
        return false;
    }

    if (mMinor > rhs.mMinor) {
        return true;
    } else if (mMinor < rhs.mMinor) {
        return false;
    }

    if (mDate > rhs.mDate) {
        return true;
    } else if (mDate < rhs.mDate) {
        return false;
    }

    if (mRevision > rhs.mRevision) {
        return true;
    } else if (mRevision < rhs.mRevision) {
        return false;
    }

    return false;
}

bool ImageInfo::operator >=(const ImageInfo& rhs)
{
    return operator >(rhs) || operator ==(rhs);
}

bool ImageInfo::operator <(const ImageInfo& rhs)
{
    bool ret;
    if (operator >=(rhs)) {
        ret = false;
    } else {
        ret = true;
    }

    return ret;
}

bool ImageInfo::operator <=(const ImageInfo& rhs)
{
    return operator <(rhs) || operator ==(rhs);
}

} // namespace container
} // namespace kmre
