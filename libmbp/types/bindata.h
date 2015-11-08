/*
 * Copyright (C) 2015  Andrew Gunnerson <andrewgunnerson@gmail.com>
 *
 * This file is part of MultiBootPatcher
 *
 * MultiBootPatcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MultiBootPatcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MultiBootPatcher.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <cctype>

class BinData
{
public:
    BinData();
    ~BinData();

    void setData(unsigned char *data, std::size_t size, bool ownData);
    bool setDataCopy(const unsigned char *data, std::size_t size);
    bool reallocate(std::size_t size);
    bool resize(std::size_t size);
    void free();
    void clear();

    unsigned char * data();
    const unsigned char * data() const;
    std::size_t size() const;
    bool empty() const;

    unsigned char * begin();
    const unsigned char * begin() const;
    const unsigned char * cbegin() const;

    unsigned char * end();
    const unsigned char * end() const;
    const unsigned char * cend() const;

    bool ownsData() const;
    void setOwnsData(bool ownsData);

    unsigned char & operator[](std::size_t pos);
    const unsigned char & operator[](std::size_t pos) const;

    bool operator==(const BinData &other) const;
    bool operator!=(const BinData &other) const;
    bool operator<(const BinData &other) const;
    bool operator<=(const BinData &other) const;
    bool operator>(const BinData &other) const;
    bool operator>=(const BinData &other) const;

    BinData(const BinData &) = delete;
    BinData(BinData &&bd);
    BinData & operator=(const BinData &) = delete;
    BinData & operator=(BinData &&bd);

private:
    unsigned char *m_data;
    std::size_t m_size;
    bool m_ownsData;
};
