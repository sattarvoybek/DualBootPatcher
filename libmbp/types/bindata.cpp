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

#include "types/bindata.h"

#include <utility>
#include <cstdlib>
#include <cstring>

/*!
 * \class BinData
 * \brief Thin wrapper around malloc/realloc/free
 *
 * This class is meant to provide a safe way store binary data, accounting for
 * allocation failures. It's not meant to replace other types, like std::vector,
 * which provide far more functionality, but require support for exceptions to
 * be used safely.
 */

BinData::BinData() : m_data(nullptr), m_size(0), m_ownsData(true)
{
}

BinData::~BinData()
{
    free();
}

/*!
 * \brief Set the underlying data for this object
 *
 * If \a ownsData is true, the caller retains ownership of the data. The pointer
 * \a data will be saved and no new memory will be allocated. Nothing will
 * happen when this BinData object is destroyed.
 *
 * If \a ownsData is false, this BinData object will take ownership of the
 * data. The pointer \a data will be saved and no new memory will be allocated.
 * When this BinData object is destroyed, \a data will be freed.
 *
 * \note free() is called prior to setting the new data. However, if memory
 *       allocation fails, the state of this object is not changed (ie. free()
 *       is not called).
 *
 * \param data Data
 * \param size Size
 * \param ownData Whether this object should own the data
 */
void BinData::setData(unsigned char *data, std::size_t size, bool ownData)
{
    free();
    m_ownsData = ownData;
    m_data = data;
    m_size = size;
}

/*!
 * \brief Set the underlying data to a copy of the provided data
 *
 * The binary data will be copied and this BinData object will take ownership of
 * the copied data. A new memory block with size \a size will be allocated and
 * the contents in \a data will be copied to the new memory block. When this
 * BinData object is destroyed, the allocated memory is freed.
 *
 * \note free() is called prior to setting the new data. However, if memory
 *       allocation fails, the state of this object is not changed (ie. free()
 *       is not called).
 *
 * \param data Data
 * \param size Size
 *
 * \return True if the operation was successful. False if memory could not be
 *         allocated.
 */
bool BinData::setDataCopy(const unsigned char *data, std::size_t size)
{
    unsigned char *newData;

    if (m_ownsData) {
        // Reallocate memory if we own it
        newData = (unsigned char *) std::realloc(m_data, size);
    } else {
        // Otherwise, allocate new memory
        newData = (unsigned char *) std::malloc(size);
    }

    if (!newData) {
        return false;
    }

    std::memcpy(newData, data, size);

    free();
    m_data = newData;
    m_size = size;
    m_ownsData = true;
    return true;
}

/*!
 * \brief Reallocates underlying data
 *
 * This function reallocates the memory wrapped by this object. If \a size is 0,
 * then the memory is freed. A subsequent reallocate call can allocate memory
 * again. If reallocation fails, the memory is left untouched and this function
 * will return false.
 *
 * \note If this BinData object does not own the underlying data, this
 *       function will not do anything and will just return false.
 *
 * \param size New size or 0 if the memory is to be deallocated.
 *
 * \return True if the reallocation was successful. False if:
 *         - Memory could not be allocated
 *         - This object does not own the underlying data
 */
bool BinData::reallocate(std::size_t size)
{
    if (!m_ownsData) {
        return false;
    }

    unsigned char *newData = (unsigned char *) std::realloc(m_data, size);
    if (!newData) {
        return false;
    }

    m_data = newData;
    m_size = size;

    return true;
}

/*!
 * \brief Resizes underlying data
 *
 * This function is equivalent to calling reallocate() and zeroing the
 * additional memory (if the new size is larger than the original size).
 */
bool BinData::resize(std::size_t size)
{
    std::size_t oldSize = m_size;
    if (!reallocate(size)) {
        return false;
    }
    if (size > oldSize) {
        memset(m_data + oldSize, 0, size - oldSize);
    }
    return true;
}

/*!
 * \brief Frees underlying data
 *
 * This function is exactly equivalent to calling BinData::reallocate(0).
 *
 * \return True unless this object does not own the underlying data.
 */
void BinData::free()
{
    reallocate(0);
}

/*!
 * \brief Disassociates underlying data
 *
 * If this object owns the underlying data, the data will be freed.
 *
 * After this function returns, this object will be associated with an empty
 * block of memory that is owned by this object.
 */
void BinData::clear()
{
    free();
    m_ownsData = true;
    m_data = nullptr;
    m_size = 0;
}

/*!
 * \brief Get pointer to associated memory
 *
 * \note: This function could return null if this object is not associated to
 *        any memory or if the size of the data is 0.
 *
 * \return Pointer to associated memory
 */
unsigned char * BinData::data()
{
    return m_data;
}

/*!
 * \brief Get pointer to associated memory (const)
 *
 * \note: This function could return null if this object is not associated to
 *        any memory or if the size of the data is 0.
 *
 * \return Pointer to associated memory (const)
 */
const unsigned char * BinData::data() const
{
    return m_data;
}

/*!
 * \brief Get size of the associated memory
 *
 * \return Size of associated memory
 */
std::size_t BinData::size() const
{
    return m_size;
}

/*!
 * \brief Check whether the binary data has size 0
 *
 * \return Whether the binary data has size 0
 */
bool BinData::empty() const
{
    return m_size == 0;
}

unsigned char * BinData::begin()
{
    return m_data;
}

const unsigned char * BinData::begin() const
{
    return m_data;
}

const unsigned char * BinData::cbegin() const
{
    return begin();
}

unsigned char * BinData::end()
{
    return m_data + m_size;
}

const unsigned char * BinData::end() const
{
    return m_data + m_size;
}

const unsigned char * BinData::cend() const
{
    return end();
}

/*!
 * \brief Returns whether this object owns the underlying data
 *
 * \return Whether this object owns the underlying data
 */
bool BinData::ownsData() const
{
    return m_ownsData;
}

/*!
 * \brief Set whether this object owns the underlying data
 *
 * \note: If this object does not own the underlying data, calls to reallocate()
 *        and free() will fail.
 *
 * \param ownsData Whether this object should own the underlying data
 */
void BinData::setOwnsData(bool ownsData)
{
    m_ownsData = ownsData;
}

/*!
 * \brief Returns reference to the specified element position
 *
 * \warning: No bounds checking is performed!
 *
 * \param pos Position
 *
 * \return Reference to the specified element position
 */
unsigned char & BinData::operator[](std::size_t pos)
{
    return m_data[pos];
}

/*!
 * \brief Returns const reference to the specified element position
 *
 * \warning: No bounds checking is performed!
 *
 * \param pos Position
 *
 * \return Const reference to the specified element position
 */
const unsigned char & BinData::operator[](std::size_t pos) const
{
    return m_data[pos];
}

bool BinData::operator==(const BinData &other) const
{
    return m_size == other.m_size
            && std::memcmp(m_data, other.m_data, m_size) == 0;
}

bool BinData::operator!=(const BinData &other) const
{
    return !(*this == other);
}

bool BinData::operator<(const BinData &other) const
{
    return m_size == other.m_size
            && std::memcmp(m_data, other.m_data, m_size) < 0;
}

bool BinData::operator<=(const BinData &other) const
{
    return m_size == other.m_size
            && std::memcmp(m_data, other.m_data, m_size) <= 0;
}

bool BinData::operator>(const BinData &other) const
{
    return !(*this <= other);
}

bool BinData::operator>=(const BinData &other) const
{
    return !(*this < other);
}

BinData::BinData(BinData && bd) :
    m_data(std::move(bd.m_data)), m_size(std::move(bd.m_size)),
    m_ownsData(std::move(bd.m_ownsData))
{

}

BinData & BinData::operator=(BinData && bd)
{
    free();
    m_data = std::move(bd.m_data);
    m_size = std::move(bd.m_size);
    m_ownsData = std::move(bd.m_ownsData);
    return *this;
}
