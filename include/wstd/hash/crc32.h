/**
 * @file crc32.h
 * @brief 
 * @date 2021-04-21
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace wstd
{
    namespace hash
    {
        uint32_t crc32(const unsigned char* buf, uint32_t size);
        uint32_t crc32(const std::string& data);
        uint32_t crc32(const std::vector<unsigned char>& data);
    }
}
