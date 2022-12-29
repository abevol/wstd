/**
 * @file pe.h
 * @brief 
 * @date 2021-05-17
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"

namespace wstd
{
    namespace pe
    {
        bool read_resource_data(HMODULE hMod, int res_id, std::string& data);

        bool write_resource_data(const std::wstring& file, int res_id, const std::string& data);
    }
}
