/**
 * @file sqlite.h
 * @brief 
 * @date 2021-03-12
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */
#pragma once
#ifdef USING_SQLITE3
#include "base.h"

#ifdef _WIN64
#ifdef _DEBUG
#pragma comment (lib,"sqlite3_x64_d.lib")
#else
#pragma comment (lib,"sqlite3_x64.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment (lib,"sqlite3_d.lib")
#else
#pragma comment (lib,"sqlite3.lib")
#endif
#endif

namespace wstd
{
    namespace sqlite
    {
        bool exec(const std::wstring& db_file, const std::wstring& sql, uint32_t codepage,
                  std::vector<std::wstring>& result);
    }
}
#endif 
