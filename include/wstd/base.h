/**
 * @file base.h
 * @brief 
 * @date 2021-03-12
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <list>
#include <memory>

#if defined(__RESHARPER__) || defined(__GNUC__)
#define PRINTF_ATTR(StringIndex, FirstToCheck) \
        [[gnu::format(printf, StringIndex, FirstToCheck)]]
#else
#define PRINTF_ATTR(StringIndex, FirstToCheck)
#endif

#if defined(__RESHARPER__)
#define WPRINTF_ATTR(StringIndex, FirstToCheck) \
        [[rscpp::format(wprintf, StringIndex, FirstToCheck)]]
#else
#define WPRINTF_ATTR(StringIndex, FirstToCheck)
#endif

namespace wstd
{
    PRINTF_ATTR(1, 2)
        void debug_msg(const char* pszText, ...);

    PRINTF_ATTR(1, 2)
        void debug_msg(const wchar_t* pszText, ...);
}
