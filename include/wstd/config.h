/**
 * @file config.h
 * @brief 
 * @date 2021-03-12
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"

namespace wstd
{
    namespace config
    {
        bool read(
            LPCWSTR lpAppName,
            LPCWSTR lpKeyName,
            LPCWSTR lpDefault,
            std::wstring& lpReturnedString,
            LPCWSTR lpFileName);

        inline UINT read_int(
            LPCWSTR lpAppName,
            LPCWSTR lpKeyName,
            UINT nDefault,
            LPCWSTR lpFileName)
        {
            return GetPrivateProfileInt(lpAppName, lpKeyName, nDefault, lpFileName);
        }

        inline BOOL read_bool(
            LPCWSTR lpAppName,
            LPCWSTR lpKeyName,
            BOOL nDefault,
            LPCWSTR lpFileName)
        {
            return GetPrivateProfileInt(lpAppName, lpKeyName, nDefault, lpFileName);
        }

        inline bool write(
            LPCWSTR lpAppName,
            LPCWSTR lpKeyName,
            LPCWSTR lpString,
            LPCWSTR lpFileName)
        {
            return FALSE != WritePrivateProfileString(lpAppName, lpKeyName,
                lpString, lpFileName);
        }
    }
}
