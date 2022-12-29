/**
 * @file registry.h
 * @brief 
 * @date 2021-04-06
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"

namespace wstd
{
    namespace registry
    {
        HKEY get_root_key(const std::wstring& key);

        bool read(HKEY root, LPCWSTR path, LPCWSTR key, DWORD type, VOID*& value, DWORD& length);

        inline bool read(LPCWSTR path, LPCWSTR key, DWORD type, VOID*& value, DWORD& length)
        {
            HKEY root = get_root_key(path);
            if (!root)
                return false;
            return read(root, wcschr(path, '\\') + 1, key, type, value, length);
        }

        inline bool read(HKEY root, const std::wstring& path, const std::wstring& key, DWORD type, VOID*& value, DWORD& length)
        {
            return read(root, path.c_str(), key.c_str(), type, value, length);
        }

        inline bool read(const std::wstring& path, const std::wstring& key, DWORD type, VOID*& value, DWORD& length)
        {
            return read(path.c_str(), key.c_str(), type, value, length);
        }

        bool read(HKEY root, const std::wstring& path, const std::wstring& key, std::wstring& value);

        inline bool read(const std::wstring& path, const std::wstring& key, std::wstring& value)
        {
            HKEY root = get_root_key(path);
            if (!root)
                return false;
            return read(root, path.substr(path.find('\\') + 1), key, value);
        }

        bool read(HKEY root, const std::wstring& path, const std::wstring& key, DWORD& value);

        inline bool read(const std::wstring& path, const std::wstring& key, DWORD& value)
        {
            HKEY root = get_root_key(path);
            if (!root)
                return false;
            return read(root, path.substr(path.find('\\') + 1), key, value);
        }

        template<typename ValueT>
        ValueT read(HKEY root, const std::wstring& path, const std::wstring& key) = delete;

        template <>
        inline DWORD read<DWORD>(HKEY root, const std::wstring& path, const std::wstring& key)
        {
            DWORD value = 0;
            read(root, path, key, value);
            return value;
        }

        template <>
        inline std::wstring read<std::wstring>(HKEY root, const std::wstring& path, const std::wstring& key)
        {
            std::wstring value;
            read(root, path, key, value);
            return value;
        }

        template<typename ValueT>
        ValueT read(const std::wstring& path, const std::wstring& key) = delete;

        template <>
        inline DWORD read<DWORD>(const std::wstring& path, const std::wstring& key)
        {
            DWORD value = 0;
            read(path, key, value);
            return value;
        }

        template <>
        inline std::wstring read<std::wstring>(const std::wstring& path, const std::wstring& key)
        {
            std::wstring value;
            read(path, key, value);
            return value;
        }

        bool write(HKEY root, LPCWSTR path, LPCWSTR key, DWORD type, BYTE* data, DWORD length);

        inline bool write(LPCWSTR path, LPCWSTR key, DWORD type, BYTE* data, DWORD length)
        {
            HKEY root = get_root_key(path);
            if (!root)
                return false;
            return write(root, wcschr(path, '\\') + 1, key, type, data, length);
        }

        inline bool write(HKEY root, const std::wstring& path, const std::wstring& key, DWORD type, BYTE* data, DWORD length)
        {
            return write(root, path.c_str(), key.c_str(), type, data, length);
        }

        inline bool write(const std::wstring& path, const std::wstring& key, DWORD type, BYTE* data, DWORD length)
        {
            return write(path.c_str(), key.c_str(), type, data, length);
        }

        inline bool write(HKEY root, const std::wstring& path, const std::wstring& key, const std::wstring& value)
        {
            return write(root, path, key, REG_SZ, (LPBYTE)&value[0], (DWORD)((value.size() + 1) * sizeof(wchar_t)));
        }

        inline bool write(const std::wstring& path, const std::wstring& key, const std::wstring& value)
        {
            return write(path, key, REG_SZ, (LPBYTE)&value[0], (DWORD)((value.size() + 1) * sizeof(wchar_t)));
        }

        inline bool write(HKEY root, const std::wstring& path, const std::wstring& key, DWORD value)
        {
            return write(root, path, key, REG_DWORD, (LPBYTE)&value, sizeof(value));
        }

        inline bool write(const std::wstring& path, const std::wstring& key, DWORD value)
        {
            return write(path, key, REG_DWORD, (LPBYTE)&value, sizeof(value));
        }

        inline bool write(HKEY root, LPCWSTR path, LPCWSTR key, const std::wstring& value)
        {
            return write(root, path, key, REG_SZ, (LPBYTE)&value[0], (DWORD)((value.size() + 1) * sizeof(wchar_t)));
        }

        inline bool write(LPCWSTR path, LPCWSTR key, const std::wstring& value)
        {
            return write(path, key, REG_SZ, (LPBYTE)&value[0], (DWORD)((value.size() + 1) * sizeof(wchar_t)));
        }

        inline bool write(HKEY root, LPCWSTR path, LPCWSTR key, DWORD value)
        {
            return write(root, path, key, REG_DWORD, (LPBYTE)&value, sizeof(value));
        }

        inline bool write(LPCWSTR path, LPCWSTR key, DWORD value)
        {
            return write(path, key, REG_DWORD, (LPBYTE)&value, sizeof(value));
        }

        bool delete_value(HKEY root, LPCWSTR path, LPCWSTR key);

        inline bool delete_value(HKEY root, const std::wstring& path, const std::wstring& key)
        {
            return delete_value(root, path, key);
        }
        
    }
}
