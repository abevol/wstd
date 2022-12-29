#include <wstd/registry.h>
#include <wstd/string.h>

namespace wstd
{
    namespace registry
    {
        HKEY get_root_key(const std::wstring& key)
        {
            if (key.empty())
                return nullptr;

            std::wstring root_key_str;
            auto pos = key.find(L'\\');
            if (pos == std::wstring::npos)
                root_key_str = key;
            else
                root_key_str = key.substr(0, pos);

            if (string::compare(root_key_str, L"HKEY_CLASSES_ROOT", true) ||
                string::compare(root_key_str, L"HKCR", true))
                return HKEY_CLASSES_ROOT;

            if (string::compare(root_key_str, L"HKEY_CURRENT_USER", true) ||
                string::compare(root_key_str, L"HKCU", true))
                return HKEY_CURRENT_USER;

            if (string::compare(root_key_str, L"HKEY_LOCAL_MACHINE", true) ||
                string::compare(root_key_str, L"HKLM", true))
                return HKEY_LOCAL_MACHINE;

            if (string::compare(root_key_str, L"HKEY_USERS", true) ||
                string::compare(root_key_str, L"HKU", true))
                return HKEY_USERS;

            if (string::compare(root_key_str, L"HKEY_CURRENT_CONFIG", true) ||
                string::compare(root_key_str, L"HKCC", true))
                return HKEY_CURRENT_CONFIG;

            return nullptr;
        }

        bool read(HKEY root, LPCWSTR path, LPCWSTR key, DWORD type, VOID*& value, DWORD& length)
        {
            value = nullptr;
            HKEY h_key = nullptr;
            LSTATUS status = RegOpenKeyEx(root, path, 0, KEY_READ, &h_key);
            if (status != ERROR_SUCCESS || !h_key)
                return false;

            DWORD buffer_size;
            if (type == REG_DWORD)
            {
                buffer_size = 4;
            }
            else if (type == REG_QWORD)
            {
                buffer_size = 8;
            }
            else
            {
                buffer_size = 1024;
            }
            auto* perf_data = malloc(buffer_size);
            if (!perf_data)
                return false;
            length = buffer_size;
            status = RegQueryValueEx(h_key, key, nullptr, &type, (LPBYTE)perf_data, &length);
            while (status == ERROR_MORE_DATA)
            {
                buffer_size += 1024;
                free(perf_data);
                perf_data = malloc(buffer_size);
                if (!perf_data)
                    return false;
                length = buffer_size;
                status = RegQueryValueEx(h_key, key, nullptr, &type, (LPBYTE)perf_data, &length);
            }
            RegCloseKey(h_key);
            value = perf_data;
            return (status == ERROR_SUCCESS);
        }

        bool read(HKEY root, const std::wstring& path, const std::wstring& key, std::wstring& value)
        {
            void* result = nullptr;
            DWORD cbData = 0;
            bool res = read(root, path, key, REG_SZ, result, cbData);
            if (res && result)
            {
                cbData = cbData / sizeof(wchar_t);
                if (((wchar_t*)result)[cbData - 1] == L'\x00')
                {
                    value.assign((wchar_t*)result);
                }
                else
                {
                    value.assign((wchar_t*)result, cbData);
                }

                free(result);
                return true;
            }
            return false;
        }

        bool read(HKEY root, const std::wstring& path, const std::wstring& key, DWORD& value)
        {
            void* result = nullptr;
            DWORD cbData = 0;
            bool res = read(root, path, key, REG_DWORD, result, cbData);
            if (res && result)
            {
                value = *(DWORD*)result;
                free(result);
                return true;
            }
            return false;
        }

        bool write(HKEY root, LPCWSTR path, LPCWSTR key, DWORD type, BYTE* data, DWORD length)
        {
            if (!data)
                return false;

            HKEY app_key = nullptr;
            LSTATUS status = RegCreateKeyEx(root, path, 0, nullptr, NULL, KEY_ALL_ACCESS, nullptr, &app_key, nullptr);
            if (status == ERROR_SUCCESS && app_key != nullptr)
            {
                status = RegSetValueEx(app_key, key, NULL, type, data, length);
                RegCloseKey(app_key);
                if (status == ERROR_SUCCESS)
                {
                    return true;
                }
            }
            return false;
        }

        bool delete_value(HKEY root, LPCWSTR path, LPCWSTR key)
        {
            HKEY app_key = nullptr;
            LSTATUS status = RegOpenKeyEx(root, path, 0, KEY_SET_VALUE, &app_key);
            if (status == ERROR_SUCCESS && app_key != nullptr)
            {
                status = RegDeleteValue(app_key, key);
                RegCloseKey(app_key);
                if (status == ERROR_SUCCESS)
                {
                    return true;
                }
            }
            return false;
        }
    }
}
