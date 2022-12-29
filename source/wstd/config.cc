#include <wstd/config.h>

namespace wstd
{
    namespace config
    {
        bool read(LPCWSTR lpAppName, LPCWSTR lpKeyName, LPCWSTR lpDefault, std::wstring& lpReturnedString,
                  LPCWSTR lpFileName)
        {
            DWORD buf_size = 256;
            while (true)
            {
                WCHAR* buf = new(std::nothrow) WCHAR[buf_size];
                if (!buf)
                    return false;

                auto len = GetPrivateProfileString(lpAppName, lpKeyName,
                                                   lpDefault, buf, buf_size, lpFileName);
                if (GetLastError() == ERROR_SUCCESS)
                {
                    lpReturnedString.assign(buf, (size_t)len);
                    delete[] buf;
                    return true;
                }

                delete[] buf;
                if (GetLastError() != ERROR_MORE_DATA)
                    return false;

                buf_size = buf_size * 2;
                if (buf_size > 1024 * 1024 * 100)
                    break;
            }
            return false;
        }
    }
}
