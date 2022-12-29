#include <wstd/base.h>
#include <wstd/string.h>

namespace wstd
{
    void debug_msg(const char* pszText, ...)
    {
        std::string result;
        va_list args;

        va_start(args, pszText);
        auto len = _vscprintf(pszText, args);
        if (len < 0)
            return;
        result.resize((size_t)len);
        vsprintf_s(&result[0], result.size() + sizeof(TCHAR), pszText, args);
        va_end(args);

        result.append("\n");
        OutputDebugStringW(string::utf8_to_unicode(result).c_str());
        printf_s(result.c_str());
    }

    void debug_msg(const wchar_t* pszText, ...)
    {
        std::wstring result;
        va_list args;

        va_start(args, pszText);
        auto len = _vscwprintf(pszText, args);
        if (len < 0)
            return;
        result.resize((size_t)len);
        vswprintf_s(&result[0], result.size() + sizeof(TCHAR), pszText, args);
        va_end(args);

        result.append(L"\n");
        OutputDebugStringW(result.c_str());
        wprintf_s(result.c_str());
    }
}
