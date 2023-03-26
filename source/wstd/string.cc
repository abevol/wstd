#include <wstd/string.h>
#include <rpc.h>

#pragma comment(lib, "Rpcrt4.lib")

namespace wstd
{
    namespace string
    {
        std::string unicode_to_utf8(const std::wstring& wstr)
        {
            if (wstr.empty()) return std::string();
            const int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), nullptr, 0, nullptr, nullptr);
            if (!size_needed)
                return "";
            std::string strTo(size_needed, 0);
            if (!WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, nullptr, nullptr))
                return "";
            return strTo;
        }

        std::wstring utf8_to_unicode(const std::string& str)
        {
            if (str.empty()) return std::wstring();
            const int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), nullptr, 0);
            if (!size_needed)
                return L"";
            std::wstring wstrTo(size_needed, 0);
            if (!MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed))
                return L"";
            return wstrTo;
        }

        std::wstring local_to_unicode(const std::string& str)
        {
            if (str.empty()) return std::wstring();
            const int size_needed = MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), nullptr, 0);
            if (!size_needed)
                return L"";
            std::wstring wstrTo(size_needed, 0);
            if (!MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed))
                return L"";
            return wstrTo;
        }

        std::string unicode_to_local(const std::wstring& wstr)
        {
            if (wstr.empty()) return std::string();
            const int size_needed = WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), nullptr, 0, nullptr, nullptr);
            if (!size_needed)
                return "";
            std::string strTo(size_needed, 0);
            if (!WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, nullptr, nullptr))
                return "";
            return strTo;
        }

        std::wstring codepage_to_unicode(const std::string& str, uint32_t codepage)
        {
            if (str.empty()) return std::wstring();
            const int size_needed = MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), nullptr, 0);
            if (!size_needed)
                return L"";
            std::wstring wstrTo(size_needed, 0);
            if (!MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed))
                return L"";
            return wstrTo;
        }

        std::string unicode_to_codepage(const std::wstring& wstr, uint32_t codepage)
        {
            if (wstr.empty()) return std::string();
            const int size_needed = WideCharToMultiByte(codepage, 0, &wstr[0], (int)wstr.size(), nullptr, 0, nullptr, nullptr);
            if (!size_needed)
                return "";
            std::string strTo(size_needed, 0);
            if (!WideCharToMultiByte(codepage, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, nullptr, nullptr))
                return "";
            return strTo;
        }

        std::string format_v(const char* pszText, va_list args)
        {
            std::string result;
            auto len = _vscprintf(pszText, args);
            if (len == -1)
                return result;
            result.resize(len);
            vsprintf_s(&result[0], result.size() + 1, pszText, args);
            return result;
        }

        std::wstring format_v(const wchar_t* pszText, va_list args)
        {
            std::wstring result;
            auto len = _vscwprintf(pszText, args);
            if (len == -1)
                return result;
            result.resize(len);
            vswprintf_s(&result[0], result.size() + 1, pszText, args);
            return result;
        }

        bool compare(const char* a, const char* b, bool no_case)
        {
            if(!a || !b) return false;
            if (no_case)
                return (strcasecmp(a, b) == 0);
            return (strcmp(a, b) == 0);
        }

        bool compare(const wchar_t* a, const wchar_t* b, bool no_case)
        {
            if (!a || !b) return false;
            if (no_case)
                return (wcscasecmp(a, b) == 0);
            return (wcscmp(a, b) == 0);
        }

        bool compare(const std::string& a, const std::string& b, bool no_case)
        {
            if (no_case)
                return (a.size() == b.size()) && (strncasecmp(a.c_str(), b.c_str(), a.size()) == 0);
            return a == b;
        }

        bool compare(const std::wstring& a, const std::wstring& b, bool no_case)
        {
            if (no_case)
                return (a.size() == b.size()) && (wcsncasecmp(a.c_str(), b.c_str(), a.size()) == 0);
            return a == b;
        }

        char hex_to_unit(char ch)
        {
            if (ch >= '0' && ch <= '9')
            {
                return char(ch - '0');
            }
            if (ch >= 'A' && ch <= 'F')
            {
                return char(ch - 'A' + 0xA);
            }
            if (ch >= 'a' && ch <= 'f')
            {
                return char(ch - 'a' + 0xA);
            }
            return 0;
        }

        char hex_to_byte(const char* src)
        {
            return char(hex_to_unit(src[0]) * 16 + hex_to_unit(src[1]));
        }

        std::string url_encode(const std::string& src)
        {
            const char lookup[] = "0123456789ABCDEF";
            std::string s;
            for (unsigned int i = 0; i < src.length(); i++)
            {
                const char& c = src[i];
                if ((48 <= c && c <= 57) || //0-9
                    (65 <= c && c <= 90) || //abc...xyz
                    (97 <= c && c <= 122) || //ABC...XYZ
                    (c == '-' || c == '_' || c == '.' || c == '~')
                )
                {
                    s.push_back(c);
                }
                else
                {
                    s.push_back('%');
                    s.push_back(lookup[(c & 0xF0) >> 4]);
                    s.push_back(lookup[(c & 0x0F)]);
                }
            }
            return s;
        }

        std::string url_decode(const std::string& src)
        {
            std::string ret;
            for (unsigned int i = 0; i < src.length(); i++)
            {
                char ch = src[i];
                if (ch == '%')
                {
                    ch = static_cast<char>(hex_to_byte(src.data() + i + 1));
                    i = i + 2;
                }
                ret.push_back(ch);
            }
            return ret;
        }

        std::string bytes_to_hex(const void* bytes, size_t len, bool pretty)
        {
            static const char lookup[] = "0123456789ABCDEF";
            std::string result;
            size_t i = 0;
            while (i < len)
            {
                const char ch = ((const char*)bytes)[i];
                result.push_back(lookup[(ch & 0xF0) >> 4]);
                result.push_back(lookup[(ch & 0x0F)]);
                if (pretty)
                    result.push_back(' ');
                i = i + 1;
            }
            if (pretty)
                result.pop_back();
            return result;
        }

        std::string bytes_to_hex(const std::string& bytes, bool pretty)
        {
            return bytes_to_hex(bytes.c_str(), bytes.size(), pretty);
        }

        std::string hex_to_bytes(const char* hex, size_t len)
        {
            if (len == 0)
                len = strlen(hex);
            std::string result;
            for (size_t i = 0; i < len; ++i)
            {
                if (hex[i] == ' ')
                    continue;
                if (i + 1 >= len)
                    break;
                if (hex[i + 1] == ' ')
                    continue;
                result.push_back(hex_to_byte(hex + i));
                i = i + 1;
            }
            return result;
        }

        std::string hex_to_bytes(const std::string& hex)
        {
            return hex_to_bytes(hex.c_str(), hex.size());
        }

        const char* strcasestr(const char* s, const char* find)
        {
            char c, sc;
            size_t len;
            if ((c = *find++) != 0)
            {
                c = (char)tolower((unsigned char)c);
                len = strlen(find);
                do
                {
                    do
                    {
                        if ((sc = *s++) == 0)
                            return (NULL);
                    } while ((char)tolower((unsigned char)sc) != c);
                } while (strncasecmp(s, find, len) != 0);
                s--;
            }
            return s;
        }

        const wchar_t* wcscasestr(const wchar_t* s, const wchar_t* find)
        {
            wchar_t c, sc;
            size_t len;
            if ((c = *find++) != L'\0')
            {
                c = (wchar_t)towlower(c);
                len = wcslen(find);
                do
                {
                    do
                    {
                        if ((sc = *s++) == L'\0')
                            return (NULL);
                    } while ((wchar_t)towlower(sc) != c);
                } while (wcsncasecmp(s, find, len) != 0);
                s--;
            }
            return s;
        }

        size_t find(const std::string& s, const std::string& p, size_t offset, bool no_case)
        {
            if (s.size() - offset < p.size())
                return std::string::npos;
            if (no_case)
            {
                const char* f = strcasestr(&s[0] + offset, p.c_str());
                if (!f)
                    return std::string::npos;
                return f - &s[0];
            }
            return s.find(p, offset);
        }

        size_t find(const std::wstring& s, const std::wstring& p, size_t offset, bool no_case)
        {
            if (s.size() - offset < p.size())
                return std::wstring::npos;
            if (no_case)
            {
                const wchar_t* f = wcscasestr(&s[0] + offset, p.c_str());
                if (!f)
                    return std::wstring::npos;
                return f - &s[0];
            }
            return s.find(p, offset);
        }

        template<>
        std::string guid_to_string<char>(const GUID* uuid)
        {
            std::string result;
            RPC_STATUS status;
            if (!UuidIsNil((GUID*)uuid, &status) && status == RPC_S_OK)
            {
                CHAR* wszUuid = nullptr;
                auto status = UuidToStringA(uuid, (RPC_CSTR*)&wszUuid);
                if (status == RPC_S_OK && wszUuid != nullptr)
                {
                    result = wszUuid;
                    RpcStringFreeA((RPC_CSTR*)&wszUuid);
                }
            }
            return result;
        }

        template<>
        std::wstring guid_to_string<wchar_t>(const GUID* uuid)
        {
            std::wstring result;
            RPC_STATUS status;
            if (!UuidIsNil((GUID*)uuid, &status) && status == RPC_S_OK)
            {
                WCHAR* wszUuid = nullptr;
                auto status = UuidToStringW(uuid, (RPC_WSTR*)&wszUuid);
                if (status == RPC_S_OK && wszUuid != nullptr)
                {
                    result = wszUuid;
                    RpcStringFreeW((RPC_WSTR*)&wszUuid);
                }
            }
            return result;
        }

        bool create_guid(GUID& guid)
        {
            const auto status = UuidCreate(&guid);
            if (status != RPC_S_OK)
            {
                return false;
            }
            return true;
        }

        template <>
        std::string get_random_string<std::string>(size_t len)
        {
            const char* dic = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            const size_t dic_len = strlen(dic);
            std::string result;
            for (size_t i = 0; i < len; i++)
            {
                result.push_back(dic[random(0, dic_len - 1)]);
            }
            return result;
        }

        template <>
        std::wstring get_random_string<std::wstring>(size_t len)
        {
            const wchar_t* dic = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            const size_t dic_len = wcslen(dic);
            std::wstring result;
            for (size_t i = 0; i < len; i++)
            {
                result.push_back(dic[random(0, dic_len - 1)]);
            }
            return result;
        }
    }

    std::string format(const char* pszText, ...)
    {
        std::string result;
        if (!pszText)
            return result;
        va_list args;
        va_start(args, pszText);
        result = string::format_v(pszText, args);
        va_end(args);

        return result;
    }

    std::wstring format(const wchar_t* pszText, ...)
    {
        std::wstring result;
        if (!pszText)
            return result;

        va_list args;
        va_start(args, pszText);
        result = string::format_v(pszText, args);
        va_end(args);

        return result;
    }
}
