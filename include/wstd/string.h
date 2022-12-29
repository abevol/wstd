/**
 * @file string.h
 * @brief 字符串辅助类
 * @date 2021-04-06
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"
#include <algorithm>
#include <unordered_map>

#ifdef WIN32
#ifndef strcasecmp
#define strcasecmp _stricmp
#endif
#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif
#ifndef wcscasecmp
#define wcscasecmp _wcsicmp
#endif
#ifndef wcsncasecmp
#define wcsncasecmp _wcsnicmp
#endif
#endif

 // [a, b]
#define random(a, b)        ((rand()%((b)-(a)+1))+(a))

namespace wstd
{
    namespace string
    {
        // Convert a wide Unicode string to an UTF8 string
        std::string unicode_to_utf8(const std::wstring& wstr);

        // Convert an UTF8 string to a wide Unicode String
        std::wstring utf8_to_unicode(const std::string& str);

        // [[deprecated("Not recommended to use the system default code page.")]]
        std::wstring local_to_unicode(const std::string& str);

        // [[deprecated("Not recommended to use the system default code page.")]]
        std::string unicode_to_local(const std::wstring& wstr);

        std::wstring codepage_to_unicode(const std::string& str, uint32_t codepage);

        std::string unicode_to_codepage(const std::wstring& wstr, uint32_t codepage);

        std::string format_v(const char* pszText, va_list args);

        std::wstring format_v(const wchar_t* pszText, va_list args);

        /**
         * @brief 查找以指定字符开始的字符串。
         * @param src 源字符串。
         * @param c 起始字符。
         * @param remove 去掉起始字符。
         * @return 结果字符串。
        */
        template<typename CharT>
        std::string find_char_str(const std::basic_string<CharT>& src, CharT c, bool remove = false)
        {
            const auto pos = src.find(c);
            if (pos == std::basic_string<CharT>::npos)
                return std::basic_string<CharT>();

            if (remove)
            {
                return src.substr(pos + 1);
            }
            return src.substr(0, pos);
        }

        /**
         * @brief 反向查找以指定字符开始的字符串。
         * @param src 源字符串。
         * @param c 起始字符。
         * @param remove 去掉起始字符。
         * @return 结果字符串。
        */
        template<typename CharT>
        std::basic_string<CharT> rfind_char_str(const std::basic_string<CharT>& src, CharT c, bool remove = false)
        {
            const auto pos = src.rfind(c);
            if (pos == std::basic_string<CharT>::npos)
                return std::basic_string<CharT>();

            if (remove)
            {
                return src.substr(src.rfind(c) + 1);
            }
            return src.substr(0, src.rfind(c));
        }

        template<typename CharT>
        size_t get_mid_str(const std::basic_string<CharT>& src, const std::basic_string<CharT>& front,
            const std::basic_string<CharT>& back, std::basic_string<CharT>& result, size_t pos_begin = 0)
        {
            using StringT = std::basic_string<CharT>;

            size_t pos_a = src.find(front, pos_begin);
            if (pos_a == StringT::npos)
                return StringT::npos;

            pos_a = pos_a + front.size();
            size_t pos_b = src.find(back, pos_a);
            if (pos_b == StringT::npos)
                return StringT::npos;

            result = src.substr(pos_a, pos_b - pos_a);
            return pos_b + back.size();
        }

        template<typename CharT>
        size_t get_mid_str(const std::basic_string<CharT>& src, CharT front, CharT back,
            std::basic_string<CharT>& result, size_t pos_begin = 0)
        {
            using StringT = std::basic_string<CharT>;

            size_t pos_a = src.find(front, pos_begin);
            if (pos_a == StringT::npos)
                return StringT::npos;

            pos_a = pos_a + 1;
            size_t pos_b = src.find(back, pos_a);
            if (pos_b == StringT::npos)
                return StringT::npos;

            result = src.substr(pos_a, pos_b - pos_a);
            return pos_b + 1;
        }

        template<typename CharT>
        std::basic_string<CharT> get_mid_str(const std::basic_string<CharT>& src,
            const std::basic_string<CharT>& front, const std::basic_string<CharT>& back, size_t pos_begin = 0)
        {
            std::basic_string<CharT> result;
            get_mid_str<CharT>(src, front, back, result, pos_begin);
            return result;
        }

        template<typename CharT>
        std::basic_string<CharT> get_mid_str(const std::basic_string<CharT>& src,
            CharT front, CharT back, size_t pos_begin = 0)
        {
            std::basic_string<CharT> result;
            get_mid_str<CharT>(src, front, back, result, pos_begin);
            return result;
        }

        template<typename CharT>
        std::vector<std::basic_string<CharT>> split(const std::basic_string<CharT>& str,
            const std::basic_string<CharT>& delimiter, const bool trim_empty = false)
        {
            size_t pos, last_pos = 0, len;
            std::vector<std::basic_string<CharT>> tokens;

            while (true)
            {
                pos = str.find(delimiter, last_pos);
                if (pos == std::basic_string<CharT>::npos)
                {
                    pos = str.size();
                }

                len = pos - last_pos;
                if (!trim_empty || len != 0)
                {
                    tokens.push_back(str.substr(last_pos, len));
                }

                if (pos == str.size())
                {
                    break;
                }

                last_pos = pos + delimiter.size();
            }
            return tokens;
        }

        template<typename CharT>
        std::vector<std::basic_string<CharT>> split_lines(const std::basic_string<CharT>& str)
        {
            std::vector<std::basic_string<CharT>> result;
            size_t begin = 0;
            const size_t size = str.size();
            while (begin <= size)
            {
                size_t end = str.find('\n', begin);
                if (end == std::basic_string<CharT>::npos)
                {
                    result.push_back(str.substr(begin, size - begin));
                    break;
                }
                size_t skip = 1;
                if (end != 0)
                {
                    // windows: \r\n
                    if (str[end - 1] == '\r')
                    {
                        end = end - 1;
                        skip = 2;
                    }
                }
                result.push_back(str.substr(begin, end - begin));
                begin = end + skip;
            }
            return result;
        }

        template<typename CharT>
        std::basic_string<CharT> to_upper(const std::basic_string<CharT>& str)
        {
            std::basic_string<CharT> s(str);
            std::transform(s.begin(), s.end(), s.begin(), toupper);
            return s;
        }

        template<typename CharT>
        std::basic_string<CharT> to_lower(const std::basic_string<CharT>& str)
        {
            std::basic_string<CharT> s(str);
            std::transform(s.begin(), s.end(), s.begin(), tolower);
            return s;
        }

        bool compare(const std::string& a, const std::string& b, bool no_case = false);

        bool compare(const std::wstring& a, const std::wstring& b, bool no_case = false);

        template<typename CharT>
        bool starts_with(const std::basic_string<CharT>& src,
            const std::basic_string<CharT>& prefix, size_t offset = 0, bool no_case = false)
        {
            if (src.size() < prefix.size() + offset)
                return false;
            return compare(src.substr(offset, prefix.size()), prefix, no_case);
        }

        template<typename CharT>
        bool ends_with(const std::basic_string<CharT>& src,
            const std::basic_string<CharT>& suffix, bool noCase = false)
        {
            if (src.size() < suffix.size())
                return false;
            return compare(src.substr(src.size() - suffix.size()), suffix, noCase);
        }

        template<typename CharT>
        bool separate(const std::basic_string<CharT>& src, const std::basic_string<CharT>& delimiters,
            std::basic_string<CharT>& first, std::basic_string<CharT>& second)
        {
            size_t del = src.find(delimiters);
            if (del != std::basic_string<CharT>::npos)
            {
                first.assign(src.begin(), src.begin() + del);
                second.assign(src.begin() + del + delimiters.size(), src.end());
                return true;
            }
            return false;
        }

        char hex_to_unit(char ch);

        char hex_to_byte(const char* src);

        std::string url_encode(const std::string& src);

        std::string url_decode(const std::string& src);

        std::string bytes_to_hex(const void* bytes, size_t len, bool pretty = true);

        std::string bytes_to_hex(const std::string& bytes, bool pretty = true);

        std::string hex_to_bytes(const char* hex, size_t len = 0);

        std::string hex_to_bytes(const std::string& hex);

        const char* strcasestr(const char* s, const char* find);

        inline char* strcasestr(char* s, const char* find)
        {
            return const_cast<char*>(strcasestr(static_cast<const char*>(s), find));
        }

        const wchar_t* wcscasestr(const wchar_t* s, const wchar_t* find);

        inline wchar_t* wcscasestr(wchar_t* s, const wchar_t* find)
        {
            return const_cast<wchar_t*>(wcscasestr(static_cast<const wchar_t*>(s), find));
        }

        size_t find(const std::string& s, const std::string& p, size_t offset = 0, bool no_case = false);

        size_t find(const std::wstring& s, const std::wstring& p, size_t offset = 0, bool no_case = false);

        /**
         * @brief 替换字符串（只替换一次）
         * @tparam CharT char或wchar_t
         * @param str 源字符串
         * @param old_value 老的字符串
         * @param new_value 新的字符串
         * @param offset 搜索偏移
         * @param no_case 不区分大小写
         * @return 返回结果字符串
        */
        template<typename CharT>
        std::basic_string<CharT> replace(const std::basic_string<CharT>& str, const std::basic_string<CharT>& old_value,
            const std::basic_string<CharT>& new_value, size_t offset = 0, bool no_case = false)
        {
            using StringT = std::basic_string<CharT>;
            StringT result = str;
            auto pos = find(result, old_value, offset, no_case);
            if (pos != StringT::npos)
                result.replace(pos, old_value.length(), new_value);
            return result;
        }

        /**
         * @brief 替换字符串（完全替换）
         * @tparam CharT char或wchar_t
         * @param str 源字符串
         * @param old_value 老的字符串
         * @param new_value 新的字符串
         * @param no_case 不区分大小写
         * @return 返回结果字符串
        */
        template<typename CharT>
        std::basic_string<CharT> replace_all(const std::basic_string<CharT>& str,
            const std::basic_string<CharT>& old_value, const std::basic_string<CharT>& new_value, bool no_case = false)
        {
            using StringT = std::basic_string<CharT>;
            StringT result = str;
            while (true)
            {
                typename StringT::size_type pos(0);
                if ((pos = find(result, old_value, 0, no_case)) != StringT::npos)
                    result.replace(pos, old_value.length(), new_value);
                else break;
            }
            return result;
        }

        /**
         * @brief 替换字符串（只替换可见的）
         * @tparam CharT char或wchar_t
         * @param str 源字符串
         * @param old_value 老的字符串
         * @param new_value 新的字符串
         * @param no_case 不区分大小写
         * @return 返回结果字符串
        */
        template<typename CharT>
        std::basic_string<CharT> replace_all_distinct(const std::basic_string<CharT>& str,
            const std::basic_string<CharT>& old_value, const std::basic_string<CharT>& new_value, bool no_case = false)
        {
            using StringT = std::basic_string<CharT>;
            StringT result = str;
            for (typename StringT::size_type pos(0); pos != StringT::npos; pos += new_value.length())
            {
                if ((pos = find(result, old_value, pos, no_case)) != StringT::npos)
                    result.replace(pos, old_value.length(), new_value);
                else break;
            }
            return result;
        }

        /**
         * @brief 反转字符串
         * @tparam CharT char或wchar_t
         * @param str 源字符串
         * @return 返回结果字符串
        */
        template<typename CharT>
        std::basic_string<CharT> reverse(const std::basic_string<CharT>& str)
        {
            auto data = str;
            auto len = data.size();
            for (size_t i = 0; i < len / 2; ++i)
            {
                CharT* p = &data[0];
                CharT c = p[i];
                p[i] = p[len - i - 1];
                p[len - i - 1] = c;
            }
            return data;
        }

        template<typename CharT>
        size_t length(const CharT* str) = delete;

        template<>
        inline size_t length(const char* str)
        {
            return strlen(str);
        }

        template<>
        inline size_t length(const wchar_t* str)
        {
            return wcslen(str);
        }

        template<typename CharT>
        size_t length(const std::basic_string<CharT>& str)
        {
            return str.length();
        }

        /**
         * @brief 复制字符串，以终止字符结尾，如果目标缓冲区不足，则会截断字符串。
         * @param dst 目的缓冲区
         * @param dst_len 目的缓冲区最大尺寸，以字符为单位
         * @param src 源字符串
         * @param copy_len 复制长度，以字符为单位
         * @return 
         */
        template<typename CharT>
        size_t copy(CharT* dst, const size_t dst_len, const CharT* src, size_t copy_len)
        {
            if (copy_len > dst_len - 1)
                copy_len = dst_len - 1;
            if (memcpy_s(dst, dst_len * sizeof(CharT), src, copy_len * sizeof(CharT)))
                return static_cast<size_t>(-1);
            dst[copy_len] = 0;
            return copy_len;
        }

        /**
         * @brief 复制字符串，以终止字符结尾，如果目标缓冲区不足，则会截断字符串。
         * @param dst 目的缓冲区
         * @param dst_len 目的缓冲区最大尺寸，以字符为单位
         * @param src 源字符串
         * @param copy_len 复制长度，以字符为单位
         * @return
         */
        template<typename CharT>
        size_t copy(CharT* dst, const size_t dst_len, const CharT* src)
        {
            return copy<CharT>(dst, dst_len, src, length(src));
        }

        /**
         * @brief 复制字符串，以终止字符结尾，如果目标缓冲区不足，则会截断字符串。
         * @param dst 目的缓冲区
         * @param dst_len 目的缓冲区最大尺寸，以字符为单位
         * @param src 源字符串
         */
        template<typename CharT>
        size_t copy(CharT* dst, const size_t dst_len, const std::basic_string<CharT>& src)
        {
            size_t copy_len = src.size();
            if (copy_len > dst_len - 1)
                copy_len = dst_len - 1;
            if (memcpy_s(dst, dst_len * sizeof(CharT), &src[0], copy_len * sizeof(CharT)))
                return static_cast<size_t>(-1);
            dst[copy_len] = 0;
            return copy_len;
        }

        /**
         * @brief 复制字符串，以终止字符结尾，如果目标缓冲区不足，则会截断字符串。
         * @param dst 目的缓冲区
         * @tparam SizeT 目的缓冲区最大尺寸，以字符为单位
         * @param src 源字符串
         * @param copy_len 复制长度，以字符为单位
         */
        template<typename CharT, size_t SizeT>
        size_t copy(CharT(&dst)[SizeT], const CharT* src, size_t copy_len)
        {
            return copy<CharT>(dst, SizeT, src, copy_len);
        }

        /**
         * @brief 复制字符串，以终止字符结尾，如果目标缓冲区不足，则会截断字符串。
         * @param dst 目的缓冲区
         * @tparam SizeT 目的缓冲区最大尺寸，以字符为单位
         * @param src 源字符串
         * @param copy_len 复制长度，以字符为单位
         */
        template<typename CharT, size_t SizeT>
        size_t copy(CharT(&dst)[SizeT], const CharT* src)
        {
            return copy<CharT>(dst, SizeT, src, length(src));
        }

        /**
         * @brief 复制字符串，以终止字符结尾，如果目标缓冲区不足，则会截断字符串。
         * @param dst 目的缓冲区
         * @tparam SizeT 目的缓冲区最大尺寸，以字符为单位
         * @param src 源字符串
         */
        template<typename CharT, size_t SizeT>
        size_t copy(CharT(&dst)[SizeT], const std::basic_string<CharT>& src)
        {
            return copy<CharT>(dst, SizeT, src);
        }

        template<typename CharT>
        int to_int(const std::basic_string<CharT>& str)
        {
            if (str.empty())
                return 0;

            int result = 0;
            try
            {
                result = std::stoi(str);
            }
            catch (...)
            {
            }
            return result;
        }

        template<typename CharT>
        unsigned long to_ul(const std::basic_string<CharT>& str)
        {
            if (str.empty())
                return 0;

            unsigned long result = 0;
            try
            {
                result = std::stoul(str);
            }
            catch (...)
            {
            }
            return result;
        }

        template<typename CharT>
        std::basic_string<CharT> guid_to_string(const GUID* uuid) = delete;
        template<>
        std::string guid_to_string(const GUID* uuid);
        template<>
        std::wstring guid_to_string(const GUID* uuid);

        bool create_guid(_Out_ GUID& guid);

        template<typename CharT>
        std::basic_string<CharT> create_guid()
        {
            GUID guid;
            if (!create_guid(guid))
                return std::basic_string<CharT>();
            return guid_to_string<CharT>(&guid);
        }

        template <typename T>
        T get_random_string(size_t len) = delete;

        template <>
        std::string get_random_string(size_t len);

        template <>
        std::wstring get_random_string(size_t len);
    }

    PRINTF_ATTR(1, 2)
    std::string format(const char* pszText, ...);
    WPRINTF_ATTR(1, 2)
    std::wstring format(const wchar_t* pszText, ...);

    /**
     * @brief 将字符串列表拼接成字符串。
     * @tparam T
     * @param args 字符串列表
     * @param separator 分隔符
     * @return 返回拼接后的字符串。
    */
    template<typename S, typename T = typename S::value_type>
    T serialize_array(const S& args, const T& separator)
    {
        T result;
        for (const auto& v : args)
        {
            result.append(v);
            result.append(separator);
        }
        if (!args.empty())
            result.erase(result.size() - separator.size(), separator.size());
        return result;
    }

    /**
     * @brief 将字符串列表拼接成字符串。
     * @tparam M
     * @param map 字符串MAP
     * @return 返回拼接后的字符串。
    */
    template<template<typename...> class M, typename T, typename ...Ts>
    T serialize_map(const M<T, T, Ts...>& map)
    {
        std::wstring str;
        T result;
        result.push_back('{');
        for (const auto& v : map)
        {
            result.append(v.first);
            result.push_back(':');
            result.append(v.second);
            result.push_back(',');
        }
        if (!map.empty())
            result.pop_back();
        result.push_back('}');
        return result;
    }
}
