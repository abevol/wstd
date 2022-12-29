#include <wstd/string.h>
#include <gtest/gtest.h>
#include "constant.h"

// 编码转换
TEST(string, transcoding)
{
    { // GB2312转UNICODE
        std::wstring unicode_string = wstd::string::codepage_to_unicode(constant::kSimpleChineseString, 936);
        EXPECT_EQ(unicode_string, constant::kSimpleChineseStringW);
    }
    { // UNICODE转GB2312
        std::string gb2312_string = wstd::string::unicode_to_codepage(constant::kSimpleChineseStringW, 936);
        EXPECT_EQ(gb2312_string, constant::kSimpleChineseString);
    }
    { // UTF-8转UNICODE
        std::wstring unicode_string = wstd::string::utf8_to_unicode(constant::kSimpleChineseStringUTF8);
        EXPECT_EQ(unicode_string, constant::kSimpleChineseStringW);
    }
    { // UNICODE转UTF-8
        std::string utf8_string = wstd::string::unicode_to_utf8(constant::kSimpleChineseStringW);
        EXPECT_EQ(utf8_string, constant::kSimpleChineseStringUTF8);
    }
}

// 复制字符串
TEST(string, copy_string)
{
    {
        char buf[10];
        size_t copy_size = wstd::string::copy(buf, _countof(buf), "0123456789", 10);
        EXPECT_EQ(copy_size, _countof(buf) - 1);
        EXPECT_STREQ(buf, "012345678");
    }
    {
        wchar_t buf[10];
        size_t copy_size = wstd::string::copy(buf, _countof(buf), L"0123456789", 10);
        EXPECT_EQ(copy_size, _countof(buf) - 1);
        EXPECT_STREQ(buf, L"012345678");
    }
    {
        char buf[10];
        size_t copy_size = wstd::string::copy(buf, "0123456789", 10);
        EXPECT_EQ(copy_size, _countof(buf) - 1);
        EXPECT_STREQ(buf, "012345678");
    }
    {
        wchar_t buf[10];
        size_t copy_size = wstd::string::copy(buf, L"0123456789", 10);
        EXPECT_EQ(copy_size, _countof(buf) - 1);
        EXPECT_STREQ(buf, L"012345678");
    }
    {
        char buf[10];
        size_t copy_size = wstd::string::copy(buf, "0123456789");
        EXPECT_EQ(copy_size, _countof(buf) - 1);
        EXPECT_STREQ(buf, "012345678");
    }
    {
        wchar_t buf[10];
        size_t copy_size = wstd::string::copy(buf, L"0123456789");
        EXPECT_EQ(copy_size, _countof(buf) - 1);
        EXPECT_STREQ(buf, L"012345678");
    }
    {
        char buf[10];
        std::string source = "0123456789";
        size_t copy_size = wstd::string::copy(buf, source);
        EXPECT_EQ(copy_size, _countof(buf) - 1);
        EXPECT_STREQ(buf, "012345678");
    }
    {
        wchar_t buf[10];
        std::wstring source = L"0123456789";
        size_t copy_size = wstd::string::copy(buf, source);
        EXPECT_EQ(copy_size, _countof(buf) - 1);
        EXPECT_STREQ(buf, L"012345678");
    }
    {
        char buf[100];
        std::string source = "0123456789";
        size_t copy_size = wstd::string::copy(buf, source);
        EXPECT_EQ(copy_size, source.size());
        EXPECT_STREQ(buf, source.c_str());
    }
    {
        wchar_t buf[100];
        std::wstring source = L"0123456789";
        size_t copy_size = wstd::string::copy(buf, source);
        EXPECT_EQ(copy_size, source.size());
        EXPECT_STREQ(buf, source.c_str());
    }
    {
        char buf[10];
        size_t copy_size = wstd::string::copy(buf, "", 0);
        EXPECT_EQ(copy_size, 0);
        EXPECT_STREQ(buf, "");
    }
    {
        wchar_t buf[10];
        size_t copy_size = wstd::string::copy(buf, L"", 0);
        EXPECT_EQ(copy_size, 0);
        EXPECT_STREQ(buf, L"");
    }
}

// 格式化字符串
TEST(string, format_string)
{
    {
        char buf[255];
        sprintf_s(buf, 255, "%i\t%u\t%.02f\t0x%X\t%p\t%hs\t%ws\n", 1, MAXDWORD, 3.1415926, MAXDWORD, buf, "123", L"abc");
        const auto str = wstd::format("%i\t%u\t%.02f\t0x%X\t%p\t%hs\t%ws\n", 1, MAXDWORD, 3.1415926, MAXDWORD, buf, "123", L"abc");
        EXPECT_EQ(buf, str);
    }
    {
        wchar_t buf[255];
        swprintf_s(buf, 255, L"%i\t%u\t%.02f\t0x%X\t%p\t%ws\t%hs\n", 1, MAXDWORD, 3.1415926, MAXDWORD, buf, L"123", "abc");
        const auto str = wstd::format(L"%i\t%u\t%.02f\t0x%X\t%p\t%ws\t%hs\n", 1, MAXDWORD, 3.1415926, MAXDWORD, buf, L"123", "abc");
        EXPECT_EQ(buf, str);
    }
}

// 序列化字符串
TEST(string, serialize_string)
{
    // string
    {
        const std::vector<std::string> vec{"a", "b", "c"};
        const auto buf = wstd::serialize_array(vec, std::string(", "));
        const auto str = std::string("a, b, c");
        EXPECT_EQ(buf, str);
    }
    {
        const std::vector<std::string> vec{ "a", "b", "c" };
        const auto buf = wstd::serialize_array<std::vector<std::string>>(vec, std::string(", "));
        const auto str = std::string("a, b, c");
        EXPECT_EQ(buf, str);
    }
    {
        const std::list<std::string> list{ "a", "b", "c" };
        const auto buf = wstd::serialize_array(list, std::string(", "));
        const auto str = std::string("a, b, c");
        EXPECT_EQ(buf, str);
    }
    {
        const std::map<std::string, std::string> map{ {"a", "1"}, {"b", "2"} , {"c", "3"} };
        const auto buf = wstd::serialize_map(map);
        const auto str = std::string("{a:1,b:2,c:3}");
        EXPECT_EQ(buf, str);
    }
    {
        const std::unordered_map<std::string, std::string> map{ {"a", "1"}, {"b", "2"} , {"c", "3"} };
        const auto buf = wstd::serialize_map(map);
        const auto str = std::string("{a:1,b:2,c:3}");
        EXPECT_EQ(buf, str);
    }

    // wstring
    {
        const std::vector<std::wstring> vec{ L"a", L"b", L"c" };
        const auto buf = wstd::serialize_array(vec, std::wstring(L", "));
        const auto str = std::wstring(L"a, b, c");
        EXPECT_EQ(buf, str);
    }
    {
        const std::vector<std::wstring> vec{ L"a", L"b", L"c" };
        const auto buf = wstd::serialize_array< std::vector<std::wstring>>(vec, std::wstring(L", "));
        const auto str = std::wstring(L"a, b, c");
        EXPECT_EQ(buf, str);
    }
    {
        const std::list<std::wstring> list{ L"a", L"b", L"c" };
        const auto buf = wstd::serialize_array(list, std::wstring(L", "));
        const auto str = std::wstring(L"a, b, c");
        EXPECT_EQ(buf, str);
    }
    {
        const std::map<std::wstring, std::wstring> map{ {L"a", L"1"}, {L"b", L"2"} , {L"c", L"3"} };
        const auto buf = wstd::serialize_map(map);
        const auto str = std::wstring(L"{a:1,b:2,c:3}");
        EXPECT_EQ(buf, str);
    }
    {
        const std::unordered_map<std::wstring, std::wstring> map{ {L"a", L"1"}, {L"b", L"2"} , {L"c", L"3"} };
        const auto buf = wstd::serialize_map(map);
        const auto str = std::wstring(L"{a:1,b:2,c:3}");
        EXPECT_EQ(buf, str);
    }
}

// 计算字符串长度
TEST(string, length_string)
{
    {
        size_t len_string = wstd::string::length(constant::kSimpleChineseStringUTF8);
        size_t len_w_string = wstd::string::length(constant::kSimpleChineseStringW);
        size_t len_string_c = wstd::string::length(constant::kSimpleChineseStringUTF8.c_str());
        size_t len_w_string_c = wstd::string::length(constant::kSimpleChineseStringW.c_str());

        EXPECT_EQ(len_string, 30);
        EXPECT_EQ(len_string, len_string_c);
        EXPECT_EQ(len_w_string, 10);
        EXPECT_EQ(len_w_string, len_w_string_c);
    }
}
