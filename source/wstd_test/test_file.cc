#include <wstd/file.h>
#include <wstd/string.h>
#include <gtest/gtest.h>
#include "constant.h"

TEST(file, read_file)
{
    const std::wstring cfg_file = L"../../../../source/wstd_test/data/test.txt";
    const std::string value = wstd::file::read_file<std::string>(cfg_file);
    wprintf_s(L"value: %ws\n", wstd::string::local_to_unicode(value).c_str());
    EXPECT_EQ(wstd::string::local_to_unicode(value), L"中华人民共和国");
}

TEST(file, create_directories)
{
    {
        const std::wstring dir_path = L"create_directories\\01\\02\\03";
        const bool value = wstd::file::create_directories(dir_path);
        wprintf_s(L"value: %u, error: %u\n", value, GetLastError());
        EXPECT_EQ(value, true);
    }
    {
        const std::wstring dir_path = L".\\create_directories\\02\\03\\04";
        const bool value = wstd::file::create_directories(dir_path);
        wprintf_s(L"value: %u, error: %u\n", value, GetLastError());
        EXPECT_EQ(value, true);
    }
}
