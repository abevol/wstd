#include <wstd/config.h>
#include <wstd/string.h>
#include <gtest/gtest.h>
#include "constant.h"

TEST(config, read)
{
    const std::wstring cfg_file = L"../../../../source/wstd_test/data/test.ini";
    std::wstring value;
    bool result = wstd::config::read(L"test", L"test", L"", value, cfg_file.c_str());
    wprintf_s(L"value: %ws\n", value.c_str());
    EXPECT_EQ(result, true);
    EXPECT_EQ(value, L"中华人民共和国");
}
