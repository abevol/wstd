#include <wstd/crypto/base64.h>
#include <wstd/crypto/crypto.h>
#include <wstd/file.h>
#include <wstd/string.h>
#include <gtest/gtest.h>
#include <wincrypt.h>
#include "constant.h"

#pragma comment(lib, "Crypt32.lib")

TEST(crypto, base64_encode)
{
    std::string data = R"([^ "<>|\n\*\?]*(?:.exe|.bat|.vbs))";
    std::string value = base64_encode(data);
    wprintf_s(L"value, %zu: %S\n", value.size(), value.c_str());

    std::string value_win = wstd::crypto::base64_encode<std::string>(data);
    wprintf_s(L"value_win, %zu: %S\n", value_win.size(), value_win.c_str());

    std::wstring value_win_w = wstd::crypto::base64_encode<std::wstring>(data);
    wprintf_s(L"value_win_w, %zu: %ws\n", value_win_w.size(), value_win_w.c_str());

    EXPECT_EQ(value, "W14gIjw+fFxuXCpcP10qKD86LmV4ZXwuYmF0fC52YnMp");
    EXPECT_EQ(value_win_w, L"W14gIjw+fFxuXCpcP10qKD86LmV4ZXwuYmF0fC52YnMp");
    EXPECT_EQ(value, value_win);
}

TEST(crypto, base64_decode)
{
    std::string data = R"(W14gIjw+fFxuXCpcP10qKD86LmV4ZXwuYmF0fC52YnMp)";
    std::wstring data_w = LR"(W14gIjw+fFxuXCpcP10qKD86LmV4ZXwuYmF0fC52YnMp)";
    std::string value = base64_decode(data);
    wprintf_s(L"value, %zu: %S\n", value.size(), value.c_str());

    std::string value_win = wstd::crypto::base64_decode(data);
    wprintf_s(L"value_win, %zu: %S\n", value_win.size(), value_win.c_str());

    std::string value_win_w = wstd::crypto::base64_decode(data_w);
    wprintf_s(L"value_win_w, %zu: %S\n", value_win_w.size(), value_win_w.c_str());

    std::string target = R"([^ "<>|\n\*\?]*(?:.exe|.bat|.vbs))";
    EXPECT_EQ(value, target);
    EXPECT_EQ(value_win_w, target);
    EXPECT_EQ(value, value_win);
}

TEST(crypto, base64_encode_perf)
{
    std::string data = R"([^ "<>|\n\*\?]*(?:.exe|.bat|.vbs))";
    for (int i = 0; i < 15; ++i)
    {
        data = data + data;
    }

    std::string value;
    DWORD t1 = GetTickCount();
    for (int i = 0; i < 10; ++i)
    {
        value = base64_encode(data);
    }
    t1 = GetTickCount() - t1;
    wprintf_s(L"t1: %u, value: %zu\n", t1, value.size());
    
    std::wstring value_win;
    DWORD t2 = GetTickCount();
    for (int i = 0; i < 10; ++i)
    {
        value_win = wstd::crypto::base64_encode<std::wstring>(data);
    }
    t2 = GetTickCount() - t2;
    wprintf_s(L"t2: %u, value_win: %zu\n", t2, value_win.size());

#ifdef _DEBUG
    EXPECT_GT(t1, t2);
#else
    EXPECT_LT(t1, t2);
#endif
}

TEST(crypto, base64_encode_file)
{
    std::string data = wstd::file::read_file<std::string>(L"../../../../source/wstd_test/data/Base64.us.html");
    EXPECT_FALSE(data.empty());

    std::string value = base64_encode(data);
    wprintf_s(L"value, %zu\n", value.size());

    std::string value_win = wstd::crypto::base64_encode<std::string>(data);
    wprintf_s(L"value_win, %zu\n", value_win.size());

    std::wstring value_win_w = wstd::crypto::base64_encode<std::wstring>(data);
    wprintf_s(L"value_win_w, %zu\n", value_win_w.size());

    EXPECT_EQ(value, wstd::string::unicode_to_utf8(value_win_w));
    EXPECT_EQ(value, value_win);
}
