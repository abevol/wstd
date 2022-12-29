#ifdef USING_SQLITE3
#include <wstd/sqlite.h>
#include <wstd/string.h>
#include <gtest/gtest.h>
#include "constant.h"

#ifdef _WIN64
#ifdef _DEBUG
#pragma comment (lib,"sqlite3_x64_d.lib")
#else
#pragma comment (lib,"sqlite3_x64.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment (lib,"sqlite3_d.lib")
#else
#pragma comment (lib,"sqlite3.lib")
#endif
#endif

TEST(sqlite, exec)
{
    const std::wstring db_file = L"../../../../source/wstd_test/data/barserver.db";
    const std::wstring sql = L"SELECT IdcClass FROM tbl_Package WHERE PkgType = 19";
    std::vector<std::wstring> result;
    wstd::sqlite::exec(db_file, sql, 936, result);

    const std::wstring result_str = wstd::serialize_array(result, std::wstring(L", "));
    EXPECT_EQ(result_str, L"系统更新, 系统更新");
}
#endif
