#include <wstd/registry.h>
#include <wstd/string.h>
#include <gtest/gtest.h>

TEST(file, read_registry)
{
    {
        std::wstring value;
        const std::wstring path = LR"(HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\网维大师服务)";
        const bool al = wstd::registry::read(path, L"ImagePath", value);
        wprintf_s(L"value: %ws\n", value.c_str());
        EXPECT_EQ(al, true);
        EXPECT_EQ(value, LR"(C:\Program Files\网维大师\ServerManager\ServerManager.exe)");
    }
    
}
