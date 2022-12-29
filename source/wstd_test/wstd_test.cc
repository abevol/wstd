#include <Windows.h>
#include <string>
#include <thread>
#include <clocale>
#include <gtest/gtest.h>

#ifdef _WIN64
#ifdef _DEBUG
#pragma comment (lib,"gtest_x64_d.lib")
#else
#pragma comment (lib,"gtest_x64.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment (lib,"gtest_d.lib")
#else
#pragma comment (lib,"gtest.lib")
#endif
#endif

void InitConsole()
{
    SetConsoleCP(936);
    SetConsoleOutputCP(936);
    setlocale(LC_CTYPE, "");

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleScreenBufferSize(out, { 120, 3000 });
    SMALL_RECT sr{ 0, 0, 120, 30 };
    SetConsoleWindowInfo(out, FALSE, &sr);
}

GTEST_API_ int main(int argc, char** argv)
{
    InitConsole();
    printf("Running main() from %hs\n", __FILE__);
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
