#include "constant.h"

namespace constant
{
    std::string kSimpleChineseString("\xD6\xD0\xBB\xAA\xC8\xCB\xC3\xF1\xB9\xB2\xBA\xCD\xB9\xFA\xCD\xF2\xCB\xEA\xA3\xA1");
    std::wstring kSimpleChineseStringW(L"中华人民共和国万岁！");
    std::string kSimpleChineseStringUTF8(u8"中华人民共和国万岁！");

    std::string kLowerString(
        "abcdefghijklmnopqrstuvwxyz01234567890~!@#$%^&*()_+-={}[]|:;'.><,?");
    std::wstring kLowerStringW(
        L"abcdefghijklmnopqrstuvwxyz01234567890~!@#$%^&*()_+-={}[]|:;'.><,?");

    std::string kUpperString(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890~!@#$%^&*()_+-={}[]|:;'.><,?");
    std::wstring kUpperStringW(
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890~!@#$%^&*()_+-={}[]|:;'.><,?");

    std::string kLowerHexString(
        "6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435"
        "36373839307e21402324255e262a28295f2b2d3d7b7d5b5d7c3a3b272e3e3c2c"
        "3f");

    std::wstring kLowerHexStringW(
        L"6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435"
        L"36373839307e21402324255e262a28295f2b2d3d7b7d5b5d7c3a3b272e3e3c2c"
        L"3f");

    std::string kFormatString(
        "abcdefghijklmnopqrstuvwxyz01234567890~!@#$%^&*()_+-={}[]|:;'.><,?"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890~!@#$%^&*()_+-={}[]|:;'.><,?");
}
