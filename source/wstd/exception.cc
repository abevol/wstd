#include <wstd/exception.h>
#include <wstd/string.h>

namespace wstd
{
    std::exception exception(const char* pszText, ...)
    {
        std::string result;
        if (!pszText)
            return std::exception();
        va_list args;
        va_start(args, pszText);
        result = string::format_v(pszText, args);
        va_end(args);

        return std::exception(result.c_str());
    }
}
