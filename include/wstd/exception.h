/**
 * @file exception.h
 * @brief
 * @date 2021-04-19
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"
#include <string>
#include <exception>

namespace wstd
{
    PRINTF_ATTR(1, 2)
    std::exception exception(const char* pszText, ...);
}
