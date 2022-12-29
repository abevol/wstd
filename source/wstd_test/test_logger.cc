#include <wstd/logger.h>
#include <wstd/string.h>
#include <gtest/gtest.h>
#include "constant.h"

TEST(config, logger)
{
    logger::start_log();
    log_trace("kSimpleChineseStringW: %ws", constant::kSimpleChineseStringW.c_str());
    log_warn("kSimpleChineseString: %hs", constant::kSimpleChineseString.c_str());
    log_warn("kSimpleChineseStringW: %ws", constant::kSimpleChineseStringW.c_str());
    log_error("kSimpleChineseStringUTF8: %hs", constant::kSimpleChineseStringUTF8.c_str());
    logger::stop_log();
}
