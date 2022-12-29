/**
 * @file time.h
 * @brief 
 * @date 2021-04-25
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"
#include <ctime>

namespace wstd
{
    namespace time
    {
        std::time_t get_timestamp_sec();

        std::time_t get_timestamp_msec();

        std::time_t localtime_string_to_timestamp(const std::string& str);

        std::string timestamp_to_localtime_string(std::time_t unix_time, const std::string& format = "%d-%d-%d.%d:%d:%d");

        std::wstring timestamp_to_localtime_wstring(std::time_t unix_time, const std::wstring& format);

        std::string get_localtime_string(const std::string& format = "%d-%d-%d.%d:%d:%d");

        std::wstring get_localtime_wstring(const std::wstring& format = L"%d-%d-%d.%d:%d:%d");

        LONGLONG filetime_to_timestamp(FILETIME ft);

        LONGLONG filetime_to_timestamp(ULARGE_INTEGER date);

        BOOL time_string_to_filetime(const CHAR* timeStr, ULARGE_INTEGER& filetime, int timeZone);

        std::string filetime_to_time_string(ULARGE_INTEGER filetime, int timeZone);
    }
}
