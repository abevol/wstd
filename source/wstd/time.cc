#include <wstd/time.h>
#include <chrono>
#include <sys/timeb.h>

namespace wstd
{
    namespace time
    {
        std::time_t get_timestamp_sec()
        {
            __timeb64 buf{};
            _ftime64_s(&buf);
            return buf.time;
        }

        std::time_t get_timestamp_msec()
        {
            __timeb64 buf{};
            _ftime64_s(&buf);
            return buf.time * 1000 + buf.millitm;
        }

        std::time_t localtime_string_to_timestamp(const std::string& str)
        {
            tm ltime;
            int year, month, day, hour, minute, second;
            sscanf_s(str.c_str(), "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second);
            ltime.tm_year = year - 1900;
            ltime.tm_mon = month - 1;
            ltime.tm_mday = day;
            ltime.tm_hour = hour;
            ltime.tm_min = minute;
            ltime.tm_sec = second;
            ltime.tm_isdst = 0;

            time_t unix = mktime(&ltime);
            return unix;
        }

        std::string timestamp_to_localtime_string(std::time_t unix_time, const std::string& format)
        {
            char buf[255];
            tm local_time{};
            if (localtime_s(&local_time, &unix_time) == NULL)
            {
                sprintf_s(buf, format.c_str(), local_time.tm_year + 1900, local_time.tm_mon + 1,
                          local_time.tm_mday, local_time.tm_hour, local_time.tm_min, local_time.tm_sec);
                return buf;
            }
            return "";
        }

        std::wstring timestamp_to_localtime_wstring(std::time_t unix_time, const std::wstring& format)
        {
            wchar_t buf[255];
            tm local_time{};
            if (localtime_s(&local_time, &unix_time) == NULL)
            {
                swprintf_s(buf, format.c_str(), local_time.tm_year + 1900, local_time.tm_mon + 1,
                           local_time.tm_mday, local_time.tm_hour, local_time.tm_min, local_time.tm_sec);
                return buf;
            }
            return L"";
        }

        std::string get_localtime_string(const std::string& format)
        {
            std::time_t unix_time;
            ::time(&unix_time);
            return timestamp_to_localtime_string(unix_time, format);
        }

        std::wstring get_localtime_wstring(const std::wstring& format)
        {
            std::time_t unix_time;
            ::time(&unix_time);
            return timestamp_to_localtime_wstring(unix_time, format);
        }

        LONGLONG filetime_to_timestamp(FILETIME ft)
        {
            // takes the last modified date
            LARGE_INTEGER date, adjust;
            date.HighPart = ft.dwHighDateTime;
            date.LowPart = ft.dwLowDateTime;

            // 100-nanoseconds = milliseconds * 10000
            adjust.QuadPart = 11644473600000 * 10000ULL;

            // removes the diff between 1970 and 1601
            date.QuadPart -= adjust.QuadPart;

            // converts back from 100-nanoseconds to seconds
            return date.QuadPart / 10000000ULL;
        }

        LONGLONG filetime_to_timestamp(ULARGE_INTEGER date)
        {
            // takes the last modified date
            LARGE_INTEGER adjust;

            // 100-nanoseconds = milliseconds * 10000
            adjust.QuadPart = 11644473600000 * 10000ULL;

            // removes the diff between 1970 and 1601
            date.QuadPart -= adjust.QuadPart;

            // converts back from 100-nanoseconds to seconds
            return date.QuadPart / 10000000ULL;
        }

        BOOL time_string_to_filetime(const CHAR* timeStr, ULARGE_INTEGER& filetime, int timeZone)
        {
            if (timeStr)
            {
                // 2019-11-08 16:21:56.010
                SYSTEMTIME st{};
                if (7 == sscanf_s(timeStr, "%hu-%02hu-%02hu %02hu:%02hu:%02hu.%03hu",
                                  &st.wYear, &st.wMonth, &st.wDay, &st.wHour, &st.wMinute, &st.wSecond,
                                  &st.wMilliseconds))
                {
                    FILETIME ft{};
                    if (SystemTimeToFileTime(&st, &ft))
                    {
                        filetime.LowPart = ft.dwLowDateTime;
                        filetime.HighPart = ft.dwHighDateTime;
                        if (timeZone)
                        {
                            filetime.QuadPart = filetime.QuadPart - (ULONGLONG)timeZone * 60 * 60 * 10000000ULL;
                        }
                        return TRUE;
                    }
                }
            }
            return FALSE;
        }

        std::string filetime_to_time_string(ULARGE_INTEGER filetime, int timeZone)
        {
            // 2019-11-08 16:21:56.010
            std::string result;
            SYSTEMTIME st{};
            if (timeZone)
                filetime.QuadPart = filetime.QuadPart + (ULONGLONG)timeZone * 60 * 60 * 10000000ULL;
            FILETIME ft{filetime.LowPart, filetime.HighPart};
            if (FileTimeToSystemTime(&ft, &st))
            {
                const auto len = _scprintf("%d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour,
                                           st.wMinute, st.wSecond);
                result.resize(len);
                sprintf_s(const_cast<char*>(result.data()), result.size() + 1, "%d-%02d-%02d %02d:%02d:%02d", st.wYear,
                          st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            }
            return result;
        }
    }
}
