/**
 * @file logger.h
 * @brief 简单日志输出
 * @date 2021-04-30
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include <string>

#if defined(__RESHARPER__) || defined(__GNUC__)
#define PRINTF_ATTR(StringIndex, FirstToCheck) \
        [[gnu::format(printf, StringIndex, FirstToCheck)]]
#else
#define PRINTF_ATTR(StringIndex, FirstToCheck)
#endif

#define COMPUTER_KB		 (1024)
#define COMPUTER_MB		 (COMPUTER_KB*1024)

namespace logger
{
    /// 日志级别
    enum Level
    {
        kTrace,     ///< 跟踪级别
        kDebug,     ///< 调试级别
        kInfo,      ///< 普通信息级别
        kWarning,   ///< 警告级别
        kError,     ///< 错误级别
        kLevelAll = kTrace,  ///< 打印全部级别
        kLevelNone = 0xFF  ///< 不打印日志
    };

    /// 日志输出模式
    enum OutMode
    {
        kOutModeNone = 0x00, ///< 不输出日志
        kConsole = 0x01,     ///< 控制台输出
        kDiskFile = 0x02,    ///< 日志文件输出
        kWinDebug = 0x04,    ///< Win32 Debug输出
        kOutModeAll = 0x07,  ///< 全模式输出
    };

    bool is_log_enable(int level);
    void set_level(int level);
    void set_out_mode(int mode);
    void set_no_line_header(bool value);
    void set_max_file_size(long value);
    void set_max_file_count(size_t value);
    void set_line_prefix(const std::string& value);
    void set_log_directory_path(const std::wstring& path);
    std::wstring get_log_directory_path();
    std::wstring get_log_file_path();
    bool open_log_file();
    void close_log_file();
    void start_log(const std::wstring& log_dir = L"", int level = kWarning, int out = kDiskFile,
        long max_file_size = 100 * COMPUTER_MB, size_t max_file_count = 10);
    void stop_log();

    PRINTF_ATTR(5, 6)
    void print(int level, const wchar_t* file, unsigned int line, const wchar_t* func, const char* format, ...);
    
    class FuncTrace
    {
    public:
        FuncTrace(const wchar_t* file, unsigned int line, const wchar_t* func)
            : m_file(file), m_line(line), m_func(func)
        {
            if (logger::is_log_enable(kTrace))
                print(kTrace, file, line, func, "Begin");
        }

        ~FuncTrace()
        {
            if (logger::is_log_enable(kTrace))
                print(kTrace, m_file, m_line, m_func, "End");
        }

    private:
        const wchar_t* m_file;
        unsigned int m_line;
        const wchar_t* m_func;
    };
}

/// 日志级别
enum LogLevel
{
    kTrace = logger::kTrace,         ///< 跟踪级别
    kDebug = logger::kDebug,         ///< 调试级别
    kInfo = logger::kInfo,           ///< 普通信息级别
    kWarning = logger::kWarning,     ///< 警告级别
    kError = logger::kError,         ///< 错误级别
    kLevelAll = logger::kLevelAll,   ///< 打印全部级别
    kLevelNone = logger::kLevelNone  ///< 不打印日志
};

#ifdef LOGGER_NO_FUNC
#define LOGGER_FUNC L""
#else
#define LOGGER_FUNC (L"[" __FUNCTIONW__ L"]")
#endif

#ifdef LOGGER_NO_LOG
#define _UNUSED_FUNC(...)  (void)0

#define log_print    _UNUSED_FUNC
#define log_trace    _UNUSED_FUNC
#define log_debug    _UNUSED_FUNC
#define log_info     _UNUSED_FUNC
#define log_warn     _UNUSED_FUNC
#define log_error    _UNUSED_FUNC
#define trace_func   _UNUSED_FUNC
#else

#define log_print(level, ...) \
    if (logger::is_log_enable(level)) \
        logger::print(level, __FILEW__, __LINE__, LOGGER_FUNC, __VA_ARGS__)

#define log_trace(...) \
    if (logger::is_log_enable(logger::kTrace)) \
        logger::print(logger::kTrace, __FILEW__, __LINE__, LOGGER_FUNC, __VA_ARGS__)

#define log_debug(...) \
    if (logger::is_log_enable(logger::kDebug)) \
        logger::print(logger::kDebug, __FILEW__, __LINE__, LOGGER_FUNC, __VA_ARGS__)

#define log_info(...) \
    if (logger::is_log_enable(logger::kInfo)) \
        logger::print(logger::kInfo, __FILEW__, __LINE__, LOGGER_FUNC, __VA_ARGS__)

#define log_warn(...) \
    if (logger::is_log_enable(logger::kWarning)) \
        logger::print(logger::kWarning, __FILEW__, __LINE__, LOGGER_FUNC, __VA_ARGS__)

#define log_error(...) \
    if (logger::is_log_enable(logger::kError)) \
        logger::print(logger::kError, __FILEW__, __LINE__, LOGGER_FUNC, __VA_ARGS__)

#define trace_func() \
        logger::FuncTrace funcTrace(__FILEW__, __LINE__, LOGGER_FUNC)

#endif // !LOGGER_NO_LOG
