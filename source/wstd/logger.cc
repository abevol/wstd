#include <wstd/logger.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <time.h>
#include <locale.h>
#include <sys/timeb.h>
#include <list>

namespace logger
{
#pragma region PRIVATE

    bool g_log_started = false;
    int g_log_level = 0;
    int g_out_mode = 0;
    bool g_no_line_header = false;
    long g_max_file_size = 0;
    size_t g_max_file_count = 0;
    size_t g_current_file_index = 0;
    std::wstring g_log_directory_path;
    std::wstring g_log_file_path;
    std::string g_line_prefix;
    FILE* g_log_file = nullptr;
    tm g_last_log_file_time{};
    std::list<std::wstring> g_log_files_history;
    CRITICAL_SECTION g_cs;

    const CHAR* g_level_names[]{ "Trace", "Debug", "Info", "Warning", "Error" };

    extern "C" IMAGE_DOS_HEADER __ImageBase;

    std::string unicode_to_utf8(const std::wstring& wstr)
    {
        if (wstr.empty()) return std::string();
        const int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), nullptr, 0, nullptr, nullptr);
        if (!size_needed)
            return "";
        std::string strTo(size_needed, 0);
        if (!WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, nullptr, nullptr))
            return "";
        return strTo;
    }

    std::wstring utf8_to_unicode(const std::string& str)
    {
        if (str.empty()) return std::wstring();
        const int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), nullptr, 0);
        if (!size_needed)
            return L"";
        std::wstring wstrTo(size_needed, 0);
        if (!MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed))
            return L"";
        return wstrTo;
    }

    PRINTF_ATTR(1, 2)
    static void debug_msg(const char* pszText, ...)
    {
        std::string result;
        va_list args;

        va_start(args, pszText);
        auto len = _vscprintf(pszText, args);
        if (len < 0)
            return;
        result.resize((size_t)len);
        vsprintf_s(&result[0], result.size() + sizeof(TCHAR), pszText, args);
        va_end(args);

        result.append("\n");
        OutputDebugStringW(utf8_to_unicode(result).c_str());
        printf_s(result.c_str());
    }

    static HMODULE GetCurrentModule()
    {
        return (HINSTANCE)&__ImageBase;
    }

    static std::wstring GetModulePath(HMODULE module)
    {
        TCHAR path[MAX_PATH * sizeof(TCHAR)] = { 0, };
        GetModuleFileNameW(module, path, MAX_PATH * sizeof(TCHAR));
        return path;
    }

    static bool IsFileExist(const std::wstring& path)
    {
        const auto attr = GetFileAttributesW(path.c_str());
        return (attr != INVALID_FILE_ATTRIBUTES) && ((attr & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY);
    }

    static bool IsDirectoryExist(const std::wstring& path)
    {
        const auto attr = GetFileAttributesW(path.c_str());
        return (attr != INVALID_FILE_ATTRIBUTES) && ((attr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY);
    }

    static bool CreateDirectories(const std::wstring& path)
    {
        if (IsDirectoryExist(path))
            return true;

        if (IsFileExist(path))
            return false;

        bool result = true;
        auto pos = path.rfind('\\');
        if (pos != std::string::npos)
        {
            const auto parent = path.substr(0, pos);
            result = CreateDirectories(parent);
        }

        if (result)
            result = CreateDirectoryW(path.c_str(), nullptr);

        return result;
    }

    static const wchar_t* PathGetFilename(const wchar_t* path)
    {
        if (path)
        {
            const auto* pos = wcsrchr(path, L'\\');
            if (pos)
                return pos + 1;
            return path;
        }
        return L"";
    }

    static bool compare(const std::wstring& a, const std::wstring& b, bool no_case = false)
    {
        if (no_case)
            return (a.size() == b.size()) && (_wcsnicmp(a.c_str(), b.c_str(), a.size()) == 0);
        return a == b;
    }

    static bool starts_with(const std::wstring& src, const std::wstring& prefix, size_t offset = 0, bool no_case = false)
    {
        return compare(src.substr(offset, prefix.size()), prefix, no_case);
    }

    static bool ends_with(const std::wstring& src, const std::wstring& suffix, bool no_case = false)
    {
        return compare(src.substr(src.size() - suffix.size()), suffix, no_case);
    }

    static unsigned short get_level_color(int level)
    {
        switch (level)
        {
        case kTrace:
            return FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        case kDebug:
            return FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_BLUE;
        case kInfo:
            return FOREGROUND_INTENSITY | FOREGROUND_GREEN;
        case kWarning:
            return FOREGROUND_INTENSITY | FOREGROUND_GREEN | FOREGROUND_RED;
        case kError:
            return FOREGROUND_INTENSITY | FOREGROUND_RED;
        default:
            return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        }
    }

    static void set_console_text_color(int level)
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), get_level_color(level));
    }

    static void init_log_files_history()
    {
        auto log_dir = get_log_directory_path();
        if (!IsDirectoryExist(log_dir))
            return;

        const auto mod_path = GetModulePath(GetCurrentModule());
        const auto mod_name = mod_path.substr(mod_path.rfind(L'\\') + 1);

        if (log_dir.back() == '\\')
            log_dir.pop_back();

        auto find_path = log_dir;
        find_path.push_back('\\');
        find_path.push_back('*');

        WIN32_FIND_DATA find_data;
        HANDLE hFind = FindFirstFileW(find_path.c_str(), &find_data);
        if (hFind == INVALID_HANDLE_VALUE)
            return;

        g_log_files_history.clear();
        do
        {
            if (find_data.dwFileAttributes != INVALID_FILE_ATTRIBUTES &&
                (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY)
            {
                const auto filename = find_data.cFileName;
                if (starts_with(filename, mod_name) &&
                    ends_with(filename, L".log"))
                {
                    auto file_path = log_dir + L"\\" + filename;
                    g_log_files_history.emplace_back(file_path);
                }
            }
        } while (FindNextFile(hFind, &find_data));
        FindClose(hFind);
    }

    static void write(int level, const tm& lt, const std::string& result)
    {
        EnterCriticalSection(&g_cs);

        if (g_out_mode & kWinDebug)
            OutputDebugStringW(utf8_to_unicode(result).c_str());

        if (g_out_mode & kConsole)
        {
            set_console_text_color(level);
            printf_s("%hs\n", result.c_str());
            set_console_text_color(0);
        }

        if (g_out_mode & kDiskFile)
        {
            if (!g_log_file)
                open_log_file();

            if (g_last_log_file_time.tm_mday != lt.tm_mday)
                open_log_file();

            while (true)
            {
                if (g_log_file)
                {
                    fseek(g_log_file, 0, SEEK_END);
                    const auto file_size = ftell(g_log_file);
                    if (file_size >= g_max_file_size)
                        open_log_file();
                    else
                        break;
                }
            }

            if (g_log_file)
            {
                size_t write_size = fwrite(result.c_str(), sizeof(char), result.size(), g_log_file);
                if (write_size != result.size())
                {
                    errno_t err;
                    _get_errno(&err);
                    char err_msg[256];
                    strerror_s(err_msg, err);
                    debug_msg("[%hs:%u] error: %i, %hs", __FUNCTION__, __LINE__, err, err_msg);
                }
                fwrite("\n", sizeof(char), 1, g_log_file);
                fflush(g_log_file);
            }
        }

        LeaveCriticalSection(&g_cs);
    }

    static void print_v(int level, const wchar_t* file, unsigned int line, const wchar_t* func, const char* format, va_list args)
    {
        try
        {
            std::string result;
            std::string content;
            auto len = _vscprintf(format, args);
            if (len < 0)
            {
                errno_t err;
                _get_errno(&err);
                char err_msg[256];
                strerror_s(err_msg, err);
                debug_msg("[%hs:%u] error: %i, %hs", __FUNCTION__, __LINE__, err, err_msg);
                return;
            }
            content.resize(len);
            len = vsprintf_s(&content[0], content.size() + sizeof(char), format, args);
            if (len < 0)
            {
                errno_t err;
                _get_errno(&err);
                char err_msg[256];
                strerror_s(err_msg, err);
                debug_msg("[%hs:%u] error: %i, %hs", __FUNCTION__, __LINE__, err, err_msg);
                return;
            }

            __timeb64 today{};
            _ftime64_s(&today);
            tm lt{};
            localtime_s(&lt, &today.time);

            if (g_no_line_header)
            {
                result = content;
            }
            else
            {
                len = _scprintf("[%02d:%02d:%02d.%03d][%04x][%hs][%ws:%d][%ws] %hs",
                    lt.tm_hour, lt.tm_min, lt.tm_sec, today.millitm,
                    GetCurrentThreadId(),
                    g_level_names[level],
                    PathGetFilename(file),
                    line,
                    func,
                    content.c_str()
                );
                if (len < 0)
                {
                    errno_t err;
                    _get_errno(&err);
                    char err_msg[256];
                    strerror_s(err_msg, err);
                    debug_msg("[%hs:%u] error: %i, %hs", __FUNCTION__, __LINE__, err, err_msg);
                    return;
                }
                result.resize(len);
                len = sprintf_s(&result[0], result.size() + sizeof(char),
                    "[%02d:%02d:%02d.%03d][%04x][%hs][%ws:%d][%ws] %hs",
                    lt.tm_hour, lt.tm_min, lt.tm_sec, today.millitm,
                    GetCurrentThreadId(),
                    g_level_names[level],
                    PathGetFilename(file),
                    line,
                    func,
                    content.c_str()
                );
                if (len < 0)
                {
                    errno_t err;
                    _get_errno(&err);
                    char err_msg[256];
                    strerror_s(err_msg, err);
                    debug_msg("[%hs:%u] error: %i, %hs", __FUNCTION__, __LINE__, err, err_msg);
                    return;
                }
                
                result = g_line_prefix + result;
            }

            write(level, lt, result);
        }
        catch (std::exception& e)
        {
            debug_msg("[%hs] exception: %hs", __FUNCTION__, e.what());
        }
        catch (...)
        {
            debug_msg("[%hs] unknown exception", __FUNCTION__);
        }
    }

#pragma endregion PRIVATE

#pragma region PUBLIC

    void print(int level, const wchar_t* file, unsigned int line, const wchar_t* func, const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        print_v(level, file, line, func, format, args);
        va_end(args);
    }

    bool is_log_enable(int level)
    {
        if (level >= g_log_level && g_log_level < kLevelNone && g_out_mode & kOutModeAll)
            return true;
        return false;
    }

    void set_level(int level)
    {
        g_log_level = level;
    }

    void set_out_mode(int mode)
    {
        g_out_mode = mode;
    }

    void set_no_line_header(bool value)
    {
        g_no_line_header = value;
    }

    void set_max_file_size(long value)
    {
        g_max_file_size = value;
    }

    void set_max_file_count(size_t value)
    {
        g_max_file_count = value;
    }

    void set_line_prefix(const std::string& value)
    {
        g_line_prefix = value;
    }

    void set_log_directory_path(const std::wstring& path)
    {
        g_log_directory_path = path;
    }

    std::wstring get_log_directory_path()
    {
        if (g_log_directory_path.empty())
        {
            const auto mod_path = GetModulePath(GetCurrentModule());
            const auto mod_dir = mod_path.substr(0, mod_path.rfind('\\'));
            g_log_directory_path = mod_dir + L"\\log";
        }

        if (!IsDirectoryExist(g_log_directory_path))
            CreateDirectories(g_log_directory_path);

        return g_log_directory_path;
    }

    std::wstring get_log_file_path()
    {
        const auto mod_path = GetModulePath(GetCurrentModule());
        const auto mod_name = mod_path.substr(mod_path.rfind(L'\\') + 1);
        const auto log_dir = get_log_directory_path();

        __timeb64 today{};
        _ftime64_s(&today);
        tm lt{};
        localtime_s(&lt, &today.time);

        wchar_t log_file_path[MAX_PATH];
        swprintf_s(log_file_path, L"%ws\\%ws_p%u_%d%02d%02d_%02zu.log",
            log_dir.c_str(), mod_name.c_str(), GetCurrentProcessId(), lt.tm_year + 1900,
            lt.tm_mon + 1, lt.tm_mday, g_current_file_index);

        auto it = std::find(g_log_files_history.begin(), g_log_files_history.end(), log_file_path);
        if (it == g_log_files_history.end())
            g_log_files_history.emplace_back(log_file_path);

        g_current_file_index++;
        if (g_log_files_history.size() > g_max_file_count)
        {
            const auto& log_file = g_log_files_history.front();
            DeleteFileW(log_file.c_str());
            g_log_files_history.pop_front();
        }

        g_last_log_file_time = lt;
        return log_file_path;
    }

    bool open_log_file()
    {
        close_log_file();
        g_log_file_path = get_log_file_path();
        g_log_file = _wfsopen(g_log_file_path.c_str(), L"ab+,ccs=UTF-8", _SH_DENYNO);
        if (g_log_file)
        {
            fwrite("\xEF\xBB\xBF", sizeof(char), 3, g_log_file);
            return true;
        }
        return false;
    }

    void close_log_file()
    {
        if (g_log_file)
        {
            fclose(g_log_file);
            g_log_file = nullptr;
        }
    }

    void start_log(const std::wstring& log_dir, int level, int out, long max_file_size, size_t max_file_count)
    {
        if (g_log_started)
            return;
        g_log_started = true;

        InitializeCriticalSection(&g_cs);

        setlocale(LC_CTYPE, ".UTF-8");
        set_level(level);
        set_out_mode(out);
        set_max_file_size(max_file_size);
        set_max_file_count(max_file_count);
        set_log_directory_path(log_dir);

        init_log_files_history();
    }

    void stop_log()
    {
        g_log_started = false;
        close_log_file();
        DeleteCriticalSection(&g_cs);
    }

#pragma endregion PUBLIC
}
