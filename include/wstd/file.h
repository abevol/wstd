/**
 * @file file.h
 * @brief 
 * @date 2021-04-06
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"

namespace wstd
{
    namespace file
    {
        std::wstring get_parent_path(const std::wstring& path);

        /**
         * @brief 判断文件是否存在。
         * @param path 文件路径。
         * @param disable_wow64 处理32位进程产生的路径，不需要禁用Wow64路径重定向；
         *                     处理64位进程产生的路径，则需要禁用Wow64路径重定向。
         * @return 存在返回true，不存在返回false。
         */
        bool is_file_exist(const std::wstring& path, bool disable_wow64);

        bool is_directory_exist(const std::wstring& path, bool disable_wow64);

        bool is_file_or_directory_exist(const std::wstring& path, bool disable_wow64);

        int sh_copy_directory(const std::wstring& src, const std::wstring& dst);

        int sh_move_file(const std::wstring& src, const std::wstring& dst);

        int sh_rename_file(const std::wstring& src, const std::wstring& dst);

        int sh_delete_directory(const std::wstring& src);

        bool delete_file_on_reboot(const std::wstring& filePath);

        /**
         * @brief 删除文件或文件夹。
         * @param filePath 文件路径。
         * @param rebootDel 常规删除失败后是否使用重启删除。
         * @param disableWow64 禁用Wow64重定向。
         * @return 是否删除成功。
         */
        bool delete_file_ex(const std::wstring& filePath, bool rebootDel, bool disableWow64);

        bool delete_directory(const std::wstring& dirPath, const std::vector<std::wstring>& excluded,
                              bool rebootDel, bool disableWow64);

        HANDLE create_file(
            _In_ LPCWSTR lpFileName,
            _In_ DWORD dwDesiredAccess,
            _In_ DWORD dwShareMode,
            _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            _In_ DWORD dwCreationDisposition,
            _In_ DWORD dwFlagsAndAttributes,
            _In_opt_ HANDLE hTemplateFile);

        template<typename ValueT>
        ValueT read_file(const std::wstring& filename) = delete;

        template<>
        std::string read_file<std::string>(const std::wstring& filename);

        template<>
        std::wstring read_file<std::wstring>(const std::wstring& filename);

        template<typename ValueT>
        ValueT read_file(const std::wstring& filename, size_t len) = delete;

        template<>
        std::string read_file<std::string>(const std::wstring& filename, size_t len);

        template<>
        std::wstring read_file<std::wstring>(const std::wstring& filename, size_t len);

        bool write_file(const std::wstring& filename, const std::string& data, bool append = false);
        bool write_file(const std::wstring& filename, const std::wstring& data, bool append = false);
        bool write_file(const std::wstring& filename, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, bool append = false);

        std::wstring get_filename(const std::wstring& path);
        std::wstring get_filename_without_extension(const std::wstring& path);
        std::wstring get_file_extension(const std::wstring& path);

        BOOL is_pe_file(HANDLE hFile);
        BOOL is_pe_file(LPCWSTR szFilePath);
        BOOL is_pe_file(const std::wstring& filePath);

        BOOL is_compressed_file(const std::wstring& file_path);

        BOOL get_file_time(const std::wstring& filePath, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime);

        std::string get_pe_file_version(const std::wstring& path);

        std::string get_pe_product_version(const std::wstring& path);

        int compare_version(const char* v1, const char* v2);

        std::wstring get_debug_file(const std::wstring& filename);

        std::wstring get_long_path(const std::wstring& short_path);

        std::wstring get_temp_path();

        bool create_random_directory(_Out_ std::wstring& random_path, int depth = 1);

        /**
         * @brief 创建多级目录。
         * @param path 多级目录路径，支持绝对路径和相对路径。
         * @return 返回成功或失败，如果目录已存在，则返回成功。
        */
        bool create_directories(const std::wstring& path);
    }
}
