#include <wstd/file.h>
#include "wstd/string.h"
#include <wstd/process.h>
#include <shellapi.h>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Version.lib")

namespace wstd
{
    namespace file
    {
        std::wstring get_parent_path(const std::wstring& path)
        {
            auto pos = path.rfind(L'\\');
            if (pos == std::wstring::npos)
            {
                pos = path.rfind(L'/');
                if (pos == std::wstring::npos)
                    return path;
            }
            return path.substr(0, pos);
        }

        bool is_file_exist(const std::wstring& path, bool disable_wow64)
        {
            BOOL ret = FALSE;
            PVOID old_value = nullptr;
            if (disable_wow64)
                ret = Wow64DisableWow64FsRedirection(&old_value);
            auto attr = GetFileAttributes(path.c_str());
            if (disable_wow64 && ret)
                Wow64RevertWow64FsRedirection(old_value);
            return (attr != INVALID_FILE_ATTRIBUTES) && ((attr & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY);
        }

        bool is_directory_exist(const std::wstring& path, bool disable_wow64)
        {
            BOOL ret = FALSE;
            PVOID old_value = nullptr;
            if (disable_wow64)
                ret = Wow64DisableWow64FsRedirection(&old_value);
            auto attr = GetFileAttributes(path.c_str());
            if (disable_wow64 && ret)
                Wow64RevertWow64FsRedirection(old_value);
            return (attr != INVALID_FILE_ATTRIBUTES) && ((attr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY);
        }

        bool is_file_or_directory_exist(const std::wstring& path, bool disable_wow64)
        {
            BOOL ret = FALSE;
            PVOID ol_value = nullptr;
            if (disable_wow64)
                ret = Wow64DisableWow64FsRedirection(&ol_value);
            auto attr = GetFileAttributes(path.c_str());
            if (disable_wow64 && ret)
                Wow64RevertWow64FsRedirection(ol_value);
            return (attr != INVALID_FILE_ATTRIBUTES);
        }

        int sh_copy_directory(const std::wstring& src, const std::wstring& dst)
        {
            WCHAR sf[MAX_PATH + 1];
            WCHAR tf[MAX_PATH + 1];

            wcscpy_s(sf, MAX_PATH, src.c_str());
            wcscpy_s(tf, MAX_PATH, dst.c_str());
            wcscpy_s(sf + src.size(), MAX_PATH, L"\\*");

            sf[wcslen(sf) + 1] = 0;
            tf[wcslen(tf) + 1] = 0;

            SHFILEOPSTRUCT s;
            memset(&s, 0, sizeof(s));
            s.wFunc = FO_COPY;
            s.pTo = tf;
            s.pFrom = sf;
            s.fFlags = FOF_NO_UI;
            return SHFileOperation(&s);
        }

        int sh_move_file(const std::wstring& src, const std::wstring& dst)
        {
            WCHAR sf[MAX_PATH + 1];
            WCHAR tf[MAX_PATH + 1];

            wcscpy_s(sf, MAX_PATH, src.c_str());
            wcscpy_s(tf, MAX_PATH, dst.c_str());

            sf[wcslen(sf) + 1] = 0;
            tf[wcslen(tf) + 1] = 0;

            SHFILEOPSTRUCT s;
            memset(&s, 0, sizeof(s));
            s.wFunc = FO_MOVE;
            s.pTo = tf;
            s.pFrom = sf;
            s.fFlags = FOF_NO_UI;
            return SHFileOperation(&s);
        }

        int sh_rename_file(const std::wstring& src, const std::wstring& dst)
        {
            WCHAR sf[MAX_PATH + 1];
            WCHAR tf[MAX_PATH + 1];

            wcscpy_s(sf, MAX_PATH, src.c_str());
            wcscpy_s(tf, MAX_PATH, dst.c_str());

            sf[wcslen(sf) + 1] = 0;
            tf[wcslen(tf) + 1] = 0;

            SHFILEOPSTRUCT s;
            memset(&s, 0, sizeof(s));
            s.wFunc = FO_RENAME;
            s.pTo = tf;
            s.pFrom = sf;
            s.fFlags = FOF_NO_UI;
            return SHFileOperation(&s);
        }

        int sh_delete_directory(const std::wstring& src)
        {
            WCHAR sf[MAX_PATH + 1];

            wcscpy_s(sf, MAX_PATH, src.c_str());

            sf[wcslen(sf) + 1] = 0;

            SHFILEOPSTRUCT s;
            memset(&s, 0, sizeof(s));
            s.wFunc = FO_DELETE;
            s.pFrom = sf;
            s.fFlags = FOF_NO_UI;
            return SHFileOperation(&s);
        }

        bool delete_file_on_reboot(const std::wstring& filePath)
        {
            if (filePath.substr(filePath.size() - 6, 4) == L".del")
                return true;

            std::wstring delFilePath = filePath + L".del00";
            if (is_file_exist(delFilePath, false))
            {
                int i = 0;
                while (true)
                {
                    ++i;
                    if (i > 99)
                        return false;

                    if (2 != swprintf_s(&delFilePath[0] + delFilePath.size() - 2, 3, L"%02d", i))
                        return false;

                    if (!is_file_exist(delFilePath, false))
                        break;
                }
            }

            if (!MoveFile(filePath.c_str(), delFilePath.c_str()))
                return false;

            if (delFilePath.substr(0, 4) != LR"(\\?\)")
            {
                delFilePath = LR"(\\?\)" + delFilePath;
            }
            return FALSE != MoveFileEx(delFilePath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        }

        bool delete_file_ex(const std::wstring& filePath, bool rebootDel, bool disableWow64)
        {
            bool result = false;
            bool isFileExist = true;
            PVOID oldValue = nullptr;
            if (disableWow64)
                if (!Wow64DisableWow64FsRedirection(&oldValue))
                    return false;

            if (is_file_exist(filePath, false))
            {
                result = DeleteFile(filePath.c_str()) != FALSE;
            }
            else if (is_directory_exist(filePath, false))
            {
                result = RemoveDirectory(filePath.c_str()) != FALSE;
            }
            else
            {
                isFileExist = false;
                result = true;
            }

            if (!result && isFileExist && rebootDel)
                result = delete_file_on_reboot(filePath);

            if (disableWow64)
                if (!Wow64RevertWow64FsRedirection(oldValue))
                    return false;

            return result;
        }

        bool delete_directory(const std::wstring& dirPath, const std::vector<std::wstring>& excluded, bool rebootDel,
                              bool disableWow64)
        {
            if (dirPath.empty())
                return false;

            PVOID oldValue = nullptr;
            if (disableWow64)
                if (!Wow64DisableWow64FsRedirection(&oldValue))
                    return false;

            bool result = true;
            do
            {
                if (is_file_exist(dirPath, false))
                {
                    if (!delete_file_ex(dirPath, rebootDel, false))
                    {
                        result = false;
                        break;
                    }
                }

                if (!is_directory_exist(dirPath, false))
                {
                    result = true;
                    break;
                }

                std::wstring path = dirPath;
                if (path.back() == '\\')
                    path.pop_back();

                std::wstring findPath = path;
                findPath.push_back('\\');
                findPath.push_back('*');

                WIN32_FIND_DATA findData;
                HANDLE hFind = FindFirstFile(findPath.c_str(), &findData);
                if (hFind == INVALID_HANDLE_VALUE)
                {
                    result = false;
                    break;
                }

                do
                {
                    if (std::find(excluded.begin(), excluded.end(), findData.cFileName) != excluded.end())
                        continue;

                    if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
                    {
                        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
                            continue;

                        std::wstring subPath = path + L"\\" + findData.cFileName;
                        if (!delete_directory(subPath, excluded, rebootDel, false))
                            result = false;
                    }
                    else
                    {
                        std::wstring subPath = path + L"\\" + findData.cFileName;
                        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) == FILE_ATTRIBUTE_READONLY)
                        {
                            DWORD newAttributes = findData.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY;
                            SetFileAttributes(subPath.c_str(), newAttributes);
                        }

                        if (!delete_file_ex(subPath, rebootDel, false))
                            result = false;
                    }
                } while (FindNextFile(hFind, &findData));
                FindClose(hFind);

                if (excluded.empty())
                {
                    if (!delete_file_ex(path, rebootDel, false))
                        result = false;
                }
            } while (false);

            if (disableWow64)
                if (!Wow64RevertWow64FsRedirection(oldValue))
                    return false;

            return result;
        }

        HANDLE create_file(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                           LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                           DWORD dwFlagsAndAttributes,
                           HANDLE hTemplateFile)
        {
            HANDLE handle = INVALID_HANDLE_VALUE;
            PVOID old_value = nullptr;
            if (Wow64DisableWow64FsRedirection(&old_value))
            {
                handle = CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                    dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

                Wow64RevertWow64FsRedirection(old_value);
            }
            return handle;
        }

        template <>
        std::string read_file<std::string>(const std::wstring& filename)
        {
            std::string result;
            HANDLE hFile = CreateFile(filename.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                LARGE_INTEGER fileSize{};
                if (GetFileSizeEx(hFile, &fileSize))
                {
                    result.resize(fileSize.LowPart);
                    DWORD bytesRead = 0;
                    if (!ReadFile(hFile, &result[0], fileSize.LowPart, &bytesRead, nullptr))
                    {
                        result.clear();
                    }
                }
                CloseHandle(hFile);
            }
            return result;
        }

        template <>
        std::wstring read_file<std::wstring>(const std::wstring& filename)
        {
            std::wstring result;
            HANDLE hFile = CreateFile(filename.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                LARGE_INTEGER fileSize{};
                if (GetFileSizeEx(hFile, &fileSize))
                {
                    result.resize(fileSize.LowPart / sizeof(std::wstring::value_type));
                    DWORD bytesRead = 0;
                    if (!ReadFile(hFile, &result[0], fileSize.LowPart, &bytesRead, nullptr))
                    {
                        result.clear();
                    }
                }
                CloseHandle(hFile);
            }
            return result;
        }

        template <>
        std::string read_file<std::string>(const std::wstring& filename, size_t len)
        {
            std::string result;
            HANDLE hFile = CreateFile(filename.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                LARGE_INTEGER fileSize{};
                if (GetFileSizeEx(hFile, &fileSize))
                {
                    size_t read_size = fileSize.LowPart < len ? fileSize.LowPart : len;
                    result.resize(read_size);
                    DWORD bytesRead = 0;
                    if (!ReadFile(hFile, &result[0], (DWORD)read_size, &bytesRead, nullptr))
                    {
                        result.clear();
                    }
                }
                CloseHandle(hFile);
            }
            return result;
        }

        template <>
        std::wstring read_file<std::wstring>(const std::wstring& filename, size_t len)
        {
            std::wstring result;
            HANDLE hFile = CreateFile(filename.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                LARGE_INTEGER fileSize{};
                if (GetFileSizeEx(hFile, &fileSize))
                {
                    size_t read_size = (fileSize.LowPart < len ? fileSize.LowPart : len) / sizeof(std::wstring::value_type);
                    result.resize(read_size);
                    DWORD bytesRead = 0;
                    if (!ReadFile(hFile, &result[0], (DWORD)read_size, &bytesRead, nullptr))
                    {
                        result.clear();
                    }
                }
                CloseHandle(hFile);
            }
            return result;
        }

        bool write_file(const std::wstring& filename, const std::string& data, bool append)
        {
            return write_file(filename, data.c_str(), (DWORD)data.size(), append);
        }

        bool write_file(const std::wstring& filename, const std::wstring& data, bool append)
        {
            return write_file(filename, data.c_str(), (DWORD)data.size() * sizeof(std::wstring::value_type), append);
        }

        bool write_file(const std::wstring& filename, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, bool append)
        {
            HANDLE hFile = CreateFile(filename.c_str(), append ? FILE_APPEND_DATA : GENERIC_WRITE,
                FILE_SHARE_READ, nullptr, append ? OPEN_ALWAYS : CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                if (append)
                    SetFilePointer(hFile, 0, NULL, FILE_END);

                DWORD bytesWritten = 0;
                if (WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &bytesWritten, nullptr))
                {
                    CloseHandle(hFile);
                    return true;
                }
                CloseHandle(hFile);
            }
            return false;
        }

        std::wstring get_filename(const std::wstring& path)
        {
            auto pos = path.rfind(L'\\');
            if (pos == std::wstring::npos)
                return path;
            return path.substr(pos + 1);
        }

        std::wstring get_filename_without_extension(const std::wstring& path)
        {
            auto filename = get_filename(path);
            if (filename.empty())
                return path;
            auto pos = filename.find(L'.');
            if (pos == std::wstring::npos)
                return filename;
            return filename.substr(0, pos);
        }

        std::wstring get_file_extension(const std::wstring& path)
        {
            auto pos = path.rfind(L'.');
            if (pos == std::wstring::npos)
                return L"";
            return path.substr(pos + 1);
        }

        BOOL is_pe_file(HANDLE hFile)
        {
            BOOL result = FALSE;
            LARGE_INTEGER fileSize{};
            HANDLE hMapping = nullptr;
            LPCVOID pImageBase = nullptr;

            do
            {
                if (hFile == INVALID_HANDLE_VALUE)
                    return FALSE;

                if (!GetFileSizeEx(hFile, &fileSize))
                    return FALSE;

                if (fileSize.QuadPart < sizeof(IMAGE_DOS_HEADER))
                    break;

                hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
                if (!hMapping)
                    return FALSE;

                pImageBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
                if (!pImageBase)
                    break;

                PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
                if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                    break;

                DWORD dwNtSigSize = (DWORD)pDosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS32, Signature) + sizeof(
                    IMAGE_NT_HEADERS::Signature);
                if (fileSize.QuadPart < dwNtSigSize)
                    break;

                PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
                if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
                    break;

                result = TRUE;
            } while (false);

            if (pImageBase)
                UnmapViewOfFile(pImageBase);
            if (hMapping)
                CloseHandle(hMapping);

            return result;
        }

        BOOL is_pe_file(LPCWSTR szFilePath)
        {
            HANDLE hFile = CreateFile(
                szFilePath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL);
            if (hFile == INVALID_HANDLE_VALUE)
                return FALSE;

            BOOL bResult = is_pe_file(hFile);
            CloseHandle(hFile);
            return bResult;
        }

        BOOL is_pe_file(const std::wstring& filePath)
        {
            return is_pe_file(filePath.c_str());
        }

        BOOL is_compressed_file(const std::wstring& file_path)
        {
            const auto& extension = get_file_extension(file_path);
            std::vector<std::wstring> supported_format = { L"7z", L"rar", L"zip", L"zipx", L"jar", L"bz2", L"tbz", L"gz", L"gzip", L"tgz", L"tar", L"xar" };
            return std::find(supported_format.begin(), supported_format.end(), extension) != supported_format.end();
        }

        BOOL get_file_time(const std::wstring& filePath, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime,
                           LPFILETIME lpLastWriteTime)
        {
            HANDLE hFile = CreateFile(
                filePath.c_str(),
                FILE_GENERIC_READ | GENERIC_READ,        // open for reading
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL,                     // no security
                OPEN_EXISTING,            // existing file only
                FILE_ATTRIBUTE_NORMAL,    // normal file
                NULL);
            if (hFile == INVALID_HANDLE_VALUE)
                return FALSE;
            BOOL res = GetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
            CloseHandle(hFile);
            return res;
        }

        std::string get_pe_file_version(const std::wstring& path)
        {
            std::string result;
            DWORD size = GetFileVersionInfoSize(path.c_str(), nullptr);
            if (size)
            {
                char* buf = new(std::nothrow) char[size];
                if (buf)
                {
                    if (GetFileVersionInfo(path.c_str(), NULL, size, buf))
                    {
                        UINT nLen = 0;
                        VS_FIXEDFILEINFO* pFileInfo = nullptr;
                        if (VerQueryValue(buf, L"\\", (LPVOID*)&pFileInfo, &nLen))
                        {
                            char verBuf[32];
                            sprintf_s(verBuf, "%d.%d.%d.%d",
                                      HIWORD(pFileInfo->dwFileVersionMS),
                                      LOWORD(pFileInfo->dwFileVersionMS),
                                      HIWORD(pFileInfo->dwFileVersionLS),
                                      LOWORD(pFileInfo->dwFileVersionLS));
                            result = verBuf;
                        }
                    }
                    delete[] buf;
                }
            }
            return result;
        }

        std::string get_pe_product_version(const std::wstring& path)
        {
            std::string result;
            DWORD size = GetFileVersionInfoSize(path.c_str(), nullptr);
            if (size)
            {
                char* buf = new(std::nothrow) char[size];
                if (buf)
                {
                    if (GetFileVersionInfo(path.c_str(), NULL, size, buf))
                    {
                        UINT nLen = 0;
                        VS_FIXEDFILEINFO* pFileInfo = nullptr;
                        if (VerQueryValue(buf, L"\\", (LPVOID*)&pFileInfo, &nLen))
                        {
                            char verBuf[32];
                            sprintf_s(verBuf, "%d.%d.%d.%d",
                                      HIWORD(pFileInfo->dwProductVersionMS),
                                      LOWORD(pFileInfo->dwProductVersionMS),
                                      HIWORD(pFileInfo->dwProductVersionLS),
                                      LOWORD(pFileInfo->dwProductVersionLS));
                            result = verBuf;
                        }
                    }
                    delete[] buf;
                }
            }
            return result;
        }

        int compare_version(const char* v1, const char* v2)
        {
            if (!v1 || !v2)
                return 2;

            if (strcmp(v1, v2) == 0)
                return 0;

            int a1 = 0, b1 = 0, c1 = 0, d1 = 0;
            int a2 = 0, b2 = 0, c2 = 0, d2 = 0;
            if (sscanf_s(v1, "%d.%d.%d.%d", &a1, &b1, &c1, &d1) != 4)
                return 3;
            if (sscanf_s(v2, "%d.%d.%d.%d", &a2, &b2, &c2, &d2) != 4)
                return 4;

            if (a1 > a2)
                return 1;
            if (a1 < a2)
                return -1;
            if (b1 > b2)
                return 1;
            if (b1 < b2)
                return -1;
            if (c1 > c2)
                return 1;
            if (c1 < c2)
                return -1;
            if (d1 > d2)
                return 1;
            if (d1 < d2)
                return -1;
            return 0;
        }

        std::wstring get_debug_file(const std::wstring& filename)
        {
            std::wstring filePath = process::get_current_module_dir() + L"\\" + filename;
            if (is_file_exist(filePath, false))
                return filePath;

            filePath = L"C:\\debug\\" + filename;
            if (is_file_exist(filePath, false))
                return filePath;

            return L"";
        }

        std::wstring get_long_path(const std::wstring& short_path)
        {
            WCHAR long_path[MAX_PATH];
            if (::GetLongPathName(short_path.c_str(), long_path, MAX_PATH))
                return std::wstring(long_path);
            return L"";
        }

        std::wstring get_temp_path()
        {
            WCHAR temp_path[MAX_PATH];
            if (GetTempPath(MAX_PATH, temp_path))
                return std::wstring(temp_path);
            return L"";
        }

        bool create_random_directory(std::wstring& random_path, int depth)
        {
            auto tmp = get_temp_path();
            if (tmp.empty())
            {
                return false;
            }

            tmp = get_long_path(tmp);
            if (tmp.empty())
            {
                return false;
            }

            if (tmp.back() == '\\')
                tmp.pop_back();

            for (int i = 0; i < depth; i++)
            {
                int count = 0;
                do
                {
                    const std::wstring rnd_str = string::get_random_string<std::wstring>(random(8, 12));
                    std::wstring rnd_dir = tmp + L"\\" + rnd_str;
                    if (CreateDirectory(rnd_dir.c_str(), nullptr))
                    {
                        tmp = rnd_dir;
                        break;
                    }
                    if (count > 5)
                        return false;
                    ++count;
                } while (true);
            }
            random_path = tmp;
            return true;
        }

        bool create_directories(const std::wstring& path)
        {
            if (is_directory_exist(path, false))
                return true;

            if (is_file_exist(path, false))
                return false;

            bool result = true;
            auto pos = path.rfind(L'\\');
            if (pos != std::wstring::npos)
            {
                const std::wstring parent = path.substr(0, pos);
                result = create_directories(parent);
            }

            if (result)
            {
                result = CreateDirectory(path.c_str(), nullptr);
            }
            return result;
        }
    }
}

