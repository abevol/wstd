/**
 * @file process.h
 * @brief 
 * @date 2021-04-07
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"
#include <tuple>
#include <TlHelp32.h>

namespace wstd
{
    namespace process
    {
        DWORD get_process_id(const WCHAR* proc_name);

        std::wstring get_process_path(DWORD pid);

        HMODULE get_current_module();

        std::wstring get_module_path(HMODULE module);

        std::wstring get_module_name(HMODULE module);

        std::wstring get_module_dir(HMODULE module);

        std::wstring get_current_module_name();

        std::wstring get_current_module_path();

        std::wstring get_current_module_dir();

        std::wstring get_process_module_name(HANDLE hProcess, HMODULE module);

        std::wstring get_process_module_name(DWORD pid, HMODULE module);

        std::wstring get_process_module_path(HANDLE hProcess, HMODULE module);

        std::wstring get_process_module_path(DWORD pid, HMODULE module);

        std::wstring get_process_image_path(DWORD pid);

        std::wstring get_process_image_name(DWORD pid);

        HMODULE get_remote_module_handle(DWORD dwOwnerPID, const WCHAR* ModuleName, bool bFullPath);

        std::wstring get_remote_module_path(DWORD dwOwnerPID, HMODULE hMod);

        DWORD create_process_lite(const std::wstring& path, const std::wstring& cmd = L"", const std::wstring& dir = L"",
            bool hide = false, bool wait = false, DWORD* exitCode = nullptr, std::string* result = nullptr);

        DWORD shell_execute_lite(const std::wstring& action, const std::wstring& path,
            const std::wstring& cmd = L"", const std::wstring& dir = L"", DWORD dwMilliseconds = 0);

        std::wstring get_remote_module_path(DWORD dwOwnerPID, const WCHAR* ModuleName, bool bFullPath);

        std::vector<DWORD> get_process_ids(const WCHAR* szProcessName);

        std::wstring get_process_name(DWORD pid);

        DWORD get_main_thread_id(DWORD pid);

        DWORD get_parent_process_id(DWORD pid);

        bool is_running_as_service();

        std::vector<DWORD> get_process_thread_ids(DWORD pid);

        int get_process_entries(const WCHAR* name, std::vector<PROCESSENTRY32>& retProcess);

        BOOL kill_process(DWORD pid);

        void kill_processes(const std::wstring& proc_name);

        bool is_process_exist(HANDLE hProc);

        bool is_process_exist(DWORD pid);

        bool is_already_running(const GUID* guid, _Out_ HANDLE* mutex = nullptr);

        bool is_mutex_exist(LPCWSTR lpName);

        void enable_mini_dump();

        bool enable_debug_privilege();

        DWORD WINAPI inject_dll_by_thread_context(HANDLE hProcess, HANDLE hThread, const WCHAR* pszDllFile);

        DWORD WINAPI inject_dll_by_thread_context(DWORD dwProcessID, DWORD dwThreadID, const WCHAR* pszDllFile);

        int WINAPI inject_dll(DWORD process_id, const WCHAR* dll_file_path);

        int WINAPI eject_dll(DWORD process_id, const WCHAR* dll_file_path);

        void WINAPI eject_module(const WCHAR* pName, const WCHAR* mName);
    }
}
