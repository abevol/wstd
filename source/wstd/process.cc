#include <wstd/process.h>
#include <wstd/file.h>
#include <wstd/string.h>
#include <wstd/time.h>
#include <Psapi.h>
#include <shellapi.h>
#include <DbgHelp.h>

#pragma comment (lib,"Psapi.lib")

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace wstd
{
    namespace process
    {
        DWORD get_process_id(const WCHAR* proc_name)
        {
            DWORD pid = NULL;
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
            if (snap == INVALID_HANDLE_VALUE)
                return NULL;

            PROCESSENTRY32 pe32{};
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(snap, &pe32))
            {
                do
                {
                    if (_wcsicmp(pe32.szExeFile, proc_name) == 0)
                    {
                        pid = pe32.th32ProcessID;
                        break;
                    }
                } while (Process32Next(snap, &pe32));
            }
            CloseHandle(snap);
            return pid;
        }

        std::wstring get_process_path(DWORD pid)
        {
            std::wstring result;
            HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (proc)
            {
                WCHAR path[MAX_PATH];
                DWORD size = MAX_PATH;
                BOOL ax = QueryFullProcessImageName(proc, 0, path, &size);
                CloseHandle(proc);
                if (ax)
                    result.assign(path, size);
            }
            return result;
        }

        HMODULE get_current_module()
        {
            return (HINSTANCE)&__ImageBase;
        }

        std::wstring get_module_path(HMODULE module)
        {
            WCHAR path[MAX_PATH]{};
            GetModuleFileName(module, path, MAX_PATH);
            return std::wstring(path);
        }

        std::wstring get_module_name(HMODULE module)
        {
            std::wstring path = get_module_path(module);
            return file::get_filename(path);
        }

        std::wstring get_module_dir(HMODULE module)
        {
            std::wstring path = get_module_path(module);
            return file::get_parent_path(path);
        }

        std::wstring get_current_module_name()
        {
            return get_module_name(get_current_module());
        }

        std::wstring get_current_module_path()
        {
            return get_module_path(get_current_module());
        }

        std::wstring get_current_module_dir()
        {
            return get_module_dir(get_current_module());
        }

        std::wstring get_process_module_name(HANDLE hProcess, HMODULE module)
        {
            wchar_t path[MAX_PATH]{};
            if (GetModuleBaseName(hProcess, module, path, MAX_PATH))
                return std::wstring(path);
            return L"";
        }

        std::wstring get_process_module_name(DWORD pid, HMODULE module)
        {
            std::wstring result;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProc)
            {
                result = get_process_module_name(hProc, module);
                CloseHandle(hProc);
            }
            return result;
        }

        std::wstring get_process_module_path(HANDLE hProcess, HMODULE module)
        {
            WCHAR path[MAX_PATH]{};
            if (GetModuleFileNameEx(hProcess, module, path, MAX_PATH))
                return std::wstring(path);
            return L"";
        }

        std::wstring get_process_module_path(DWORD pid, HMODULE module)
        {
            std::wstring result;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProc)
            {
                result = get_process_module_path(hProc, module);
                CloseHandle(hProc);
            }
            return result;
        }

        std::wstring get_process_image_path(DWORD pid)
        {
            std::wstring result;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (hProc)
            {
                WCHAR path[MAX_PATH]{};
                DWORD len = GetProcessImageFileName(hProc, path, MAX_PATH);
                CloseHandle(hProc);
                if (len)
                    result.assign(path, len);
            }
            return result;
        }

        std::wstring get_process_image_name(DWORD pid)
        {
            std::wstring path = get_process_image_path(pid);
            return file::get_filename(path);
        }

        HMODULE get_remote_module_handle(DWORD dwOwnerPID, const WCHAR* ModuleName, bool bFullPath)
        {
            HMODULE hModule = nullptr;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwOwnerPID);
            if (hSnap == INVALID_HANDLE_VALUE)
            {
                return nullptr;
            }

            MODULEENTRY32 me32;
            me32.dwSize = sizeof(MODULEENTRY32);
            if (Module32First(hSnap, &me32))
            {
                do
                {
                    if (_wcsicmp(bFullPath ? me32.szExePath : me32.szModule, ModuleName) == 0)
                    {
                        hModule = me32.hModule;
                        break;
                    }
                } while (Module32Next(hSnap, &me32));
            }
            CloseHandle(hSnap);
            return hModule;
        }

        std::wstring get_remote_module_path(DWORD dwOwnerPID, HMODULE hMod)
        {
            std::wstring result;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwOwnerPID);
            if (hSnap == INVALID_HANDLE_VALUE)
            {
                return result;
            }

            MODULEENTRY32 me32;
            me32.dwSize = sizeof(MODULEENTRY32);
            if (Module32First(hSnap, &me32))
            {
                do
                {
                    if (hMod == me32.hModule)
                    {
                        result = me32.szExePath;
                        break;
                    }
                } while (Module32Next(hSnap, &me32));
            }
            CloseHandle(hSnap);
            return result;
        }

        DWORD create_process_lite(const std::wstring& path, const std::wstring& cmd, const std::wstring& dir,
            bool hide, bool wait, DWORD* exitCode, std::string* result)
        {
            std::wstring exePath = path;
            if (exePath.front() == '"')
                exePath.erase(exePath.begin());
            if (exePath.back() == '"')
                exePath.erase(exePath.end());

            std::wstring cmdLine;
            if (cmd.empty())
                cmdLine = L"\"" + exePath + L"\"";
            else
                cmdLine = cmd;

            std::wstring dir_path;
            if (dir.empty())
                dir_path = file::get_parent_path(exePath);
            else
                dir_path = dir;

            STARTUPINFO si;
            PROCESS_INFORMATION pi;
            memset(&pi, 0, sizeof(pi));
            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = hide ? SW_HIDE : SW_SHOWNORMAL;

            HANDLE hRead = nullptr, hWrite = nullptr;
            if (result)
            {
                SECURITY_ATTRIBUTES   sa;
                sa.nLength = sizeof(SECURITY_ATTRIBUTES);
                sa.bInheritHandle = TRUE;
                sa.lpSecurityDescriptor = NULL;

                if (!CreatePipe(&hRead, &hWrite, &sa, 0))
                    return 0;
                SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

                si.hStdInput = nullptr;
                si.hStdOutput = hWrite;
                si.hStdError = hWrite;
                si.dwFlags |= STARTF_USESTDHANDLES;
            }

            if (!CreateProcess(exePath.c_str(), &cmdLine[0], nullptr, nullptr, result ? TRUE : FALSE, NULL, nullptr,
                dir_path.c_str(), &si, &pi))
            {
                return 0;
            }
            if (result)
            {
                DWORD dwBufLen = 1024;
                CHAR* chBuf = new CHAR[dwBufLen];
                if (chBuf)
                {
                    while (true)
                    {
                        DWORD totalBytes = 0;
                        if (!PeekNamedPipe(hRead, nullptr, 0, nullptr, &totalBytes, nullptr))
                            break;

                        if (totalBytes)
                        {
                            if (totalBytes > dwBufLen)
                            {
                                delete[] chBuf;
                                dwBufLen = totalBytes + 64;
                                chBuf = new CHAR[dwBufLen];
                                if (!chBuf)
                                    break;
                            }
                            DWORD dwRead = 0;
                            BOOL bSuccess = ReadFile(hRead, chBuf, dwBufLen, &dwRead, NULL);
                            if (!bSuccess || dwRead == 0)
                                break;
                            result->append(chBuf, dwRead);
                        }
                        else
                        {
                            if (!is_process_exist(pi.hProcess))
                                break;
                        }
                    }
                }
                delete[] chBuf;
            }
            if (wait)
            {
                WaitForSingleObject(pi.hProcess, INFINITE);
            }

            if (exitCode)
            {
                GetExitCodeProcess(pi.hProcess, exitCode);
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return pi.dwProcessId;
        }

        DWORD shell_execute_lite(const std::wstring& action, const std::wstring& path,
            const std::wstring& cmd, const std::wstring& dir, DWORD dwMilliseconds)
        {
            DWORD pid = 0;
            SHELLEXECUTEINFO info;
            ZeroMemory(&info, sizeof(SHELLEXECUTEINFO));
            info.cbSize = sizeof(SHELLEXECUTEINFO);
            info.fMask = SEE_MASK_DEFAULT | SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
            info.lpVerb = action.c_str();
            info.lpFile = path.c_str();
            info.lpParameters = cmd.c_str();
            info.lpDirectory = dir.c_str();
            info.nShow = SW_HIDE;

            BOOL bRet = ShellExecuteEx(&info);
            if (bRet && info.hProcess)
            {
                pid = GetProcessId(info.hProcess);
                if (dwMilliseconds)
                    WaitForSingleObject(info.hProcess, dwMilliseconds);
                CloseHandle(info.hProcess);
            }
            return pid;
        }

        std::wstring get_remote_module_path(DWORD dwOwnerPID, const WCHAR* ModuleName, bool bFullPath)
        {
            std::wstring result;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwOwnerPID);
            if (hSnap == INVALID_HANDLE_VALUE)
                return result;

            MODULEENTRY32 me32;
            me32.dwSize = sizeof(MODULEENTRY32);
            if (Module32First(hSnap, &me32))
            {
                do
                {
                    if (_wcsicmp(bFullPath ? me32.szExePath : me32.szModule, ModuleName) == 0)
                    {
                        result = me32.szExePath;
                        break;
                    }
                } while (Module32Next(hSnap, &me32));
            }
            CloseHandle(hSnap);
            return result;
        }

        std::vector<DWORD> get_process_ids(const WCHAR* szProcessName)
        {
            std::vector<DWORD> vPIDs;

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE)
                return vPIDs;

            PROCESSENTRY32 pt;
            pt.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pt))
            {
                do
                {
                    if (_wcsicmp(pt.szExeFile, szProcessName) == 0)
                        vPIDs.emplace_back(pt.th32ProcessID);

                } while (Process32Next(hSnapshot, &pt));
            }

            CloseHandle(hSnapshot);
            return vPIDs;
        }

        std::wstring get_process_name(DWORD pid)
        {
            std::wstring result;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
            if (hSnap == INVALID_HANDLE_VALUE)
                return result;

            PROCESSENTRY32 pe32{};
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnap, &pe32))
            {
                do
                {
                    if (pid == pe32.th32ProcessID)
                    {
                        result = pe32.szExeFile;
                        break;
                    }
                } while (Process32Next(hSnap, &pe32));
            }
            CloseHandle(hSnap);
            return result;
        }

        DWORD get_main_thread_id(DWORD pid)
        {
            DWORD tid = NULL;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
            if (hSnap == INVALID_HANDLE_VALUE)
            {
                return NULL;
            }
            THREADENTRY32 te32{};
            te32.dwSize = sizeof(THREADENTRY32);
            if (Thread32First(hSnap, &te32))
            {
                do
                {
                    if (te32.th32OwnerProcessID == pid)
                    {
                        tid = te32.th32ThreadID;
                        break;
                    }
                } while (Thread32Next(hSnap, &te32));
            }
            CloseHandle(hSnap);
            return tid;
        }

        DWORD get_parent_process_id(DWORD pid)
        {
            DWORD result = 0;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
            if (hSnap == INVALID_HANDLE_VALUE)
            {
                return result;
            }
            PROCESSENTRY32 pe32{};
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnap, &pe32))
            {
                do
                {
                    if (pid == pe32.th32ProcessID)
                    {
                        result = pe32.th32ParentProcessID;
                        break;
                    }
                } while (Process32Next(hSnap, &pe32));
            }
            CloseHandle(hSnap);
            return result;
        }

        bool is_running_as_service()
        {
            // 也可以用未导出函数 sechost.dll!ScOpenServiceChannelHandle 判断。
            // 如果返回0，表示为服务。
            bool bResult = false;
            DWORD ppid = get_parent_process_id(GetCurrentProcessId());
            std::wstring name = get_process_name(ppid);
            if (name == L"services.exe")
                bResult = true;
            return bResult;
        }

        std::vector<DWORD> get_process_thread_ids(DWORD pid)
        {
            std::vector<DWORD> result;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
            if (hSnap != INVALID_HANDLE_VALUE)
            {
                THREADENTRY32 TE32{};
                memset(&TE32, 0, sizeof(THREADENTRY32));
                TE32.dwSize = sizeof(THREADENTRY32);
                if (Thread32First(hSnap, &TE32))
                {
                    do
                    {
                        if (TE32.th32OwnerProcessID == pid)
                        {
                            result.push_back(TE32.th32ThreadID);
                        }
                    } while (Thread32Next(hSnap, &TE32));
                }
                CloseHandle(hSnap);
            }
            return result;
        }

        int get_process_entries(const WCHAR* name, std::vector<PROCESSENTRY32>& retProcess)
        {
            int sum = 0;
            retProcess.clear();
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
            if (hSnap != INVALID_HANDLE_VALUE)
            {
                PROCESSENTRY32 pe32{};
                pe32.dwSize = sizeof(PROCESSENTRY32);
                if (Process32First(hSnap, &pe32))
                {
                    do
                    {
                        if (_wcsicmp(pe32.szExeFile, name) == 0)
                        {
                            sum = sum + 1;
                            retProcess.push_back(pe32);
                        }
                    } while (Process32Next(hSnap, &pe32));
                }
                CloseHandle(hSnap);
            }
            return sum;
        }

        BOOL kill_process(DWORD pid)
        {
            HANDLE hHandle = OpenProcess(PROCESS_TERMINATE, false, pid);
            BOOL result = TerminateProcess(hHandle, 0);
            CloseHandle(hHandle);
            return result;
        }

        void kill_processes(const std::wstring& proc_name)
        {
            std::vector<DWORD> pids = get_process_ids(proc_name.c_str());
            for (DWORD pid: pids)
            {
                kill_process(pid);
            }
        }

        bool is_process_exist(HANDLE hProc)
        {
            if (WaitForSingleObject(hProc, 0) == WAIT_TIMEOUT)
                return true;

            DWORD exit_code = 0;
            BOOL result = GetExitCodeProcess(hProc, &exit_code);
            if (result)
            {
                if (exit_code == STILL_ACTIVE)
                    return true;
            }
            return false;
        }

        bool is_process_exist(DWORD pid)
        {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, false, pid);
            if (hProc)
            {
                bool result = is_process_exist(hProc);
                CloseHandle(hProc);
                return result;
            }
            return false;
        }

        bool is_already_running(const GUID* guid, HANDLE* mutex)
        {
            HANDLE my_mutex = ::CreateMutex(nullptr, TRUE, string::guid_to_string<wchar_t>(guid).c_str());
            if (my_mutex && ::GetLastError() == ERROR_ALREADY_EXISTS)
            {
                CloseHandle(my_mutex);
                my_mutex = nullptr;
                return true;
            }
            if (mutex)
                *mutex = my_mutex;
            return false;
        }

        bool is_mutex_exist(LPCWSTR lpName)
        {
            HANDLE hMutex = OpenMutex(SYNCHRONIZE, FALSE, lpName);
            if (hMutex) {
                CloseHandle(hMutex);
                return true;
            }
            return false;
        }

        static int generate_mini_dump(HANDLE hFile, PEXCEPTION_POINTERS pExceptionPointers)
        {
            BOOL bOwnDumpFile = FALSE;
            HANDLE hDumpFile = hFile;
            MINIDUMP_EXCEPTION_INFORMATION ExpParam;

            decltype(&MiniDumpWriteDump) pfnMiniDumpWriteDump = nullptr;
            HMODULE hDbgHelp = LoadLibrary(L"DbgHelp.dll");
            if (hDbgHelp)
                pfnMiniDumpWriteDump = (decltype(&MiniDumpWriteDump))GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
            if (pfnMiniDumpWriteDump)
            {
                if (hDumpFile == nullptr || hDumpFile == INVALID_HANDLE_VALUE)
                {
                    std::wstring filepath = get_current_module_path() + L"." + time::get_localtime_wstring(L"%d-%d-%d.%d-%d-%d") +
                        L".dmp";
                    hDumpFile = CreateFile(filepath.c_str(), GENERIC_READ | GENERIC_WRITE,
                                           FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
                    bOwnDumpFile = TRUE;
                }
                if (hDumpFile != INVALID_HANDLE_VALUE)
                {
                    ExpParam.ThreadId = GetCurrentThreadId();
                    ExpParam.ExceptionPointers = pExceptionPointers;
                    ExpParam.ClientPointers = FALSE;

                    pfnMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
                                         hDumpFile, MiniDumpWithDataSegs, (pExceptionPointers ? &ExpParam : NULL), NULL,
                                         NULL);

                    if (bOwnDumpFile)
                        CloseHandle(hDumpFile);
                }
            }

            if (hDbgHelp != nullptr)
                FreeLibrary(hDbgHelp);

            return EXCEPTION_EXECUTE_HANDLER;
        }

        static LONG WINAPI exception_filter(LPEXCEPTION_POINTERS lpExceptionInfo)
        {
            if (IsDebuggerPresent())
            {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            return generate_mini_dump(nullptr, lpExceptionInfo);
        }

        void enable_mini_dump()
        {
            SetUnhandledExceptionFilter(&exception_filter);
        }

        bool enable_debug_privilege()
        {
            HANDLE hToken;
            LUID seDebugNameValue;
            TOKEN_PRIVILEGES tkp;

            if (!OpenProcessToken(GetCurrentProcess(),
                                  TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            {
                return false;
            }
            if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &seDebugNameValue))
            {
                CloseHandle(hToken);
                return false;
            }

            tkp.PrivilegeCount = 1;
            tkp.Privileges[0].Luid = seDebugNameValue;
            tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), nullptr, nullptr))
            {
                CloseHandle(hToken);
                return false;
            }
            return true;
        }

        DWORD WINAPI inject_dll_by_thread_context(HANDLE hProcess, HANDLE hThread, const WCHAR* pszDllFile)
        {
#ifndef _WIN64
            unsigned char sc[] =
            {
                 0x68, 0xef, 0xbe, 0xad, 0xde,	// push 0xDEADBEEF
                 0x9c,							// pushfd
                 0x60,							// pushad
                 0x68, 0xef, 0xbe, 0xad, 0xde,	//push 0xDEADBEEF
                 0xb8, 0xef, 0xbe, 0xad, 0xde,	// mov eax, 0xDEADBEEF
                 0xff, 0xd0,						// call eax
                 0x61,							// popad
                 0x9d,							//popfd
                 0xc3							//ret
            };
#else
            unsigned char sc[] =
            {
                 0x50, // push rax (save rax)
                 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rax, 0CCCCCCCCCCCCCCCCh (place holder for return address)
                 0x9c,                                                                   // pushfq
                 0x51,                                                                   // push rcx
                 0x52,                                                                   // push rdx
                 0x53,                                                                   // push rbx
                 0x55,                                                                   // push rbp
                 0x56,                                                                   // push rsi
                 0x57,                                                                   // push rdi
                 0x41, 0x50,                                                             // push r8
                 0x41, 0x51,                                                             // push r9
                 0x41, 0x52,                                                             // push r10
                 0x41, 0x53,                                                             // push r11
                 0x41, 0x54,                                                             // push r12
                 0x41, 0x55,                                                             // push r13
                 0x41, 0x56,                                                             // push r14
                 0x41, 0x57,                                                             // push r15
                 0x68, 0xef,0xbe,0xad,0xde,
                 0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rcx, 0CCCCCCCCCCCCCCCCh (place holder for DLL path name)
                 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // mov rax, 0CCCCCCCCCCCCCCCCh (place holder for LoadLibrary)
                 0xFF, 0xD0,                // call rax (call LoadLibrary)
                 0x58, // pop dummy
                 0x41, 0x5F,                                                             // pop r15
                 0x41, 0x5E,                                                             // pop r14
                 0x41, 0x5D,                                                             // pop r13
                 0x41, 0x5C,                                                             // pop r12
                 0x41, 0x5B,                                                             // pop r11
                 0x41, 0x5A,                                                             // pop r10
                 0x41, 0x59,                                                             // pop r9
                 0x41, 0x58,                                                             // pop r8
                 0x5F,                                                                   // pop rdi
                 0x5E,                                                                   // pop rsi
                 0x5D,                                                                   // pop rbp
                 0x5B,                                                                   // pop rbx
                 0x5A,                                                                   // pop rdx
                 0x59,                                                                   // pop rcx
                 0x9D,                                                                   // popfq
                 0x58,                                                                   // pop rax
                 0xC3                                                                    // ret
            };
#endif
            auto stubLen = sizeof(sc);
            auto hMod = GetModuleHandle(L"kernel32.dll");
            if (!hMod)
                return 1;
            auto LoadLibraryAddress = (DWORD_PTR)GetProcAddress(hMod, "LoadLibraryW");
            if (LoadLibraryAddress == NULL)
            {
                wprintf(L"[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n");
                return (1);
            }

            SIZE_T dwSize = (wcslen(pszDllFile) + 1) * sizeof(wchar_t);

            LPVOID lpDllAddr = VirtualAllocEx(hProcess, nullptr, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (lpDllAddr == nullptr)
            {
                wprintf(L"[-] Error: Could not allocate memory.\n");
                return (2);
            }

            auto stub = VirtualAllocEx(hProcess, nullptr, stubLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (stub == nullptr)
            {
                wprintf(L"[-] Error: Could not allocate memory for stub.\n");
                return (3);
            }

            BOOL bStatus = WriteProcessMemory(hProcess, lpDllAddr, pszDllFile, dwSize, NULL);
            if (bStatus == 0)
            {
                wprintf(L"[-] Error: Could not write any bytes into the address space.\n");
                return (4);
            }

            SuspendThread(hThread);

            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(hThread, &ctx);
            ctx.ContextFlags = CONTEXT_CONTROL;

#ifndef _WIN64
            auto oldIP = ctx.Eip;
            ctx.Eip = (DWORD_PTR)stub;
            memcpy((void*)((unsigned long)sc + 1), &oldIP, 4);
            memcpy((void*)((unsigned long)sc + 8), &lpDllAddr, 4);
            memcpy((void*)((unsigned long)sc + 13), &LoadLibraryAddress, 4);
#else
            auto oldIP = ctx.Rip;
            ctx.Rip = (DWORD_PTR)stub;
            memcpy(sc + 3, &oldIP, sizeof(oldIP));
            memcpy(sc + 41, &lpDllAddr, sizeof(lpDllAddr));
            memcpy(sc + 51, &LoadLibraryAddress, sizeof(LoadLibraryAddress));
#endif

            WriteProcessMemory(hProcess, stub, sc, stubLen, nullptr);
            SetThreadContext(hThread, &ctx);

            while (true)
            {
                auto count = ResumeThread(hThread);
                if (count == (DWORD)-1)
                    return 5;
                if (count <= 1)
                    break;
            }
            //VirtualFreeEx(hProcess, lpDllAddr, 0, MEM_RELEASE);
            //VirtualFreeEx(hProcess, stub, 0, MEM_RELEASE);

            return (0);
        }

        DWORD WINAPI inject_dll_by_thread_context(DWORD dwProcessID, DWORD dwThreadID, const WCHAR* pszDllFile)
        {
            if (!dwProcessID || !dwThreadID)
                return 100;
            HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
            if (hProcess == nullptr)
            {
                return 101;
            }
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, dwThreadID);
            if (hThread == nullptr)
            {
                return 102;
            }
            auto result = inject_dll_by_thread_context(hProcess, hThread, pszDllFile);
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return result;
        }

        int WINAPI inject_dll(const DWORD process_id, const WCHAR* dll_file_path)
        {
            if (get_remote_module_handle(process_id, dll_file_path, true))
                return 0;

            int err = 0;
            HANDLE process = nullptr;
            LPVOID remote_mem = nullptr;
            HANDLE remote_thread = nullptr;
            do
            {
                SIZE_T str_len = (wcslen(dll_file_path) + 1) * sizeof(wchar_t);
                process = OpenProcess(
                    PROCESS_QUERY_INFORMATION |   // CreateRemoteThread
                    PROCESS_CREATE_THREAD |       // CreateRemoteThread
                    PROCESS_VM_OPERATION |        // VirtualAllocEx / VirtualFree
                    PROCESS_VM_READ |             // CreateRemoteThread
                    PROCESS_VM_WRITE,             // WriteProcessMemory
                    FALSE, process_id);
                if (process == nullptr)
                {
                    err = 1;
                    break;
                }

                remote_mem = VirtualAllocEx(process, nullptr, str_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (remote_mem == nullptr)
                {
                    err = 2;
                    break;
                }

                if (FALSE == WriteProcessMemory(process, (LPVOID)remote_mem, dll_file_path, str_len, nullptr))
                {
                    err = 3;
                    break;
                }

                HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
                if (kernel32 == nullptr)
                {
                    err = 4;
                    break;
                }

                LPTHREAD_START_ROUTINE load_library = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "LoadLibraryW");
                if (load_library ==nullptr)
                {
                    err = 5;
                    break;
                }

                remote_thread = CreateRemoteThread(process, nullptr, 0, load_library, (LPVOID)remote_mem, 0, nullptr);
                if (remote_thread == nullptr)
                {
                    err = 6;
                    break;
                }

                WaitForSingleObject(remote_thread, INFINITE);

                DWORD exit_code;
                if(FALSE == GetExitCodeThread(remote_thread, &exit_code))
                {
                    err = 7;
                    break;
                }
                if (exit_code == 0)
                {
                    err = 8;
                    break;
                }
            } while (false);

            if (remote_mem)
                VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            if (remote_thread)
                CloseHandle(remote_thread);
            if (process)
                CloseHandle(process);
            return err;
        }

        int WINAPI eject_dll(const DWORD process_id, const WCHAR* dll_file_path)
        {
            HMODULE remote_module = get_remote_module_handle(process_id, dll_file_path, true);
            if (remote_module == nullptr)
                return 0;

            HANDLE process = OpenProcess(
                PROCESS_QUERY_INFORMATION |   // CreateRemoteThread
                PROCESS_CREATE_THREAD |       // CreateRemoteThread
                PROCESS_VM_OPERATION |        // CreateRemoteThread
                PROCESS_VM_READ |             // CreateRemoteThread
                PROCESS_VM_WRITE,             // CreateRemoteThread
                FALSE, process_id);
            if (process == nullptr)
            {
                return 1;
            }

            HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
            if (!kernel32)
                return 2;

            LPTHREAD_START_ROUTINE free_library = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "FreeLibrary");
            HANDLE remote_thread = CreateRemoteThread(process, nullptr, 0, free_library, (LPVOID)remote_module, 0, nullptr);
            if (remote_thread == nullptr)
            {
                CloseHandle(process);
                return 3;
            }
            WaitForSingleObject(remote_thread, INFINITE);

            DWORD exit_code;
            GetExitCodeThread(remote_thread, &exit_code);
            CloseHandle(remote_thread);
            CloseHandle(process);
            if (exit_code == NULL)
            {
                return 4;
            }
            return 0;
        }

        void WINAPI eject_module(const WCHAR* pName, const WCHAR* mName)
        {
            int i = 0;
            std::vector<DWORD> pe = get_process_ids(pName);
            for(auto& pid: pe)
            {
                if (pid)
                {
                    auto hMod = get_remote_module_handle(pid, mName, false);
                    auto path = get_remote_module_path(pid, hMod);
                    if (hMod)
                    {
                        eject_dll(pid, path.c_str());
                    }
                }
            }
        }

        HMODULE wait_for_module(const wchar_t* module_name)
        {
            HMODULE hModuleHandle = nullptr;
            while ((hModuleHandle = GetModuleHandle(module_name)) == nullptr)
                Sleep(1);
            return hModuleHandle;
        }
    }
}
