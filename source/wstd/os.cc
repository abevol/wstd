#include <wstd/os.h>
#include <wstd/string.h>
#include <sddl.h>

namespace wstd
{
    namespace os
    {
        std::string get_env_var(const char* name)
        {
            std::string result;
            size_t value_size;
            getenv_s(&value_size, nullptr, 0, name);
            if (value_size)
            {
                auto* value = (char*)malloc(value_size * sizeof(char));
                if (value)
                {
                    if (NULL == getenv_s(&value_size, value, value_size, name))
                        result = value;
                    free(value);
                }
            }
            return result;
        }

        std::wstring get_env_var(const wchar_t* name)
        {
            std::wstring result;
            size_t value_size;
            _wgetenv_s(&value_size, nullptr, 0, name);
            if (value_size)
            {
                auto* value = (wchar_t*)malloc(value_size * sizeof(wchar_t));
                if (value)
                {
                    if (NULL == _wgetenv_s(&value_size, value, value_size, name))
                        result = value;
                    free(value);
                }
            }
            return result;
        }

        std::wstring get_local_app_data_dir()
        {
            return get_env_var(L"LOCALAPPDATA");
        }

        std::wstring get_local_app_data_programs_dir()
        {
            const auto app_data_dir = get_local_app_data_dir();
            if (!app_data_dir.empty())
                return app_data_dir + L"\\Programs";
            return L"";
        }

        std::wstring get_program_data_dir()
        {
            return get_env_var(L"ProgramData");
        }

        std::wstring get_current_directory()
        {
            std::wstring result;
            WCHAR buffer[MAX_PATH];
            DWORD retSize = GetCurrentDirectory(MAX_PATH, buffer);
            if (retSize && retSize <= MAX_PATH)
            {
                result.assign(buffer, retSize);
            }
            return result;
        }

        bool get_account_sid(LPTSTR AccountName, PSID* Sid)
        {
            PSID pSID = NULL;
            DWORD cbSid = 0;
            LPTSTR DomainName = NULL;
            DWORD cbDomainName = 0;
            SID_NAME_USE SIDNameUse;
            BOOL bDone = FALSE;

            try
            {
                if (!LookupAccountName(NULL,
                                       AccountName,
                                       pSID,
                                       &cbSid,
                                       DomainName,
                                       &cbDomainName,
                                       &SIDNameUse))
                {
                    pSID = (PSID)malloc(cbSid);
                    DomainName = (LPTSTR)malloc(cbDomainName * sizeof(TCHAR));
                    if (!pSID || !DomainName)
                    {
                        throw;
                    }
                    if (!LookupAccountName(NULL,
                                           AccountName,
                                           pSID,
                                           &cbSid,
                                           DomainName,
                                           &cbDomainName,
                                           &SIDNameUse))
                    {
                        throw;
                    }
                    bDone = TRUE;
                }
            }
            catch (...)
            {
                //nothing
            }

            if (DomainName)
            {
                free(DomainName);
            }
            if (!bDone && pSID)
            {
                free(pSID);
            }
            if (bDone)
            {
                *Sid = pSID;
            }

            return bDone;
        }

        std::wstring get_current_user_sid()
        {
            std::wstring result;
            HANDLE hProc = nullptr;
            HANDLE hToken = nullptr;
            PSID pSid = nullptr;
            LPWSTR pStrSid = nullptr;

            try
            {
                DWORD pid = GetProcessId(L"explorer.exe");
                if (!pid)
                    throw;

                hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                if (!hProc)
                    throw;

                if (!OpenProcessToken(hProc, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
                    throw;

                if (!ImpersonateLoggedOnUser(hToken))
                    throw;

                wchar_t szBuf[MAX_PATH] = L"";
                DWORD dwRet = MAX_PATH;
                if (!GetUserName(szBuf, &dwRet))
                    throw;

                if (!RevertToSelf())
                    throw;

                if (!get_account_sid(szBuf, &pSid))
                    throw;

                if (!ConvertSidToStringSid(pSid, &pStrSid))
                    throw;

                if (!pStrSid)
                    throw;

                result = pStrSid;
            }
            catch (...)
            {
                //nothing
            }

            if (hProc)
                CloseHandle(hProc);
            if (hToken)
                CloseHandle(hToken);
            if (pSid)
                free(pSid);
            if (pStrSid)
                LocalFree(pStrSid);

            return result;
        }
    }
}
