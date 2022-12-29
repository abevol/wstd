#include <wstd/service.h>
#include <wstd/process.h>
#include <wstd/logger.h>

namespace wstd
{
    namespace service
    {
        bool is_service_exist(LPCWSTR name)
        {
            bool result = false;
            SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
            if (hSCManager)
            {
                SC_HANDLE hSvr = OpenService(hSCManager, name, SERVICE_QUERY_STATUS);
                if (hSvr)
                {
                    result = true;
                    CloseServiceHandle(hSvr);
                }
                CloseServiceHandle(hSCManager);
            }
            return result;
        }

        bool is_service_running(LPCWSTR name)
        {
            bool result = false;
            auto hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
            if (hSCManager)
            {
                auto hSvr = OpenService(hSCManager, name, SERVICE_QUERY_STATUS);
                if (hSvr)
                {
                    SERVICE_STATUS status;
                    if (QueryServiceStatus(hSvr, &status))
                    {
                        if (status.dwCurrentState == SERVICE_CONTINUE_PENDING ||
                            status.dwCurrentState == SERVICE_RUNNING ||
                            status.dwCurrentState == SERVICE_START_PENDING
                        )
                        {
                            result = true;
                        }
                    }
                    CloseServiceHandle(hSvr);
                }
                CloseServiceHandle(hSCManager);
            }
            return result;
        }

        bool is_running_as_service(const TCHAR* szSvcName)
        {
            bool bResult = false;
            SC_HANDLE schSCManager = nullptr;
            SC_HANDLE schService = nullptr;

            do
            {
                schSCManager = OpenSCManager(
                    NULL, // local computer
                    NULL, // servicesActive database 
                    SC_MANAGER_CONNECT); // only require SC_MANAGER_CONNECT

                if (schSCManager == NULL)
                    break;

                // Get a handle to the service.
                schService = OpenService(
                    schSCManager, // SCM database 
                    szSvcName, // name of service 
                    SERVICE_QUERY_STATUS); // only require SERVICE_QUERY_STATUS

                if (schService == NULL)
                    break;

                // Check the status in case the service is not stopped. 

                DWORD dwBytesNeeded = 0;
                SERVICE_STATUS_PROCESS ssStatus{};
                if (!QueryServiceStatusEx(
                    schService, // handle to service 
                    SC_STATUS_PROCESS_INFO, // information level
                    (LPBYTE)&ssStatus, // address of structure
                    sizeof(SERVICE_STATUS_PROCESS), // size of structure
                    &dwBytesNeeded)) // size needed if buffer is too small
                {
                    break;
                }

                bResult = (GetCurrentProcessId() == ssStatus.dwProcessId);
            } while (false);

            if (schService)
                CloseServiceHandle(schService);
            if (schSCManager)
                CloseServiceHandle(schSCManager);

            return bResult;
        }

        bool is_running_as_service()
        {
            // 也可以用未导出函数 sechost.dll!ScOpenServiceChannelHandle 判断。
            // 如果返回0，表示为服务。
            bool bResult = false;
            DWORD ppid = process::get_parent_process_id(GetCurrentProcessId());
            auto name = process::get_process_name(ppid);
            if (name == L"services.exe")
                bResult = true;
            return bResult;
        }

        BOOL wait_for_service_to_reach_state(SC_HANDLE hService, DWORD dwDesiredState, SERVICE_STATUS* pss,
                                        DWORD dwTimeoutMilliseconds)
        {
            DWORD dwLastState, dwLastCheckPoint;
            BOOL fFirstTime = TRUE; // Don't compare state & checkpoint the first time through
            BOOL fServiceOk = TRUE;
            DWORD dwTimeout = GetTickCount() + dwTimeoutMilliseconds;

            // Loop until the service reaches the desired state,
            // an error occurs, or we timeout
            while (TRUE)
            {
                // Get current state of service
                fServiceOk = ::QueryServiceStatus(hService, pss);

                // If we can't query the service, we're done
                if (!fServiceOk) break;

                // If the service reaches the desired state, we're done
                if (pss->dwCurrentState == dwDesiredState) break;

                // If we timed-out, we're done
                if ((dwTimeoutMilliseconds != INFINITE) && (dwTimeout > GetTickCount()))
                {
                    SetLastError(ERROR_TIMEOUT);
                    break;
                }

                // If this is our first time, save the service's state & checkpoint
                if (fFirstTime)
                {
                    dwLastState = pss->dwCurrentState;
                    dwLastCheckPoint = pss->dwCheckPoint;
                    fFirstTime = FALSE;
                }
                else
                {
                    // If not first time & state has changed, save state & checkpoint
                    if (dwLastState != pss->dwCurrentState)
                    {
                        dwLastState = pss->dwCurrentState;
                        dwLastCheckPoint = pss->dwCheckPoint;
                    }
                    else
                    {
                        // State hasn't change, check that checkpoint is increasing
                        if (pss->dwCheckPoint > dwLastCheckPoint)
                        {
                            // Checkpoint has increased, save checkpoint
                            dwLastCheckPoint = pss->dwCheckPoint;
                        }
                        else
                        {
                            // Checkpoint hasn't increased, service failed, we're done!
                            fServiceOk = FALSE;
                            break;
                        }
                    }
                }
                // We're not done, wait the specified period of time
                Sleep(pss->dwWaitHint);
            }

            // Note: The last SERVICE_STATUS is returned to the caller so
            // that the caller can check the service state and error codes.
            return (fServiceOk);
        }

        DWORD stop_service(LPCTSTR pszInternalName, DWORD dwTimeoutMilliseconds)
        {
            // Variables 
            DWORD dwResult = 0;
            SC_HANDLE hSCM = NULL;
            SC_HANDLE hService = NULL;
            do
            {
                // Connect to the SCM 
                hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
                if (hSCM == NULL)
                {
                    dwResult = GetLastError();
                    break;
                }
                // Open the service 
                hService = ::OpenService(hSCM, pszInternalName, SERVICE_STOP | SERVICE_QUERY_STATUS);
                if (hService == NULL)
                {
                    dwResult = GetLastError();
                    break;
                }
                // Ask the service to stop 
                SERVICE_STATUS ss;
                if (!::ControlService(hService, SERVICE_CONTROL_STOP, &ss))
                {
                    DWORD dwErrCode = GetLastError();
                    if (dwErrCode != ERROR_SERVICE_NOT_ACTIVE)
                    {
                        dwResult = dwErrCode;
                        break;
                    }
                }
                // Wait until it stopped (or timeout expired)
                if (!wait_for_service_to_reach_state(hService, SERVICE_STOPPED, &ss, dwTimeoutMilliseconds))
                {
                    dwResult = GetLastError();
                    break;
                }
            } while (false);
            // Cleanup 
            if (hService != NULL)
                ::CloseServiceHandle(hService);
            if (hSCM != NULL)
                ::CloseServiceHandle(hSCM);
            // Return 
            return dwResult;
        }

        bool remove_service(const std::wstring& name)
        {
            std::wstring cmdLine = L" /c net stop \"" + name + L"\"";
            DWORD dwRet = process::shell_execute_lite(L"runas", L"cmd.exe", cmdLine, L"", 10 * 1000);
            if (dwRet)
            {
                cmdLine = L" /c sc delete \"" + name + L"\"";
                dwRet = process::shell_execute_lite(L"runas", L"cmd.exe", cmdLine, L"", 10 * 1000);
                if (dwRet)
                    return true;
            }
            return false;
        }

        bool remove_service_deprecated(const std::wstring& name)
        {
            bool result = false;
            auto hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
            if (hSCManager)
            {
                auto hSvr = OpenService(hSCManager, name.c_str(), SERVICE_STOP | DELETE);
                if (hSvr)
                {
                    SERVICE_STATUS status;
                    ControlService(hSvr, SERVICE_CONTROL_STOP, &status);
                    if (DeleteService(hSvr))
                    {
                        result = true;
                    }
                    else
                    {
                        // printf_s("DeleteService failed: 0x%X\n", GetLastError());
                    }
                    CloseServiceHandle(hSvr);
                }
                else
                {
                    // printf_s("OpenService failed: 0x%X\n", GetLastError());
                }
                CloseServiceHandle(hSCManager);
            }
            else
            {
                // printf_s("OpenSCManager failed: 0x%X\n", GetLastError());
            }
            return result;
        }

        bool set_service_config(LPCWSTR lpServiceName, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl,
                              LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId,
                              LPCWSTR lpDependencies,
                              LPCWSTR lpServiceStartName, LPCWSTR lpPassword, LPCWSTR lpDisplayName)
        {
            bool result = false;
            auto hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
            if (hSCManager)
            {
                auto hSvr = OpenService(hSCManager, lpServiceName, SERVICE_CHANGE_CONFIG);
                if (hSvr)
                {
                    result = ChangeServiceConfig(hSvr, dwServiceType, dwStartType, dwErrorControl,
                                                 lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies,
                                                 lpServiceStartName, lpPassword, lpDisplayName);
                    CloseServiceHandle(hSvr);
                }
                CloseServiceHandle(hSCManager);
            }
            return result;
        }

        bool get_service_config(LPCWSTR lpServiceName, std::shared_ptr<QUERY_SERVICE_CONFIG>& lpServiceConfig)
        {
            bool result = false;
            auto hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
            if (hSCManager)
            {
                auto hSvr = OpenService(hSCManager, lpServiceName, SERVICE_QUERY_CONFIG);
                if (hSvr)
                {
                    DWORD cbBytesNeeded = 0;
                    QueryServiceConfig(hSvr, nullptr, NULL, &cbBytesNeeded);
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                    {
                        LPBYTE buffer = new(std::nothrow) BYTE[cbBytesNeeded];
                        if (buffer)
                        {
                            if (QueryServiceConfig(hSvr, (LPQUERY_SERVICE_CONFIG)buffer, cbBytesNeeded, &cbBytesNeeded))
                            {
                                lpServiceConfig.reset((LPQUERY_SERVICE_CONFIG)buffer);
                                return true;
                            }
                        }
                    }
                    CloseServiceHandle(hSvr);
                }
                CloseServiceHandle(hSCManager);
            }
            return false;
        }

        bool get_service_desc(SC_HANDLE hSCManager, LPWSTR lpServiceName, std::wstring& result)
        {
            if (!hSCManager || !lpServiceName)
            {
                return false;
            }
            auto hSvr = OpenService(hSCManager, lpServiceName, SERVICE_QUERY_CONFIG);
            if (hSvr)
            {
                DWORD cbBytesNeeded = 0;
                QueryServiceConfig2(hSvr, SERVICE_CONFIG_DESCRIPTION, nullptr, NULL, &cbBytesNeeded);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                {
                    LPBYTE buffer = new(std::nothrow) BYTE[cbBytesNeeded];
                    if (buffer)
                    {
                        if (QueryServiceConfig2(hSvr, SERVICE_CONFIG_DESCRIPTION, buffer, cbBytesNeeded,
                                                &cbBytesNeeded))
                        {
                            SERVICE_DESCRIPTIONW* pSvrConfig = (SERVICE_DESCRIPTIONW*)buffer;
                            if (pSvrConfig->lpDescription)
                            {
                                result = pSvrConfig->lpDescription;
                            }
                            delete[] buffer;
                            buffer = nullptr;
                            CloseServiceHandle(hSvr);
                            return true;
                        }
                        delete[] buffer;
                        buffer = nullptr;
                    }
                }
            }
            return false;
        }

        bool get_service_name_by_desc(const std::wstring& serviceDesc, std::wstring& result)
        {
            auto hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            if (hSCManager)
            {
                DWORD cbBytesNeeded = 0;
                DWORD cbServicesReturned = 0;
                DWORD dwResumeHandle = 0;
                LPBYTE buffer = nullptr;
                ENUM_SERVICE_STATUS_PROCESS* pServices = nullptr;
                while (true)
                {
                    BOOL bRet = EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                                     nullptr, NULL, &cbBytesNeeded, &cbServicesReturned,
                                                     &dwResumeHandle, nullptr);
                    if (!bRet && GetLastError() == ERROR_MORE_DATA && cbBytesNeeded >= sizeof(
                        ENUM_SERVICE_STATUS_PROCESS))
                    {
                        buffer = new(std::nothrow) BYTE[cbBytesNeeded];
                        if (buffer)
                        {
                            if (EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                                     buffer, cbBytesNeeded, &cbBytesNeeded, &cbServicesReturned,
                                                     &dwResumeHandle, nullptr))
                            {
                                pServices = (ENUM_SERVICE_STATUS_PROCESS*)buffer;
                                for (DWORD i = 0; i < cbServicesReturned; ++i)
                                {
                                    auto service = &pServices[i];
                                    std::wstring desc;
                                    if (get_service_desc(hSCManager, service->lpServiceName, desc))
                                    {
                                        if (desc == serviceDesc)
                                        {
                                            result = service->lpServiceName;
                                            return true;
                                        }
                                    }
                                }
                                delete[] buffer;
                                buffer = nullptr;
                                break;
                            }
                            delete[] buffer;
                            buffer = nullptr;
                        }
                    }
                }
                CloseServiceHandle(hSCManager);
            }
            return false;
        }

        bool is_driver_exist(const std::wstring& driverName)
        {
            auto hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            if (hSCManager)
            {
                DWORD cbBytesNeeded = 0;
                DWORD cbServicesReturned = 0;
                DWORD dwResumeHandle = 0;
                LPBYTE buffer = nullptr;
                ENUM_SERVICE_STATUS_PROCESS* pServices = nullptr;
                while (true)
                {
                    BOOL bRet = EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                                     SERVICE_STATE_ALL, nullptr, NULL, &cbBytesNeeded,
                                                     &cbServicesReturned, &dwResumeHandle, nullptr);
                    if (!bRet && GetLastError() == ERROR_MORE_DATA && cbBytesNeeded >= sizeof(
                        ENUM_SERVICE_STATUS_PROCESS))
                    {
                        buffer = new(std::nothrow) BYTE[cbBytesNeeded];
                        if (buffer)
                        {
                            if (EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                                     SERVICE_STATE_ALL, buffer, cbBytesNeeded, &cbBytesNeeded,
                                                     &cbServicesReturned, &dwResumeHandle, nullptr))
                            {
                                // wprintf_s(L"cbServicesReturned: %d\n", cbServicesReturned);
                                pServices = (ENUM_SERVICE_STATUS_PROCESS*)buffer;
                                for (DWORD i = 0; i < cbServicesReturned; ++i)
                                {
                                    auto service = &pServices[i];
                                    // wprintf_s(L"CurrentState: %d, ServiceName: %-32s DisplayName: %ws\n", service->ServiceStatusProcess.dwCurrentState, service->lpServiceName, service->lpDisplayName);
                                    std::wstring desc;
                                    if (service->lpServiceName && driverName == service->lpServiceName)
                                    {
                                        return true;
                                    }
                                }
                                delete[] buffer;
                                buffer = nullptr;
                                break;
                            }
                            delete[] buffer;
                            buffer = nullptr;
                        }
                    }
                }
                CloseServiceHandle(hSCManager);
            }
            return false;
        }

        BOOL install_service(LPCWSTR pszBinaryPathName, LPCWSTR pszServiceName, LPCWSTR pszDisplayName,
                            LPCWSTR pszDescription, DWORD dwStartType, LPCWSTR pszDependencies, LPCWSTR pszAccount,
                            LPCWSTR pszPassword)
        {
            BOOL bResult = FALSE;
            SC_HANDLE schSCManager = NULL;
            SC_HANDLE schService = NULL;
            SC_HANDLE hService = NULL;

            do
            {
                // Open the local default service control manager database
                schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT |
                                             SC_MANAGER_CREATE_SERVICE);
                if (schSCManager == NULL)
                {
                    log_error("OpenSCManager failed w/err 0x%08lx", GetLastError());
                    break;
                }

                // Install the service into SCM by calling CreateService
                schService = CreateService(
                    schSCManager, // SCManager database
                    pszServiceName, // Name of service
                    pszDisplayName, // Name to display
                    SERVICE_QUERY_STATUS, // Desired access
                    SERVICE_WIN32_OWN_PROCESS, // Service type
                    dwStartType, // Service start type
                    SERVICE_ERROR_NORMAL, // Error control type
                    pszBinaryPathName, // Service's binary
                    NULL, // No load ordering group
                    NULL, // No tag identifier
                    pszDependencies, // Dependencies
                    pszAccount, // Service running account
                    pszPassword // Password of the account
                );
                if (schService == NULL)
                {
                    log_error("CreateService failed w/err 0x%08lx", GetLastError());
                    break;
                }
                log_trace("%ws is installed.", pszServiceName);

                hService = OpenService(schSCManager, pszServiceName, SERVICE_CHANGE_CONFIG | SERVICE_START);
                if (schSCManager == NULL)
                {
                    log_error("OpenService failed w/err 0x%08lx", GetLastError());
                    break;
                }

                SERVICE_DESCRIPTIONW description{const_cast<LPWSTR>(pszDescription)};
                if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &description))
                {
                    log_error("ChangeServiceConfig2 failed w/err 0x%08lx", GetLastError());
                }

                if (!StartService(hService, 0, NULL))
                {
                    log_error("StartService failed w/err 0x%08lx", GetLastError());
                    break;
                }
                log_trace("%ws is started.", pszServiceName);

                bResult = TRUE;
            } while (false);

            // Centralized cleanup for all allocated resources.
            if (hService)
            {
                CloseServiceHandle(hService);
                hService = NULL;
            }
            if (schService)
            {
                CloseServiceHandle(schService);
                schService = NULL;
            }
            if (schSCManager)
            {
                CloseServiceHandle(schSCManager);
                schSCManager = NULL;
            }
            return bResult;
        }

        BOOL uninstall_service(LPCWSTR pszServiceName)
        {
            BOOL bResult = FALSE;
            SC_HANDLE schSCManager = NULL;
            SC_HANDLE schService = NULL;

            do
            {
                // Open the local default service control manager database
                schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
                if (schSCManager == NULL)
                {
                    log_error("OpenSCManager failed w/err 0x%08lx", GetLastError());
                    break;
                }

                // Open the service with delete, stop, and query status permissions
                schService = OpenService(schSCManager, pszServiceName, SERVICE_STOP |
                                         SERVICE_QUERY_STATUS | DELETE);
                if (schService == NULL)
                {
                    log_error("OpenService failed w/err 0x%08lx", GetLastError());
                    break;
                }

                // Try to stop the service
                SERVICE_STATUS ssSvcStatus = {};
                if (ControlService(schService, SERVICE_CONTROL_STOP, &ssSvcStatus))
                {
                    log_trace("Stopping %ws.", pszServiceName);
                    Sleep(1);

                    while (QueryServiceStatus(schService, &ssSvcStatus))
                    {
                        if (ssSvcStatus.dwCurrentState == SERVICE_STOP_PENDING)
                        {
                            log_trace(".");
                            Sleep(1);
                        }
                        else
                        {
                            break;
                        }
                    }

                    if (ssSvcStatus.dwCurrentState == SERVICE_STOPPED)
                    {
                        log_trace("%ws is stopped.", pszServiceName);
                    }
                    else
                    {
                        log_error("%ws failed to stop.", pszServiceName);
                    }
                }

                // Now remove the service by calling DeleteService.
                if (!DeleteService(schService))
                {
                    log_error("DeleteService failed w/err 0x%08lx\n", GetLastError());
                    break;
                }

                log_trace("%ws is removed.\n", pszServiceName);
                bResult = TRUE;
            } while (false);

            // Centralized cleanup for all allocated resources.
            if (schService)
            {
                CloseServiceHandle(schService);
                schService = NULL;
            }
            if (schSCManager)
            {
                CloseServiceHandle(schSCManager);
                schSCManager = NULL;
            }
            return bResult;
        }
    }
}
