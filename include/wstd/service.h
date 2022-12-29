/**
 * @file service.h
 * @brief 
 * @date 2021-04-25
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"

namespace wstd
{
    namespace service
    {
        bool is_service_exist(LPCWSTR name);

        bool is_service_running(LPCWSTR name);

        bool is_running_as_service(const TCHAR* szSvcName);

        bool is_running_as_service();

        BOOL wait_for_service_to_reach_state(SC_HANDLE hService, DWORD dwDesiredState,
                                        SERVICE_STATUS* pss, DWORD dwTimeoutMilliseconds);

        DWORD stop_service(LPCTSTR pszInternalName, DWORD dwTimeoutMilliseconds = 5000);

        bool remove_service(const std::wstring& name);

        bool remove_service_deprecated(const std::wstring& name);

        bool set_service_config(
            LPCWSTR lpServiceName,
            DWORD dwServiceType = SERVICE_NO_CHANGE,
            DWORD dwStartType = SERVICE_NO_CHANGE,
            DWORD dwErrorControl = SERVICE_NO_CHANGE,
            LPCWSTR lpBinaryPathName = nullptr,
            LPCWSTR lpLoadOrderGroup = nullptr,
            LPDWORD lpdwTagId = nullptr,
            LPCWSTR lpDependencies = nullptr,
            LPCWSTR lpServiceStartName = nullptr,
            LPCWSTR lpPassword = nullptr,
            LPCWSTR lpDisplayName = nullptr);

        bool get_service_config(
            LPCWSTR lpServiceName,
            std::shared_ptr<QUERY_SERVICE_CONFIG>& lpServiceConfig);

        bool get_service_desc(SC_HANDLE hSCManager, LPWSTR lpServiceName, std::wstring& result);

        bool get_service_name_by_desc(const std::wstring& serviceDesc, std::wstring& result);

        bool is_driver_exist(const std::wstring& driverName);

        BOOL install_service(
            LPCWSTR pszBinaryPathName,
            LPCWSTR pszServiceName,
            LPCWSTR pszDisplayName,
            LPCWSTR pszDescription,
            DWORD dwStartType,
            LPCWSTR pszDependencies,
            LPCWSTR pszAccount,
            LPCWSTR pszPassword);

        BOOL uninstall_service(LPCWSTR pszServiceName);
    }
}
