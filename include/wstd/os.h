/**
 * @file os.h
 * @brief 
 * @date 2021-03-12
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"

namespace wstd
{
    namespace os
    {
        std::string get_env_var(const char* name);

        std::wstring get_env_var(const wchar_t* name);

        inline bool set_env_var(const char* name, const char* value)
        {
            return _putenv_s(name, value) == 0;
        }

        inline bool set_env_var(const wchar_t* name, const wchar_t* value)
        {
            return _wputenv_s(name, value) == 0;
        }

        std::wstring get_local_app_data_dir();

        std::wstring get_local_app_data_programs_dir();

        std::wstring get_program_data_dir();

        std::wstring get_current_directory();

        bool get_account_sid(LPTSTR AccountName, PSID* Sid);

        std::wstring get_current_user_sid();
    }
}
