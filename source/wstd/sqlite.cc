#ifdef USING_SQLITE3
#include <wstd/sqlite.h>
#include <wstd/string.h>
#include <wstd/logger.h>
#include <sqlite3.h>

namespace wstd
{
    namespace sqlite
    {
        struct callback_data
        {
            uint32_t codepage;
            std::vector<std::wstring>& result;
        };

        static int callback(void* data, int argc, char** argv, char** /*col_name*/)
        {
            auto* cb_data = static_cast<callback_data*>(data);
            if (cb_data)
            {
                for (int i = 0; i < argc; i++)
                {
                    std::wstring value = string::codepage_to_unicode(argv[i], cb_data->codepage);
                    cb_data->result.emplace_back(value);
                }
            }
            return 0;
        }

        bool exec(const std::wstring& db_file, const std::wstring& sql, uint32_t codepage,
                  std::vector<std::wstring>& result)
        {
            sqlite3* db;
            int status = sqlite3_open(string::unicode_to_utf8(db_file).c_str(), &db);
            if (status)
            {
                log_error("can't open database: %hs", sqlite3_errmsg(db));
                return false;
            }
            char* err_msg = nullptr;
            callback_data cb_data{codepage, result};
            status = sqlite3_exec(db, string::unicode_to_utf8(sql).c_str(), callback,
                static_cast<void*>(&cb_data), &err_msg);
            if (status != SQLITE_OK)
            {
                log_error("sqlite3_exec error: %hs", err_msg);
                sqlite3_free(err_msg);
                sqlite3_close(db);
                return false;
            }
            sqlite3_close(db);
            return true;
        }
    }
}
#endif 
