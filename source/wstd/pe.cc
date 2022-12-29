#include <wstd/pe.h>
#include <wstd/string.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")

namespace wstd
{
    namespace pe
    {
        bool read_resource_data(HMODULE hMod, int res_id, std::string& data)
        {
            if (!hMod)
                return false;
            auto hRes = FindResource(hMod, MAKEINTRESOURCE(res_id), RT_RCDATA);
            if (!hRes)
                return false;

            auto hResLoad = LoadResource(hMod, hRes);
            if (!hResLoad)
                return false;

            auto lpResLock = LockResource(hResLoad);
            if (!lpResLock)
                return false;

            auto dwSize = SizeofResource(hMod, hRes);
            if (!dwSize)
                return false;

            data.assign((const char*)lpResLock, dwSize);
            return true;
        }

        bool write_resource_data(const std::wstring& file, int res_id, const std::string& data)
        {
            HANDLE hUpdateRes = BeginUpdateResource(file.c_str(), FALSE);
            if (!hUpdateRes)
                return false;

            BOOL result = UpdateResource(
                hUpdateRes,
                RT_RCDATA,
                MAKEINTRESOURCE(res_id),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                (LPVOID)&data[0],
                (DWORD)data.size());
            if (!result)
                return false;

            result = EndUpdateResource(hUpdateRes, FALSE);
            if (!result)
                return false;
            return true;
        }
    }
}
