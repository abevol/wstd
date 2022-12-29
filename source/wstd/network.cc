#include <wstd/network.h>
#include <wstd/string.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")

namespace wstd
{
    namespace network
    {
        BOOL get_ip_addresses(std::vector<std::string>& ip_list)
        {
            BOOL bResult = FALSE;
            PMIB_IPADDRTABLE pAddresses = nullptr;

            try
            {
                DWORD i = 0;
                DWORD dwSize = 10 * 1024;
                DWORD dwRetVal = 0;

                do
                {
                    pAddresses = (MIB_IPADDRTABLE*)malloc(dwSize);
                    if (pAddresses == NULL)
                    {
                        throw std::exception("Memory allocation failed for MIB_IPADDRTABLE struct");
                    }

                    dwRetVal = GetIpAddrTable(pAddresses, &dwSize, 0);
                    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER)
                    {
                        free(pAddresses);
                        pAddresses = NULL;
                    }
                    else
                    {
                        break;
                    }

                    i++;
                } while ((dwRetVal == ERROR_INSUFFICIENT_BUFFER) && (i < 5));

                if (dwRetVal != NO_ERROR)
                {
                    std::string errorMsg = "GetAdaptersAddresses failed: ";
                    errorMsg.append(std::to_string(dwRetVal));
                    throw std::exception(errorMsg.c_str());
                }

                char ipBuf[32];
                IN_ADDR ipAddr;
                for (i = 0; i < pAddresses->dwNumEntries; i++)
                {
                    ipAddr.S_un.S_addr = (ULONG)pAddresses->table[i].dwAddr;
                    if (InetNtopA(AF_INET, &ipAddr, ipBuf, sizeof(ipBuf)))
                    {
                        ip_list.emplace_back(ipBuf);
                    }
                }

                bResult = TRUE;
            }
            catch (...)
            {
            }

            if (pAddresses)
            {
                free(pAddresses);
            }
            return bResult;
        }

        BOOL get_mac_addresses(std::vector<std::string>& mac_list)
        {
            BOOL bResult = FALSE;
            PIP_ADAPTER_ADDRESSES pAddresses = NULL;

            try
            {
                DWORD dwRetVal;
                uint32_t i = 0;

                // Set the flags to pass to GetAdaptersAddresses
                ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

                // default to unspecified address family (both)
                ULONG family = AF_INET;

                // Allocate a 15 KB buffer to start with.
                ULONG outBufLen = 15 * 1024;

                do
                {
                    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
                    if (pAddresses == NULL)
                    {
                        throw std::exception("Memory allocation failed for IP_ADAPTER_ADDRESSES struct");
                    }

                    dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

                    if (dwRetVal == ERROR_BUFFER_OVERFLOW)
                    {
                        free(pAddresses);
                        pAddresses = NULL;
                    }
                    else
                    {
                        break;
                    }

                    i++;
                } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (i < 5));

                if (dwRetVal != NO_ERROR)
                {
                    std::string errorMsg = "GetAdaptersAddresses failed: ";
                    errorMsg.append(std::to_string(dwRetVal));
                    throw std::exception(errorMsg.c_str());
                }

                PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
                while (pCurrAddresses)
                {
                    if (pCurrAddresses->PhysicalAddressLength != 0)
                    {
                        std::string mac = string::bytes_to_hex(&pCurrAddresses->PhysicalAddress[0],
                                                               pCurrAddresses->PhysicalAddressLength, false);
                        mac_list.emplace_back(mac);
                    }

                    pCurrAddresses = pCurrAddresses->Next;
                }
                bResult = TRUE;
            }
            catch (...)
            {
            }

            if (pAddresses)
                free(pAddresses);

            return bResult;
        }
    }
}
