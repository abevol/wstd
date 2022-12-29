/**
 * @file network.h
 * @brief 
 * @date 2021-03-12
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"

namespace wstd
{
    namespace network
    {
        BOOL get_ip_addresses(std::vector<std::string>& ip_list);

        BOOL get_mac_addresses(std::vector<std::string>& mac_list);
    }
}
