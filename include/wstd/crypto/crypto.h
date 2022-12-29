/**
 * @file crypto.h
 * @brief 
 * @date 2021-04-21
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include <string>
#include <cstdint>

namespace wstd
{
    namespace crypto
    {
        // Multi byte

        template<typename ValueT>
        ValueT base64_encode(void const* input, size_t len);
        template<>
        std::string base64_encode(void const* input, size_t len);

        template<typename ValueT>
        ValueT base64_encode(std::string const& input);
        template<>
        inline std::string base64_encode(std::string const& input)
        {
            return base64_encode<std::string>(input.data(), input.size());
        }

        std::string base64_decode(char const* input, size_t len);
        inline std::string base64_decode(std::string const& input)
        {
            return base64_decode(input.data(), input.size());
        }

        // Wide byte

        template<>
        std::wstring base64_encode(void const* input, size_t len);
        template<>
        inline std::wstring base64_encode(std::string const& input)
        {
            return base64_encode<std::wstring>(input.data(), input.size());
        }

        std::string base64_decode(wchar_t const* input, size_t len);
        inline std::string base64_decode(std::wstring const& input)
        {
            return base64_decode(input.data(), input.size());
        }

        void xor_crypt(uint8_t* bytes, int len, bool is_encrypt);
    }
}

