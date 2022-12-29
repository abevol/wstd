/**
 * @file bcrypt.h
 * @brief 
 * @date 2021-04-21
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>

namespace wstd
{
    namespace crypto
    {
        DWORD aes_decrypt_data(PBYTE AesKey, DWORD AesKeyLength, PBYTE CipherText, DWORD CipherTextLength, PBYTE& PlainText, DWORD& PlainTextLength);
        DWORD decrypt_data(uint8_t xor_key[], const std::string& input, std::string& output);
    }
}
