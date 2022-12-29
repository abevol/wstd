#include <wstd/crypto/crypto.h>
#include <wstd/base.h>
#include <wincrypt.h>

namespace wstd
{
    namespace crypto
    {
        // Multi byte

        template<>
        std::string base64_encode(void const* input, size_t len)
        {
            std::string result;
            DWORD dwLen = 0;
            if (CryptBinaryToStringA((const BYTE*)input, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &dwLen))
            {
                CHAR* buffer = (CHAR*)malloc(dwLen);
                if (buffer)
                {
                    if (CryptBinaryToStringA((const BYTE*)input, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buffer, &dwLen))
                    {
                        result.assign(buffer, dwLen);
                    }
                    free(buffer);
                }
            }
            return result;
        }

        std::string base64_decode(char const* input, size_t len)
        {
            std::string result;
            DWORD dwLen = 0;
            if (CryptStringToBinaryA(input, (DWORD)len, CRYPT_STRING_BASE64, nullptr, &dwLen, nullptr, nullptr))
            {
                CHAR* buffer = (CHAR*)malloc(dwLen);
                if (buffer)
                {
                    if (CryptStringToBinaryA(input, (DWORD)len, CRYPT_STRING_BASE64, (BYTE*)buffer, &dwLen, nullptr, nullptr))
                    {
                        result.assign(buffer, dwLen);
                    }
                    free(buffer);
                }
            }
            return result;
        }

        // Wide byte

        template<>
        std::wstring base64_encode(void const* input, size_t len)
        {
            std::wstring result;
            DWORD dwLen = 0;
            if (CryptBinaryToStringW((const BYTE*)input, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &dwLen))
            {
                WCHAR* buffer = (WCHAR*)malloc(dwLen * sizeof(WCHAR));
                if (buffer)
                {
                    if (CryptBinaryToStringW((const BYTE*)input, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buffer, &dwLen))
                    {
                        result.assign(buffer, dwLen);
                    }
                    free(buffer);
                }
            }
            return result;
        }

        std::string base64_decode(wchar_t const* input, size_t len)
        {
            std::string result;
            DWORD dwLen = 0;
            if (CryptStringToBinaryW(input, (DWORD)len, CRYPT_STRING_BASE64, nullptr, &dwLen, nullptr, nullptr))
            {
                CHAR* buffer = (CHAR*)malloc(dwLen);
                if (buffer)
                {
                    if (CryptStringToBinaryW(input, (DWORD)len, CRYPT_STRING_BASE64, (BYTE*)buffer, &dwLen, nullptr, nullptr))
                    {
                        result.assign(buffer, dwLen);
                    }
                    free(buffer);
                }
            }
            return result;
        }

        void xor_crypt(uint8_t* bytes, int len, bool is_encrypt)
        {
            uint8_t seed = 0x66;
            if (is_encrypt)
            {
                for (int i = len - 1; i >= 0; i--)
                {
                    bytes[i] ^= seed;
                    seed = bytes[i];
                }
            }
            else
            {
                for (int i = 0; i < len; i++)
                {
                    if (i == len - 1)
                    {
                        bytes[i] ^= seed;
                        seed = 0;
                        break;
                    }
                    bytes[i] ^= bytes[i + 1];
                }
            }
        }

    }
}
