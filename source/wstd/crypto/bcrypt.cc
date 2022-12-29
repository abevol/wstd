#include <wstd/crypto/bcrypt.h>
#include <wstd/crypto/crypto.h>
#include <winternl.h>
#include <bcrypt.h>
#include <sal.h>
#include <wstd/logger.h>

#pragma comment(lib, "Bcrypt.lib")

namespace wstd
{
    namespace crypto
    {
        NTSTATUS
            EncryptData(
                _In_        BCRYPT_ALG_HANDLE   AlgHandle,
                _In_reads_bytes_(KeyLength)
                PBYTE               Key,
                _In_        DWORD               KeyLength,
                _In_reads_bytes_(InitVectorLength)
                PBYTE               InitVector,
                _In_        DWORD               InitVectorLength,
                _In_reads_bytes_(ChainingModeLength)
                PBYTE               ChainingMode,
                _In_        DWORD               ChainingModeLength,
                _In_reads_bytes_(PlainTextLength)
                PBYTE               PlainText,
                _In_        DWORD               PlainTextLength,
                _Outptr_result_bytebuffer_(*CipherTextLengthPointer)
                PBYTE* CipherTextPointer,
                _Out_       DWORD* CipherTextLengthPointer
            )
        {
            NTSTATUS    Status;

            BCRYPT_KEY_HANDLE   KeyHandle = NULL;

            DWORD   ResultLength = 0;
            PBYTE   TempInitVector = NULL;
            DWORD   TempInitVectorLength = 0;
            PBYTE   CipherText = NULL;
            DWORD   CipherTextLength = 0;

            //
            // Generate an AES key from the key bytes
            //

            Status = BCryptGenerateSymmetricKey(
                AlgHandle,                  // Algorithm provider handle
                &KeyHandle,                 // A pointer to key handle
                NULL,                       // A pointer to the buffer that recieves the key object;NULL implies memory is allocated and freed by the function
                0,                          // Size of the buffer in bytes
                (PBYTE)Key,                 // A pointer to a buffer that contains the key material
                KeyLength,                  // Size of the buffer in bytes
                0);                         // Flags
            if (!NT_SUCCESS(Status))
            {
                log_error("error: 0x%X, errorMsg: %hs", Status, "BCryptGenerateSymmetricKey failed.");
                goto cleanup;
            }


            //
            // Set the chaining mode on the key handle
            //

            Status = BCryptSetProperty(
                KeyHandle,                  // Handle to a CNG object          
                BCRYPT_CHAINING_MODE,       // Property name(null terminated unicode string)
                ChainingMode,               // Address of the buffer that contains the new property value 
                ChainingModeLength,         // Size of the buffer in bytes
                0);                         // Flags
            if (!NT_SUCCESS(Status))
            {
                log_error("error: 0x%X, errorMsg: %hs", Status, "BCryptSetProperty failed.");
                goto cleanup;
            }


            //
            // Copy initialization vector into a temporary initialization vector buffer
            // Because after an encrypt/decrypt operation, the IV buffer is overwritten.
            //

            TempInitVector = (PBYTE)HeapAlloc(GetProcessHeap(), 0, InitVectorLength);
            if (NULL == TempInitVector)
            {
                Status = STATUS_NO_MEMORY;
                log_error("error: 0x%X, errorMsg: %hs", Status, "HeapAlloc failed.");
                goto cleanup;
            }

            TempInitVectorLength = InitVectorLength;
            memcpy(TempInitVector, InitVector, TempInitVectorLength);

            //
            // Get CipherText's length
            // If the program can compute the length of cipher text(based on algorihtm and chaining mode info.), this call can be avoided.
            //

            Status = BCryptEncrypt(
                KeyHandle,                  // Handle to a key which is used to encrypt 
                PlainText,                  // Address of the buffer that contains the plaintext
                PlainTextLength,            // Size of the buffer in bytes
                NULL,                       // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
                TempInitVector,             // Address of the buffer that contains the IV. 
                TempInitVectorLength,       // Size of the IV buffer in bytes
                NULL,                       // Address of the buffer the recieves the ciphertext
                0,                          // Size of the buffer in bytes
                &CipherTextLength,          // Variable that recieves number of bytes copied to ciphertext buffer 
                BCRYPT_BLOCK_PADDING);      // Flags; Block padding allows to pad data to the next block size
            if (!NT_SUCCESS(Status))
            {
                log_error("error: 0x%X, errorMsg: %hs", Status, "BCryptEncrypt failed.");
                goto cleanup;
            }


            //
            // Allocate Cipher Text on the heap
            //

            CipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, CipherTextLength);
            if (NULL == CipherText)
            {
                Status = STATUS_NO_MEMORY;
                log_error("error: 0x%X, errorMsg: %hs", Status, "HeapAlloc failed.");
                goto cleanup;
            }

            //
            // Peform encyption
            // For block length messages, block padding will add an extra block
            //

            Status = BCryptEncrypt(
                KeyHandle,                  // Handle to a key which is used to encrypt 
                PlainText,                  // Address of the buffer that contains the plaintext
                PlainTextLength,            // Size of the buffer in bytes
                NULL,                       // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
                TempInitVector,             // Address of the buffer that contains the IV. 
                TempInitVectorLength,       // Size of the IV buffer in bytes
                CipherText,                 // Address of the buffer the recieves the ciphertext
                CipherTextLength,           // Size of the buffer in bytes
                &ResultLength,              // Variable that recieves number of bytes copied to ciphertext buffer 
                BCRYPT_BLOCK_PADDING);      // Flags; Block padding allows to pad data to the next block size

            if (!NT_SUCCESS(Status))
            {
                log_error("error: 0x%X, errorMsg: %hs", Status, "BCryptEncrypt failed.");
                goto cleanup;
            }


            *CipherTextPointer = CipherText;
            CipherText = NULL;
            *CipherTextLengthPointer = CipherTextLength;

        cleanup:

            if (NULL != CipherText)
            {
                SecureZeroMemory(CipherText, CipherTextLength);
                HeapFree(GetProcessHeap(), 0, CipherText);
            }

            if (NULL != TempInitVector)
            {
                HeapFree(GetProcessHeap(), 0, TempInitVector);
            }

            if (NULL != KeyHandle)
            {
                BCryptDestroyKey(KeyHandle);
            }

            return Status;

        }

        //-----------------------------------------------------------------------------
        //
        //    Decrypt Data
        //
        //-----------------------------------------------------------------------------

        NTSTATUS
            DecryptData(
                _In_        BCRYPT_ALG_HANDLE   AlgHandle,
                _In_reads_bytes_(KeyLength)
                PBYTE               Key,
                _In_        DWORD               KeyLength,
                _In_reads_bytes_(InitVectorLength)
                PBYTE               InitVector,
                _In_        DWORD               InitVectorLength,
                _In_reads_bytes_(ChainingModeLength)
                PBYTE               ChainingMode,
                _In_        DWORD               ChainingModeLength,
                _In_reads_bytes_(CipherTextLength)
                PBYTE               CipherText,
                _In_        DWORD               CipherTextLength,
                _Outptr_result_bytebuffer_(*PlainTextLengthPointer)
                PBYTE* PlainTextPointer,
                _Out_       DWORD* PlainTextLengthPointer
            )
        {
            NTSTATUS    Status;

            BCRYPT_KEY_HANDLE   KeyHandle = NULL;

            PBYTE   TempInitVector = NULL;
            DWORD   TempInitVectorLength = 0;
            PBYTE   PlainText = NULL;
            DWORD   PlainTextLength = 0;
            DWORD   ResultLength = 0;

            //
            // Generate an AES key from the key bytes
            //

            Status = BCryptGenerateSymmetricKey(
                AlgHandle,                  // Algorithm provider handle
                &KeyHandle,                 // A pointer to key handle
                NULL,                       // A pointer to the buffer that recieves the key object;NULL implies memory is allocated and freed by the function
                0,                          // Size of the buffer in bytes
                (PBYTE)Key,                 // A pointer to a buffer that contains the key material
                KeyLength,                  // Size of the buffer in bytes
                0);                         // Flags
            if (!NT_SUCCESS(Status))
            {
                log_error("error: 0x%X, errorMsg: %hs", Status, "BCryptGenerateSymmetricKey failed.");
                goto cleanup;
            }

            BYTE ChainingModeBuffer[255]{};
            ULONG length = 0;
            Status = BCryptGetProperty(
                KeyHandle,
                BCRYPT_CHAINING_MODE,
                ChainingModeBuffer,
                255,
                &length,
                0
            );

            if (!NT_SUCCESS(Status))
            {
                log_error("error: 0x%X, errorMsg: %hs", Status, "BCryptGetProperty failed.");
                goto cleanup;
            }

            // PRINTRACE("ChainingMode: %hs\n", (PCSTR)ChainingModeBuffer);

            if (0 != wcscmp((PCWSTR)ChainingMode, (PCWSTR)ChainingModeBuffer))
            {
                //
                // Set the chaining mode on the key handle
                //

                Status = BCryptSetProperty(
                    KeyHandle,                  // Handle to a CNG object          
                    BCRYPT_CHAINING_MODE,       // Property name(null terminated unicode string)
                    ChainingMode,               // Address of the buffer that contains the new property value 
                    ChainingModeLength,         // Size of the buffer in bytes
                    0);                         // Flags
                if (!NT_SUCCESS(Status))
                {
                    log_error("error: 0x%X, errorMsg: %hs", Status, "BCryptSetProperty failed.");
                    goto cleanup;
                }
            }


            //
            // Copy initialization vector into a temporary initialization vector buffer
            // Because after an encrypt/decrypt operation, the IV buffer is overwritten.
            //

            TempInitVector = (PBYTE)HeapAlloc(GetProcessHeap(), 0, InitVectorLength);
            if (NULL == TempInitVector)
            {
                Status = STATUS_NO_MEMORY;
                log_error("error: 0x%X, errorMsg: %hs", Status, "HeapAlloc failed.");
                goto cleanup;
            }

            TempInitVectorLength = InitVectorLength;
            memcpy(TempInitVector, InitVector, TempInitVectorLength);

            //
            // Get CipherText's length
            // If the program can compute the length of cipher text(based on algorihtm and chaining mode info.), this call can be avoided.
            //

            Status = BCryptDecrypt(
                KeyHandle,                  // Handle to a key which is used to encrypt 
                CipherText,                 // Address of the buffer that contains the ciphertext
                CipherTextLength,           // Size of the buffer in bytes
                NULL,                       // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
                TempInitVector,             // Address of the buffer that contains the IV. 
                TempInitVectorLength,       // Size of the IV buffer in bytes
                NULL,                       // Address of the buffer the recieves the plaintext
                0,                          // Size of the buffer in bytes
                &PlainTextLength,           // Variable that recieves number of bytes copied to plaintext buffer 
                BCRYPT_BLOCK_PADDING);      // Flags; Block padding allows to pad data to the next block size

            if (!NT_SUCCESS(Status))
            {
                log_error("error: 0x%X, errorMsg: %hs", Status, "BCryptDecrypt failed.");
                goto cleanup;
            }

            PlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PlainTextLength);
            if (NULL == PlainText)
            {
                Status = STATUS_NO_MEMORY;
                log_error("error: 0x%X, errorMsg: %ws", Status, L"HeapAlloc failed.");
                goto cleanup;
            }

            //
            // Decrypt CipherText
            //

            Status = BCryptDecrypt(
                KeyHandle,                  // Handle to a key which is used to encrypt 
                CipherText,                 // Address of the buffer that contains the ciphertext
                CipherTextLength,           // Size of the buffer in bytes
                NULL,                       // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
                TempInitVector,             // Address of the buffer that contains the IV. 
                TempInitVectorLength,       // Size of the IV buffer in bytes
                PlainText,                  // Address of the buffer the recieves the plaintext
                PlainTextLength,            // Size of the buffer in bytes
                &ResultLength,              // Variable that recieves number of bytes copied to plaintext buffer 
                BCRYPT_BLOCK_PADDING);      // Flags; Block padding allows to pad data to the next block size

            if (!NT_SUCCESS(Status))
            {
                log_error("error: 0x%X, errorMsg: %hs", Status, "BCryptDecrypt failed.");
                goto cleanup;
            }

            *PlainTextPointer = PlainText;
            PlainText = NULL;
            *PlainTextLengthPointer = ResultLength;

        cleanup:

            if (NULL != PlainText)
            {
                HeapFree(GetProcessHeap(), 0, PlainText);
            }

            if (NULL != TempInitVector)
            {
                HeapFree(GetProcessHeap(), 0, TempInitVector);
            }

            if (NULL != KeyHandle)
            {
                BCryptDestroyKey(KeyHandle);
            }

            return Status;
        }

        DWORD aes_decrypt_data(PBYTE AesKey, DWORD AesKeyLength, PBYTE CipherText, DWORD CipherTextLength, PBYTE& PlainText, DWORD& PlainTextLength)
        {
            NTSTATUS    Status;

            BCRYPT_ALG_HANDLE   AesAlgHandle = NULL;

            DWORD ResultLength = 0;
            DWORD BlockLength = 16;

            PBYTE InitVector = NULL;
            DWORD InitVectorLength = BlockLength;

            //
            // Open an algorithm handle
            //

            Status = BCryptOpenAlgorithmProvider(
                &AesAlgHandle,              // Alg Handle pointer
                BCRYPT_AES_ALGORITHM,       // Cryptographic Algorithm name (null terminated unicode string)
                NULL,                       // Provider name; if null, the default provider is loaded
                0);                         // Flags
            if (!NT_SUCCESS(Status))
            {
                log_error("error: 0x%X, errorMsg: %hs", Status, "BCryptOpenAlgorithmProvider failed.");
                goto cleanup;
            }

            //
            // Allocate the InitVector on the heap
            //

            InitVector = (PBYTE)HeapAlloc(GetProcessHeap(), 0, InitVectorLength);
            if (NULL == InitVector)
            {
                Status = STATUS_NO_MEMORY;
                log_error("error: 0x%X, errorMsg: %hs", Status, "HeapAlloc failed.");
                goto cleanup;
            }

            memset(InitVector, '0', InitVectorLength);

            //
            // Decrypt Cipher text
            //

            Status = DecryptData(
                AesAlgHandle,
                AesKey,
                AesKeyLength,
                InitVector,
                InitVectorLength,
                (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                sizeof(BCRYPT_CHAIN_MODE_CBC),
                CipherText,
                CipherTextLength,
                &PlainText,
                &PlainTextLength);

            if (!NT_SUCCESS(Status))
            {
                log_error("error: 0x%X, errorMsg: %hs", Status, "DecryptData failed.");
                goto cleanup;
            }

            Status = NULL;
            // wprintf(L"Success : Plaintext has been encrypted, ciphertext has been decrypted with AES-128 bit key\n");

        cleanup:

            if (NULL != InitVector)
            {
                HeapFree(GetProcessHeap(), 0, InitVector);
            }

            if (NULL != AesAlgHandle)
            {
                BCryptCloseAlgorithmProvider(AesAlgHandle, 0);
            }

            return (DWORD)Status;
        }

        DWORD decrypt_data(uint8_t xor_key[], const std::string& input, std::string& output)
        {
            BYTE temp_key[24];
            memcpy_s(temp_key, sizeof(temp_key), xor_key, 24);
            xor_crypt(temp_key, sizeof(temp_key), false);

            PBYTE out = nullptr;
            DWORD outLen = 0;
            DWORD status = aes_decrypt_data(temp_key, 192 / 8, (PBYTE)&input[0],
                (DWORD)input.size(), out, outLen);
            memset(temp_key, 0, sizeof(temp_key));
            if (NULL == status && out != nullptr)
                output.assign((char*)out, outLen);
            delete[] out;
            return status;
        }

    }
}
