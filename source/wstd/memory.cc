#include <wstd/memory.h>
#include <wstd/string.h>
#include <wstd/file.h>
#include <Psapi.h>

#define INRANGE(x, a, b)    ((x) >= (a) && (x) <= (b)) 
#define getBits( x )        (INRANGE((x),'A','F') ? ((x) - 'A' + 0xA) : (INRANGE((x),'a','f') ? ((x) - 'a' + 0xA) : (INRANGE((x),'0','9') ? (x) - '0' : 0)))
#define getByte( x )        (getBits((x)[0]) << 4 | getBits((x)[1]))

namespace wstd
{
    namespace memory
    {
        bool is_bad_read_pointer(void* p)
        {
            MEMORY_BASIC_INFORMATION mbi;
            memset(&mbi, 0, sizeof(mbi));
            if (!VirtualQuery(p, &mbi, sizeof(mbi)))
                return true;
            if (!(mbi.State & MEM_COMMIT))
                return true;
            if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                return true;
            if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
                return true;
            return false;
        }

        bool is_bad_write_pointer(void* p)
        {
            MEMORY_BASIC_INFORMATION mbi;
            memset(&mbi, 0, sizeof(mbi));
            if (!VirtualQuery(p, &mbi, sizeof(mbi)))
                return true;
            if (!(mbi.State & MEM_COMMIT))
                return true;
            if (!(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                return true;
            if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
                return true;
            return false;
        }

        bool is_bad_code_pointer(void* p)
        {
            MEMORY_BASIC_INFORMATION mbi;
            memset(&mbi, 0, sizeof(mbi));
            if (!VirtualQuery(p, &mbi, sizeof(mbi)))
                return true;
            if (!(mbi.State & MEM_COMMIT))
                return true;
            if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                return true;
            if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
                return true;
            return false;
        }

        bool is_read_pointer(void* p)
        {
            return !is_bad_read_pointer(p);
        }

        bool is_write_pointer(void* p)
        {
            return !is_bad_write_pointer(p);
        }

        bool is_code_pointer(void* p)
        {
            return !is_bad_code_pointer(p);
        }

        void str_del_char(char* strSrc, char ch)
        {
            char* p = strSrc;
            char* q = strSrc;
            while (*q)
            {
                if (*q != ch)
                {
                    *p++ = *q;
                }
                q++;
            }
            *p = '\0';
        }

        void str_del_char(const char* strSrc, char ch, char* strDst)
        {
            const char* q = strSrc;
            char* p = strDst;
            while (*q)
            {
                if (*q != ch)
                {
                    *p++ = *q;
                }
                q++;
            }
            *p = '\0';
        }

        void parse(char* Hex, unsigned char* pattern, char* mask)
        {
            size_t i = 0;
            size_t Max = strlen(Hex) / 2;
            char* Byte = new char[3];
            memset(Byte, 0, 3 * sizeof(char));

            while (i < Max)
            {
                memcpy_s(Byte, 2, Hex + i * 2, 2);
                if (Byte[0] == '?' && Byte[1] == '?')
                {
                    pattern[i] = 255;
                    mask[i] = '?';
                }
                else
                {
                    pattern[i] = (unsigned char)strtol(Byte, nullptr, 16);
                    mask[i] = 'x';
                }
                i = i + 1;
            }

            mask[i] = '\0';
            delete[] Byte;
        }

        // E8????83EC088BCB
        // E8????????83EC088BCB
        // E8 ? ? ? ? 83 EC 08 8B CB
        // E8 ?? ?? ?? ?? 83 EC 08 8B CB
        void parse_new(const char* hex, size_t len, unsigned char* pattern, char* mask)
        {
            size_t n = 0;
            for (size_t i = 0; i < len; ++i)
            {
                if (hex[i] == ' ')
                    continue;
                if (i + 1 >= len)
                    break;
                if (hex[i] == '?')
                {
                    pattern[n] = 255;
                    mask[n] = '?';
                    ++n;
                    if (hex[i + 1] == '?')
                        ++i;
                    continue;
                }
                if (hex[i + 1] == ' ')
                {
                    ++i;
                    continue;
                }
                pattern[n] = (unsigned char)getByte(hex + i);
                mask[n] = 'x';
                ++i;
                ++n;
            }
            mask[n] = '\0';
        }

        uintptr_t find_pattern(uintptr_t start, size_t length, const unsigned char* pattern, char mask[])
        {
            uintptr_t pos = 0;
            size_t searchLen = strlen(mask) - 1;

            for (uintptr_t retAddress = start; retAddress < start + length; retAddress++)
            {
                if (*(unsigned char*)retAddress == pattern[pos] || mask[pos] == '?')
                {
                    if (mask[pos + 1] == '\0')
                    {
                        return (retAddress - searchLen);
                    }
                    pos++;
                }
                else
                {
                    if (pos)
                    {
                        retAddress = retAddress - pos;
                        pos = 0;
                    }
                }
            }
            return NULL;
        }

        uintptr_t find_pattern_ex(uintptr_t start, size_t length, const char* hex_str, int offset, int type, int loops)
        {
            size_t len = strlen(hex_str);
            char* mask = new char[len + 1];
            auto* pattern = new unsigned char[len + 1];
            uintptr_t retn = 0, addr = 0;

            parse_new(hex_str, len, pattern, mask);

            int i = 0;
            while (i <= loops)
            {
                addr = find_pattern(start, length, pattern, mask);
                if (addr)
                {
                    length = length - (addr - start) - 1;
                    start = addr + 1;
                }
                i = i + 1;
            }

            if (addr)
            {
                if (type == 0) // 直接返回代码地址 + offset
                {
                    retn = addr + offset;
                }
                else if (type == 1) // 返回*(addr + offset)
                {
                    addr = addr + offset;
                    retn = *reinterpret_cast<uintptr_t*>(addr);
                }
                else if (type == 2) // 返回附近Call地址, nearby jmp, nearby const
                {
                    addr = addr + offset;
                    offset = *reinterpret_cast<int32_t*>(addr);
                    retn = addr + 4 + offset;
                }
            }
            delete[] mask;
            delete[] pattern;

            return retn;
        }

        uintptr_t find_pattern_in_module(const wchar_t* module_name, const char* pHex, int offset, int type, int loops)
        {
            uintptr_t address = NULL;
            MODULEINFO ModInfo = { nullptr, 0, nullptr };
            HMODULE hModule = GetModuleHandle(module_name);
            if (hModule)
            {
                if (GetModuleInformation(GetCurrentProcess(), hModule, &ModInfo, sizeof(MODULEINFO)))
                {
                    address = find_pattern_ex(reinterpret_cast<uintptr_t>(ModInfo.lpBaseOfDll), ModInfo.SizeOfImage, pHex, offset, type, loops);
                }
            }
            return address;
        }

        const char* mem_search(const char* buf, size_t size, const char* pattern, size_t len)
        {
            if (len == NULL)
                len = strlen(pattern);
            size_t i = 0;
            while (i < size - len)
            {
                size_t j = 0;
                while (j < len)
                {
                    if (buf[i + j] != pattern[j])
                        break;
                    if (j == len - 1)
                    {
                        return buf + i;
                    }
                    j = j + 1;
                }
                i = i + 1;
            }
            return nullptr;
        }

        std::vector<uintptr_t> mem_search_array(const char* buf, size_t size, const char* pattern, size_t len)
        {
            std::vector<uintptr_t> result;
            if (len == NULL)
                len = strlen(pattern);
            size_t i = 0;
            while (i < size - len)
            {
                size_t j = 0;
                while (j < len)
                {
                    if (buf[i + j] != pattern[j])
                        break;
                    if (j == len - 1)
                    {
                        result.emplace_back((uintptr_t)(buf + i));
                        i = i + len - 1;
                        break;
                    }
                    j = j + 1;
                }
                i = i + 1;
            }
            return result;
        }

        uintptr_t mem_search_ref(uintptr_t buf, size_t size, uintptr_t target, int32_t next_line)
        {
            size_t i = 0;
            while (true)
            {
                if (i + sizeof(int32_t) > size)
                    break;
                uintptr_t addr = buf + i;
                int32_t offset = *(int32_t*)addr;
                if (target == offset + addr + next_line)
                {
                    return addr;
                }
                i = i + 1;
            }
            return 0;
        }

        uintptr_t get_absolute_address(uintptr_t address, int32_t next_line)
        {
            auto offset = *(int32_t*)address;
            return offset + address + next_line;
        }

        uintptr_t get_absolute_address(uintptr_t instruction_ptr, int offset, int instruction_size)
        {
            return instruction_ptr + *reinterpret_cast<int32_t*>(instruction_ptr + offset) + instruction_size;
        }

        uintptr_t find_ref_string(const wchar_t* module_name, const char* string, int offset)
        {
            uintptr_t address = NULL;
            MODULEINFO ModInfo = { nullptr, 0, nullptr };
            HMODULE hModule = GetModuleHandleW(module_name);
            if (hModule)
            {
                if (GetModuleInformation(GetCurrentProcess(), hModule, &ModInfo, sizeof(MODULEINFO)))
                {
                    address = (uintptr_t)mem_search(static_cast<const char*>(ModInfo.lpBaseOfDll), ModInfo.SizeOfImage, string, NULL);
                    if (address)
                    {
                        address = (uintptr_t)mem_search(static_cast<const char*>(ModInfo.lpBaseOfDll), ModInfo.SizeOfImage, reinterpret_cast<const char*>(&address), 4);
                        if (address)
                        {
                            address = address + offset;
                        }
                    }
                }
            }
            return address;
        }

        uintptr_t find_pattern_after_string(uintptr_t start, size_t length, const char* string, bool fully, const char* pHex, int offset, int type, int loops, int start_offset)
        {
            uintptr_t address = NULL;
            auto str_len = strlen(string);
            if (fully)
                ++str_len;
            address = (uintptr_t)mem_search((const char*)(start), length, string, str_len);
            if (address)
            {
                address = (uintptr_t)mem_search((const char*)(start), length, reinterpret_cast<const char*>(&address), 4);
                if (address)
                {
                    if (pHex && *pHex != '\0')
                        address = find_pattern_ex(address + start_offset, start + length - (address + start_offset), pHex, offset, type, loops);
                    else
                        address = address + start_offset;
                }
            }
            return address;
        }

        uintptr_t find_pattern_in_module_after_string(const wchar_t* module_name, const char* string, bool fully, const char* pHex, int offset, int type, int loops, int start_offset)
        {
            uintptr_t address = NULL;
            MODULEINFO ModInfo = { nullptr, 0, nullptr };
            HMODULE hModule = GetModuleHandleW(module_name);
            if (hModule)
            {
                if (GetModuleInformation(GetCurrentProcess(), hModule, &ModInfo, sizeof(MODULEINFO)))
                {
                    address = find_pattern_after_string((uintptr_t)ModInfo.lpBaseOfDll, (size_t)ModInfo.SizeOfImage, string, fully, pHex, offset, type, loops, start_offset);
                }
            }
            return address;
        }

        uintptr_t find_pattern_in_module_after_string_x64(const wchar_t* module_name, const char* string, bool fully, const char* pHex, int offset, int type, int loops, int start_offset)
        {
            uintptr_t address = NULL;
            MODULEINFO ModInfo = { nullptr, 0, nullptr };
            HMODULE hModule = GetModuleHandleW(module_name);
            if (hModule)
            {
                if (GetModuleInformation(GetCurrentProcess(), hModule, &ModInfo, sizeof(MODULEINFO)))
                {
                    auto str_len = strlen(string);
                    if (fully)
                        ++str_len;
                    address = (uintptr_t)mem_search(static_cast<const char*>(ModInfo.lpBaseOfDll), ModInfo.SizeOfImage, string, str_len);
                    if (address)
                    {
                        address = mem_search_ref((uintptr_t)ModInfo.lpBaseOfDll, ModInfo.SizeOfImage, address);
                        if (address)
                        {
                            address = find_pattern_ex(address + start_offset, (uintptr_t)ModInfo.lpBaseOfDll + ModInfo.SizeOfImage - (address + start_offset), pHex, offset, type, loops);
                        }
                    }
                }
            }
            return address;
        }

        uintptr_t find_pattern_in_module_after_mem(const wchar_t* module_name, const char* mem_hex, const char* pHex, int offset, int type, int loops, int start_offset)
        {
            uintptr_t address = NULL;
            MODULEINFO ModInfo = { nullptr, 0, nullptr };
            HMODULE hModule = GetModuleHandleW(module_name);
            if (hModule)
            {
                if (GetModuleInformation(GetCurrentProcess(), hModule, &ModInfo, sizeof(MODULEINFO)))
                {
                    address = find_pattern_ex((uintptr_t)ModInfo.lpBaseOfDll, ModInfo.SizeOfImage, mem_hex, 0, PT_Directly, 0);
                    if (address)
                    {
                        address = find_pattern_ex(address + start_offset, (uintptr_t)ModInfo.lpBaseOfDll + ModInfo.SizeOfImage - (address + start_offset), pHex, offset, type, loops);
                    }
                }
            }
            return address;
        }

        std::wstring get_module_path(const void* address)
        {
            std::wstring path;
            HMODULE module;
            if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)address, &module) == TRUE)
            {
                WCHAR moduleName[MAX_PATH];
                if (GetModuleFileName(module, moduleName, MAX_PATH) == TRUE)
                {
                    path = moduleName;
                }
            }
            return path;
        }

        std::wstring get_module_name(const void* address)
        {
            std::wstring path = get_module_path(address);
            return file::get_filename(path);
        }
    }
}
