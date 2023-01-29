/**
 * @file memory.h
 * @brief 
 * @date 2021-07-07
 * @author abevol (abevol@pm.me)
 * @copyright Copyright (c) 2021, abevol
 */

#pragma once
#include "base.h"

#define PT_Directly    0
#define PT_Absolute    1
#define PT_Relative    2

namespace wstd
{
    namespace memory
    {
        bool is_bad_read_pointer(void* p);
        bool is_bad_write_pointer(void* p);
        bool is_bad_code_pointer(void* p);
        uintptr_t find_pattern(uintptr_t start, size_t length, const unsigned char* pattern, char mask[]);
        uintptr_t find_pattern_ex(uintptr_t start, size_t length, const char* hex_str, int offset, int type, int loops);
        uintptr_t find_pattern_in_module(const wchar_t* module_name, const char* pHex, int offset, int type, int loops);
        const char* mem_search(const char* buf, size_t size, const char* pattern, size_t len);
        std::vector<uintptr_t> mem_search_array(const char* buf, size_t size, const char* pattern, size_t len);
        uintptr_t mem_search_ref(uintptr_t buf, size_t size, uintptr_t target, int32_t next_line = 4);
        uintptr_t get_absolute_address(uintptr_t address, int32_t next_line = 4);
        uintptr_t get_absolute_address(uintptr_t instruction_ptr, int offset, int instruction_size);
        uintptr_t find_ref_string(const wchar_t* module_name, const char* string, int offset);
        uintptr_t find_pattern_after_string(uintptr_t start, size_t length, const char* string, bool fully, const char* pHex, int offset, int type, int loops, int start_offset);
        uintptr_t find_pattern_in_module_after_string(const wchar_t* module_name, const char* string, bool fully, const char* pHex, int offset, int type, int loops, int start_offset);
        uintptr_t find_pattern_in_module_after_string_x64(const wchar_t* module_name, const char* string, bool fully, const char* pHex, int offset, int type, int loops, int start_offset);
        uintptr_t find_pattern_in_module_after_mem(const wchar_t* module_name, const char* mem_hex, const char* pHex, int offset, int type, int loops, int start_offset);
    }
}
