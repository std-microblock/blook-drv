#pragma once
#include "page-tables.h"
#include "exception-routines.h"
#include "ept.h"
namespace hv {
// Only used internally for ownership/permission checks; no arbitrary-read API.
inline uint64_t translate_user(uint64_t cr3_value, uint64_t address, bool executable = false) {
    if (!blook::user_address(address)) return 0;
    uint64_t table = cr3_value & blook::page_mask;
    for (unsigned level = 4; level; --level) {
        if (table >= physical_limit) return 0;
        uint64_t entry{};
        auto index = (address >> (12 + (level - 1) * 9)) & 511;
        host_exception_info exception{};
        memcpy_safe(exception, &entry, host_physical_memory_base + table + index * 8, 8);
        if (exception.exception_occurred || (entry & 5) != 5 || (executable && (entry >> 63))) return 0;
        if (level == 1) return (entry & blook::page_mask) | (address & 0xfff);
        if (entry & 0x80) {
            if (level != 2 && level != 3) return 0;
            auto mask = (1ull << (12 + (level - 1) * 9)) - 1;
            return (entry & blook::page_mask & ~mask) | (address & mask);
        }
        table = entry & blook::page_mask;
    }
    return 0;
}

// Same walk without the user-mode range restriction. Used to read the bytes of
// the instruction that caused a control-register exit: for those exits the
// processor's VMCS_VMEXIT_INSTRUCTION_LENGTH turned out to be unreliable, so
// the length has to come from the instruction itself.
inline uint64_t translate_guest(uint64_t cr3_value, uint64_t address, bool executable = false) {
    uint64_t table = cr3_value & blook::page_mask;
    for (unsigned level = 4; level; --level) {
        if (table >= physical_limit) return 0;
        uint64_t entry{};
        auto index = (address >> (12 + (level - 1) * 9)) & 511;
        host_exception_info exception{};
        memcpy_safe(exception, &entry, host_physical_memory_base + table + index * 8, 8);
        // The kernel half of the guest address space is mapped with U/S = 0,
        // so only the present bit is required here (this walk is root mode
        // reading a kernel instruction, never a user-mode access check).
        if (exception.exception_occurred || !(entry & 1) || (executable && (entry >> 63))) return 0;
        if (level == 1) return (entry & blook::page_mask) | (address & 0xfff);
        if (entry & 0x80) {
            if (level != 2 && level != 3) return 0;
            auto mask = (1ull << (12 + (level - 1) * 9)) - 1;
            return (entry & blook::page_mask & ~mask) | (address & mask);
        }
        table = entry & blook::page_mask;
    }
    return 0;
}
}
