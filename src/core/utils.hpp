#pragma once

#include <ntifs.h>
#include <windef.h>
#include "Veil.h"

namespace core {

//
// Pattern matching - uses hex string format
// Example: "4123FF66" or "41??FF66" (where ?? means wildcard)
//
uintptr_t find_pattern(uintptr_t base, size_t size, const char* hex_pattern);

//
// Find pattern in a specific PE section
//
uintptr_t find_pattern_section(uintptr_t base, const char* section_name, const char* hex_pattern);

//
// Find pattern in a kernel module
//
uintptr_t find_pattern_km(const wchar_t* module_name, const char* section_name, const char* hex_pattern);

//
// Get system routine by name
//
void* get_system_routine(const wchar_t* routine_name);

//
// Get ntoskrnl base address
//
uintptr_t get_ntos_base();

//
// Initialize core utilities
//
bool init();

//
// Get kernel module base address
//
uintptr_t get_kernel_module_base(const wchar_t* module_name);

//
// Global kernel pointers
//
inline PLIST_ENTRY PsLoadedModuleList = nullptr;
inline PERESOURCE PsLoadedModuleResource = nullptr;

}  // namespace core
