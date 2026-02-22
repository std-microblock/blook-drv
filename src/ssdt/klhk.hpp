#pragma once

#include <ntifs.h>
#include <windef.h>

#include "core/core.hpp"

// Kaspersky klhk.sys interface
// Handles initialization and low-level SSDT manipulation

namespace ssdt::klhk {

// Check if klhk.sys is loaded
bool is_loaded();

// Initialize klhk.sys interface (find required addresses)
core::VoidResult initialize();

// Initialize hypervisor support
core::Result<NTSTATUS> hvm_init();

// Get SSDT service count
unsigned int get_ssdt_count();

// Get Shadow SSDT service count
unsigned int get_shadow_ssdt_count();

// Get SSDT dispatch array (internal use)
void*** get_dispatch_array();

// Hook SSDT routine (low-level)
bool hook_ssdt_routine(unsigned short index, void* dest, void** original);

// Unhook SSDT routine (low-level)
bool unhook_ssdt_routine(unsigned short index, void* original);

// Hook Shadow SSDT routine (low-level)
bool hook_shadow_ssdt_routine(unsigned short index, void* dest,
                              void** original);

// Unhook Shadow SSDT routine (low-level)
bool unhook_shadow_ssdt_routine(unsigned short index, void* original);

// Get SSDT routine address
void* get_ssdt_routine(unsigned short index);

// Get Shadow SSDT routine address
void* get_shadow_ssdt_routine(unsigned short index);

}  // namespace ssdt::klhk
