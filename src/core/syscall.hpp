#pragma once

#include <ntifs.h>
#include <windef.h>

#include "expected.hpp"

namespace core {

// Get syscall number from ntdll.dll (SSDT)
Result<ULONG> get_syscall_number(const char* syscall_name);

// Get syscall number from win32u.dll (Shadow SSDT)
Result<ULONG> get_shadow_syscall_number(const char* syscall_name);

// Free cached syscall images
void unload_syscall_images();

}  // namespace core
