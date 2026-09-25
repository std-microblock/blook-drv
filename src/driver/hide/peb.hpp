#pragma once
#include <ntifs.h>

#include "policy/integer.hpp"

// The debug artefacts a process can read out of its own user-mode structures.
// Clearing them is what the previous implementation did from
// NtDebugActiveProcess and what keeps BeingDebugged / NtGlobalFlag / heap
// checks quiet.
namespace blook::peb {
inline constexpr uint32_t scrub_flags = 0x7;
inline constexpr uint32_t flag_being_debugged = 0x1;
inline constexpr uint32_t flag_global_flag = 0x2;
inline constexpr uint32_t flag_heap = 0x4;

NTSTATUS process(uint32_t pid, uint32_t flags);
NTSTATUS process(PEPROCESS process, uint32_t flags);
}  // namespace blook::peb
