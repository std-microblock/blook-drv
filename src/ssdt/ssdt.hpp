#pragma once
#include <ntifs.h>

#include "policy/integer.hpp"

// System service routine resolution.
//
// The services this driver hooks are not necessarily exported by ntoskrnl:
// current builds only export the Zw* kernel stubs (ZwProtectVirtualMemory),
// and some not even that (ZwWriteVirtualMemory). The service implementation
// is still reachable through the SSDT, so resolution walks that path:
//
//   SSN:   an exported Zw* stub carries it as `mov eax, imm32`; when no Zw*
//          stub is exported either, the ntdll export of the same Nt* name
//          carries it instead (read through a \KnownDlls\ntdll.dll mapping).
//   base:  KeAddSystemServiceTable (always exported) references the service
//          descriptor array with a RIP-relative lea; the first descriptor's
//          Base field points at the service table.
//   entry: routine = table + ((int32_t)table[ssn] >> 4).
//
// MmGetSystemRoutineAddress is tried first and wins where the name is
// exported. The whole chain is self-checked against a service that IS
// exported; a failure anywhere resolves to nullptr and the caller skips the
// hook instead of guessing an address. PASSIVE_LEVEL only.
namespace blook::ssdt {
void* resolve_service(const wchar_t* nt_name);
}  // namespace blook::ssdt
