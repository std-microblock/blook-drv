#pragma once
#include <ntifs.h>

#include "policy/integer.hpp"
#include "policy/names.hpp"

// The anti-anti-debug profile.
//
// Activating it installs the kernel side EPT hooks whose handlers adjust what
// the analysed process observes, so a sample running inside it cannot see the
// debugger, its windows, its handles, the hardware breakpoints it set, or the
// driver doing the hiding. The analyst tools are never filtered.
namespace blook::hide {
NTSTATUS activate();
void deactivate();

// Window hides patch win32k and are therefore a separate opt-in.
NTSTATUS enable_windows(bool enable);
[[nodiscard]] bool windows_active();
[[nodiscard]] ULONG window_hook_count();
[[nodiscard]] bool active();

// Drop per-process bookkeeping when a process exits.
void forget_process(uint32_t pid);

void pin(uint32_t pid, role value);
void unpin(uint32_t pid);

// flags: 0 = peb + heap + debug registers of every thread of the process.
NTSTATUS scrub(uint32_t pid, uint32_t flags);
}  // namespace blook::hide
