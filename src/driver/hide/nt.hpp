#pragma once
#include <ntifs.h>

namespace blook::hide::nt {
// Install every kernel side EPT hook of the anti-anti-debug profile. All of
// them route through the same call-original window, so the real service still
// runs and the handlers only adjust what the caller observes.
NTSTATUS install();
void remove();
[[nodiscard]] bool installed();

// Drop the one-shot scrub bookkeeping for a process that is going away, so a
// recycled PID still gets its PEB cleared.
void forget_process(ULONG pid);
}  // namespace blook::hide::nt
