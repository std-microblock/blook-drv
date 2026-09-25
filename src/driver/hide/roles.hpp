#pragma once
#include <ntifs.h>

#include "policy/integer.hpp"
#include "policy/names.hpp"

// Runtime classification of the caller.
//
//   target : the image under analysis. Hook handlers only alter behaviour for
//            these callers, which is what keeps the sample from noticing the
//            debugger.
//   tool   : the analyst tools. They always see the real system.
//
// Names come from the policy tables; a PID may additionally be pinned to a
// role so a renamed binary can still be classified.
namespace blook::roles {
role of_process(PEPROCESS process);
role of_pid(uint32_t pid);
role of_current();

[[nodiscard]] inline bool is_target() {
    return of_current() == role::target;
}
[[nodiscard]] inline bool is_tool() {
    return of_current() == role::tool;
}

[[nodiscard]] bool pid_is_target(uint32_t pid);
[[nodiscard]] bool pid_is_tool(uint32_t pid);

// Pin table lookup only: no process reference, no name resolution, safe to
// call for every entry of a system information list.
[[nodiscard]] role pinned_role(uint32_t pid);

void pin(uint32_t pid, role value);
void unpin(uint32_t pid);
void reset();
}  // namespace blook::roles
