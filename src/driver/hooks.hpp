#pragma once
#include <ntifs.h>

#include "policy/hook.hpp"

// Registry of EPT hooks.
//
// A hook is either global (domain = kernel, no owner) or owned by a process
// (domain = user). User hooks carry a per-process identity page - the target
// PEB - which is what the hypervisor compares at execute time, so a hook on a
// shared image page only fires for the process that owns it and a hook keeps
// working in every process the caller names, not just the current one.
namespace blook {
// Bring-up diagnostics: append one line to D:\blook-drv\.cache\driver.log.
void bringup_write(const char* label, uint32_t value, bool have_value);
NTSTATUS initialize_hooks();
void shutdown_hooks();

// Hooks installed by the driver itself carry this token and are not reachable
// from the device ABI.
inline constexpr uint64_t system_token = ~uint64_t{};

// `patch` must fit inside the 64-byte patch buffer and inside the target page.
// `token` identifies the owner for later remove/refresh calls.
NTSTATUS install_hook(uint32_t pid, uint64_t token, void* target,
                      const uint8_t* patch, size_t length, uint64_t& id);

// Installing a hook has two phases, and the split is load bearing: a patch
// may only become executable after everything its handler reads is
// published. `prepare_hook` pins the target page, assigns the id and
// registers the hook (so remove/refresh/revoke already see it); `arm_hook`
// then makes the patch live, logical processor by logical processor. A
// handler starts running on each processor the moment it is armed - possibly
// before arm_hook() returns - so the caller must publish its own state (the
// id its handler passes to begin_hook_window, and the original entry point it
// calls through that window) between the two calls. `cancel_hook` drops a
// prepared hook that was never armed.
struct prepared_hook {
    uint64_t id{};
    hook_spec spec{};
    // Callable copy of the bytes the patch overwrites, followed by a jump
    // back into the original function. Handlers call this instead of the
    // patched entry (see hide::nt), so running the original does not require
    // changing any processor's page views.
    void* trampoline{};
};
NTSTATUS prepare_hook(uint32_t pid, uint64_t token, void* target,
                      const uint8_t* patch, size_t length,
                      prepared_hook& prepared,
                      const void* destination = nullptr);

// Slot for the literal an entry jump reads through (see policy/hook.hpp).
uint64_t* hook_jump_literal(uint32_t slot);
NTSTATUS arm_hook(const prepared_hook& prepared);
void cancel_hook(const prepared_hook& prepared);

// Bring-up diagnostic: reads the REG_DWORD `value` from the driver's own
// service key and reports whether `bit` is set. A missing value means "yes",
// so the normal path is unaffected; the driver's own service-key masking is
// how a hook that misbehaves on a specific machine is bisected without
// rebuilding: set HookMask / WindowHookMask and run `hide on`.
bool service_mask_allows(const wchar_t* value, uint32_t bit);
NTSTATUS remove_hook(uint64_t id);
NTSTATUS refresh_hook(uint64_t id);
// Token checked variants: a session can only drop the hooks it created.
NTSTATUS remove_owned_hook(uint64_t id, uint64_t token);
NTSTATUS refresh_owned_hook(uint64_t id, uint64_t token);
bool hook_present(uint64_t id);

// Call-original window. Only valid on the logical processor that is currently
// executing the hook handler, which is exactly how the guest side handlers use
// it: begin, call the real function, end.
bool begin_hook_window(uint64_t id);
void end_hook_window(uint64_t id);

// Drop every hook owned by a process that is going away.
void revoke_process(uint32_t pid);

// Republish every hook after the hypervisor was restarted, e.g. across a
// system power transition.
void restore_all();
uint32_t active_hook_count();
uint32_t user_hook_count(uint32_t pid);
}  // namespace blook
