#include "hide.hpp"

#include "driver/hooks.hpp"
#include "driver/resources.hpp"
#include "driver/hide/nt.hpp"
#include "driver/hide/peb.hpp"
#include "driver/hide/roles.hpp"
#include "driver/hide/win32k.hpp"

namespace blook::hide {
namespace {
EX_PUSH_LOCK profile_lock{};
bool volatile profile_active{};
}  // namespace

NTSTATUS activate() {
    exclusive_lock guard{profile_lock};
    if (profile_active)
        return STATUS_SUCCESS;
    auto status = nt::install();
    if (!NT_SUCCESS(status))
        return status;
    profile_active = true;
    return STATUS_SUCCESS;
}

void deactivate() {
    exclusive_lock guard{profile_lock};
    win32k::remove();
    if (!profile_active)
        return;
    nt::remove();
    profile_active = false;
}

NTSTATUS enable_windows(bool enable) {
    exclusive_lock guard{profile_lock};
    if (enable) {
        if (win32k::installed())
            return STATUS_SUCCESS;
        // The window handlers ask for the caller role, so the nt profile has
        // to be up first.
        if (!profile_active)
            return STATUS_DEVICE_NOT_READY;
        return win32k::install();
    }
    win32k::remove();
    return STATUS_SUCCESS;
}

bool windows_active() { return win32k::installed(); }

ULONG window_hook_count() { return win32k::hook_count(); }

bool active() {
    return profile_active;
}

void forget_process(uint32_t pid) { nt::forget_process(pid); }

void pin(uint32_t pid, role value) {
    roles::pin(pid, value);
}
void unpin(uint32_t pid) {
    roles::unpin(pid);
}

NTSTATUS scrub(uint32_t pid, uint32_t flags) {
    return peb::process(pid, flags);
}
}  // namespace blook::hide
