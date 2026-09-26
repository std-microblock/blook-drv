#pragma once

#include "policy/hook.hpp"

// Diagnostic counters for the user-mode hook path. Purely observational: they
// say which branch a hooked-page access took, which is the only way to tell
// "the hook never fired" apart from "the page was never fetched".
namespace hv {
// One slot per VM-exit basic reason (the field is 16 bits wide but every reason
// Intel has defined so far is below 80).
inline constexpr unsigned exit_reason_slots = 80;
// One bit per logical processor, 4 * 32 = 128 processors.
inline constexpr unsigned cpu_mask_words = 4;
// Per-hook diagnostics: one row per hook slot the hypervisor knows about.
inline constexpr unsigned hook_diag_slots = blook::max_hooks;

struct hook_stats {
    volatile long long execute_violations{};
    volatile long long data_violations{};
    volatile long long window_open{};
    volatile long long identity_ok{};
    volatile long long identity_mismatch{};
    volatile long long identity_failed{};
    volatile long long internal_entry{};
    volatile long long shadow_mapped{};
    volatile long long original_step{};
    volatile long long unowned_group{};

    // ---- second round: did the access reach the hypervisor at all? ----
    // Histogram of VM-exit basic reasons. While a hooked page is being executed
    // and exit_reasons[48] (EPT violation) stays zero, the instruction fetch
    // never left guest mode, so no EPT entry could have been in the way.
    volatile long long exit_reasons[exit_reason_slots]{};
    volatile long long vcpu_count{};
    volatile long long invept_calls{};
    volatile long long invept_error{};
    volatile long long ept_misconfig{};

    // Result of the broadcast install: how many logical processors accepted
    // install_ept_hook, and which ones they were.
    volatile long long install_rounds{};
    volatile long long install_ok_cpus{};
    volatile long long install_fail_cpus{};
    volatile long long install_ok_mask[cpu_mask_words]{};
    volatile long long install_fail_mask[cpu_mask_words]{};
    // Read back out of the EPT entry the install just wrote. Present without
    // execute is the only state that can trap an instruction fetch.
    volatile long long armed_entries_verified{};
    volatile long long armed_entries_wrong{};
};

// What the hypervisor armed, per hook slot, plus how often a fetch of that page
// actually faulted.
struct hook_diag_row {
    volatile long long id{};
    volatile long long target{};
    volatile long long pfn{};
    volatile long long address_space{};
    volatile long long domain{};
    volatile long long active{};
    volatile long long execute_hits{};
    volatile long long data_hits{};
    volatile long long identity_mismatches{};
    volatile long long identity_failures{};
    volatile long long shadow_mapped{};
};

extern hook_stats g_stats;
extern hook_diag_row g_hook_diag[hook_diag_slots];
}  // namespace hv
