#pragma once

// Diagnostic counters for the user-mode hook path. Purely observational: they
// say which branch a hooked-page access took, which is the only way to tell
// "the hook never fired" apart from "the page was never fetched".
namespace hv {
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
};
extern hook_stats g_stats;
}  // namespace hv
