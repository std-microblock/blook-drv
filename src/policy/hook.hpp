#pragma once
#include <stddef.h>

#include "policy/integer.hpp"

namespace blook {
inline constexpr size_t max_hooks = 64;
inline constexpr size_t max_patch = 64;
inline constexpr uint64_t page_mask = 0x000ffffffffff000ull;

// kernel: the hook fires for every address space that maps the page. The
//         guest side handler decides what to do based on the caller.
// user:   the hook fires only while the owning process address space is
//         active. Ownership is decided by a per-process identity page, so no
//         PID, CR3 or process pointer is ever needed inside root mode.
enum class hook_domain : uint8_t { kernel, user };

struct hook_spec {
    uint64_t id{};
    uint64_t pfn{};               // physical page the hook is placed on
    uint64_t target{};            // linear address of the patched bytes
    uint64_t address_space{};     // PFN of the identity page (user hooks only)
    uint64_t identity_address{};  // linear address of the identity page (user)
    const uint8_t*
        original{};  // nonpaged MDL system mapping, never a user pointer
    uint32_t length{};
    uint32_t owner_pid{};
    uint8_t patch[max_patch]{};
    hook_domain domain{};
};

[[nodiscard]] constexpr bool valid_patch(uint64_t address,
                                         size_t size) noexcept {
    return size && size <= max_patch && (address & 0xfff) + size <= 4096;
}

[[nodiscard]] constexpr bool same_owner(const hook_spec& spec,
                                        uint64_t identity_pfn) noexcept {
    return spec.domain == hook_domain::kernel ||
           (identity_pfn && spec.address_space == identity_pfn);
}

[[nodiscard]] constexpr bool user_address(uint64_t value) noexcept {
    return value >= 0x10000 && value < 0x0000800000000000ull;
}

// The entry jump must not touch anything the machine keeps state in:
// * no register - R10 carries the service address the copy dispatch calls
//   through (nt!KiSystemServiceCopyEnd: mov rax, r10; call rax), R11 is what
//   SYSRET reads the user RFLAGS from, and callers inside the same module keep
//   their own bookkeeping in registers the ABI calls volatile;
// * no stack - the copy dispatch keeps its own bookkeeping in the shadow space
//   below RSP, so writing even one slot there is observable;
// * nothing in the patched page - the shadow is execute-only, so a literal read
//   there would be redirected to the untouched page and yield nonsense.
//
// What is left is an RIP-relative indirect jump whose target literal lives in
// this driver's own data. The displacement is checked against the +/-2 GB the
// encoding can express (measured on the target machine: about 1.2 GB between
// the driver image and nt), and a hook whose literal is out of reach is not
// installed rather than installed wrongly.
inline constexpr size_t jump_patch_length = 6;

[[nodiscard]] inline bool build_jump_patch(uint8_t (&patch)[max_patch],
                                           uint64_t patch_address,
                                           uint64_t literal_address) noexcept {
    const auto delta = static_cast<long long>(literal_address) -
                       static_cast<long long>(patch_address + jump_patch_length);
    if (delta > 0x7fffffffll || delta < -0x80000000ll)
        return false;
    const auto rel = static_cast<int>(delta);
    patch[0] = 0xff;  // jmp qword ptr [rip + rel32]
    patch[1] = 0x25;
    for (unsigned i = 0; i < 4; ++i)
        patch[2 + i] = static_cast<uint8_t>(rel >> (i * 8));
    return true;
}

// Pure state transition policy, also exercised by the host tests.
enum class ept_view {
    original_data,
    original_step,
    window_execute,
    shadow_execute
};
struct mapping {
    uint64_t pfn;
    unsigned permissions;
};

[[nodiscard]] constexpr mapping select_view(ept_view view, uint64_t original,
                                            uint64_t shadow) noexcept {
    switch (view) {
        case ept_view::original_data:
            return {original, 3};
        // Data accesses and an open call-original window both need the
        // untouched page with full read/write/execute rights: an open window is
        // running the original function straight out of that page.
        case ept_view::original_step:
        case ept_view::window_execute:
            return {original, 7};
        case ept_view::shadow_execute:
            // Execute only: reads must still trap so the handler can hand out
            // the untouched page (the entry jump reads nothing).
            return {shadow, 4};
    }
    return {original, 3};
}
}  // namespace blook
