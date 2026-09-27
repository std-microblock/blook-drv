#pragma once
#include <stddef.h>

#include "policy/integer.hpp"

namespace blook {
inline constexpr size_t max_hooks = 64;
inline constexpr size_t max_watches = 16;
inline constexpr size_t max_patch = 64;
// One dump record carries at most this many bytes of guest memory. 16 MiB is
// enough for a full unpacked image of any realistic shell while staying a
// single non-paged allocation.
inline constexpr size_t max_dump = 16ull * 1024 * 1024;
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
    const auto delta =
        static_cast<long long>(literal_address) -
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

// Two hooks may share one shadow page iff they patch the same physical page
// for the same execution scope. Scopes: a kernel hook fires in every address
// space, so its only company on a page is another kernel hook; user hooks are
// scoped to an identity page (the owner PEB PFN), so two user hooks on a
// shared image page coexist as long as their owners differ.
[[nodiscard]] constexpr bool same_scope(const hook_spec& a,
                                        const hook_spec& b) noexcept {
    if (a.pfn != b.pfn)
        return false;
    if (a.domain == hook_domain::kernel || b.domain == hook_domain::kernel)
        return a.domain == b.domain;
    return a.address_space != 0 && a.address_space == b.address_space;
}

// The in-page byte ranges the covered instructions of each hook occupy.
[[nodiscard]] constexpr bool patch_ranges_overlap(const hook_spec& a,
                                                  const hook_spec& b) noexcept {
    const auto begin_a = a.target & 0xfff;
    const auto begin_b = b.target & 0xfff;
    return begin_a < begin_b + b.length && begin_b < begin_a + a.length;
}

// May `incoming` live on the same physical page as `existing`? Hooks in
// the same scope merge into one shadow, which only works when their covered
// instruction ranges do not overlap; scopes that would both fire in one
// address space (kernel vs anything) can never share. A physical page shared
// by several processes may carry one independent hook per process.
[[nodiscard]] constexpr bool hooks_compatible(
    const hook_spec& existing, const hook_spec& incoming) noexcept {
    if (existing.pfn != incoming.pfn)
        return true;
    if (existing.domain == hook_domain::kernel ||
        incoming.domain == hook_domain::kernel)
        return existing.domain == incoming.domain &&
               !patch_ranges_overlap(existing, incoming);
    if (existing.address_space != incoming.address_space)
        return true;
    return !patch_ranges_overlap(existing, incoming);
}

// Execute watch: no patch, no shadow page. The physical page of the watched
// address is armed not-executable; an execute violation whose RIP is exactly
// `target` while the owning address space is active triggers a dump into the
// shared record. Same process scoping as user hooks: the identity page is the
// owner PEB.
struct watch_spec {
    uint64_t id{};
    uint64_t pfn{};               // physical page of the watched address
    uint64_t target{};            // linear address whose execution fires
    uint64_t address_space{};     // PEB PFN of the owner process
    uint64_t identity_address{};  // linear address of the PEB
    uint32_t owner_pid{};
    uint8_t domain_{};  // reserved, always 0 (user scope)
};

// Dump states of a watch record.
inline constexpr uint32_t watch_pending = 0;
inline constexpr uint32_t watch_hit = 1;

// Shared between the hypervisor (root mode writes it on a hit) and the driver
// (PASSIVE_LEVEL reads it for the fetch IOCTL). Non-paged, stable address.
// Root mode only ever touches `state` last: a reader that sees watch_hit can
// rely on every other field being final.
struct watch_record {
    volatile uint32_t state{watch_pending};
    uint32_t reserved{};
    uint64_t hit_rip{};
    uint64_t hit_cr3{};
    uint64_t dump_base{};  // guest linear address the dump starts at
    uint64_t dump_size{};  // requested bytes
    uint8_t* buffer{};     // non-paged, max_dump capacity
    // Everything after the pointer is internal to the root-mode writer.
};

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
