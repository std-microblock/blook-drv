#pragma once
#include <ia32.hpp>
#include "stats.h"

#include "policy/hook.hpp"

namespace hv {

inline constexpr size_t ept_pd_count = 512;
inline constexpr size_t ept_split_count = 160;
inline constexpr uint64_t physical_limit = uint64_t{ept_pd_count} << 30;
inline constexpr uint32_t unused_split = ~uint32_t{};
inline constexpr uint32_t unused_group = ~uint32_t{};

// Every hook on one physical page for one execution scope shares a single
// shadow page: the shadow is a copy of the original with every patch of the
// group applied, so N hooks on a page cost N hook slots but only one shadow
// and one EPT view. Kernel hooks form one global scope per page; user hooks
// form one scope per identity page (the owner PEB PFN), so a page shared by
// several processes still carries one independent group per process.
struct page_group {
    uint64_t pfn{};
    uint64_t address_space{};     // identity PFN for user groups; 0 for kernel
    uint64_t identity_address{};  // linear address translated at fault time
    uint32_t shadow_pfn{};
    blook::hook_domain domain{};
    bool active{};
};

struct hook_slot {
    blook::hook_spec spec{};
    uint32_t group{unused_group};
    bool active{};
};

// An execute watch: the page is armed read/write but not executable. A fetch
// exactly at spec.target in the owning address space dumps into the shared
// record and disarms this processor's entry (one-shot); any other fetch on
// the page is single-stepped and re-armed, exactly like an unowned hook page.
struct watch_slot {
    blook::watch_spec spec{};
    blook::watch_record* record{};
    bool active{};
};

struct vcpu_ept_data {
    alignas(4096) ept_pml4e pml4[512];
    alignas(4096) ept_pdpte pdpt[512];
    alignas(4096) ept_pde_2mb pds[ept_pd_count][512];
    alignas(4096) ept_pte split[ept_split_count][512];
    alignas(4096) uint8_t shadow[blook::max_hooks][4096];
    uint64_t split_pfn[ept_split_count];
    uint64_t large_original[ept_split_count];
    uint32_t split_owner[ept_split_count];
    bool permanent_split[ept_split_count];
    page_group groups[blook::max_hooks];
    hook_slot hooks[blook::max_hooks];
    watch_slot watches[blook::max_watches];
    ept_pte* temporary[blook::max_hooks]{};
    size_t temporary_count{};
    // Nesting depth of call-original windows. While non-zero the hooked page
    // must stay mapped to the untouched original.
    uint32_t window_depth[blook::max_hooks]{};
};

bool prepare_ept(vcpu_ept_data& ept);
void update_ept_memory_type(vcpu_ept_data& ept);
void set_ept_memory_type(vcpu_ept_data& ept, uint8_t type);
ept_pte* get_ept_pte(vcpu_ept_data& ept, uint64_t physical, bool split = false);
bool install_ept_hook(vcpu_ept_data& ept, const blook::hook_spec& spec);
void remove_ept_hook(vcpu_ept_data& ept, uint64_t id);
void refresh_ept_hook(vcpu_ept_data& ept, uint64_t id);
bool install_ept_watch(vcpu_ept_data& ept, const blook::watch_spec& spec,
                       blook::watch_record* record);
void remove_ept_watch(vcpu_ept_data& ept, uint64_t id);
bool begin_ept_window(vcpu_ept_data& ept, uint64_t id);
bool end_ept_window(vcpu_ept_data& ept, uint64_t id);
void rearm_ept(vcpu_ept_data& ept);
void reset_ept_context(vcpu_ept_data& ept);
void handle_page_access(
    vcpu_ept_data& ept, uint64_t physical, bool execute,
    uint64_t guest_rip = ~0ull);  // unknown: policy callers (host tests)
}  // namespace hv
