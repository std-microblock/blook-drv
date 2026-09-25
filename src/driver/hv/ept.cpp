#include "ept.h"

#include <string.h>

#include "ept_platform.hpp"
#include "mtrr.h"

namespace hv {
namespace {
void invalidate() {
    platform::invalidate();
}

void map(ept_pte& pte, blook::mapping mapping) {
    // Preserve the memory type and ignore-PAT; never inherit R/W from an
    // execute view.
    pte.flags = (pte.flags & 0x78) | (mapping.pfn << 12) | mapping.permissions;
}

void copy_shadow(vcpu_ept_data& ept, size_t index) {
    const auto& spec = ept.hooks[index].spec;
    platform::copy(ept.shadow[index], spec.original, 4096);
    platform::copy(ept.shadow[index] + (spec.target & 0xfff), spec.patch,
                   spec.length);
}

bool page_hooked(const vcpu_ept_data& ept, uint64_t pfn) {
    for (const auto& hook : ept.hooks)
        if (hook.active && hook.spec.pfn == pfn)
            return true;
    return false;
}

// Is any call-original window currently open on this page? While one is open
// the page has to keep exposing the untouched original, otherwise the function
// we are in the middle of calling would trap again and re-enter its own hook.
bool window_open(const vcpu_ept_data& ept, uint64_t pfn) {
    for (size_t i = 0; i < blook::max_hooks; ++i)
        if (ept.hooks[i].active && ept.hooks[i].spec.pfn == pfn &&
            ept.window_depth[i])
            return true;
    return false;
}

size_t hook_index(const vcpu_ept_data& ept, uint64_t id) {
    for (size_t i = 0; i < blook::max_hooks; ++i)
        if (ept.hooks[i].active && ept.hooks[i].spec.id == id)
            return i;
    return blook::max_hooks;
}

blook::ept_view armed_view(const vcpu_ept_data& ept, uint64_t pfn) {
    return window_open(ept, pfn) ? blook::ept_view::window_execute
                                 : blook::ept_view::original_data;
}
}  // namespace

ept_pte* get_ept_pte(vcpu_ept_data& ept, uint64_t address, bool split) {
    if (address >= physical_limit)
        return nullptr;
    auto& large = ept.pds[address >> 30][(address >> 21) & 511];
    const auto owner = static_cast<uint32_t>(address >> 21);
    if (large.large_page) {
        if (!split)
            return nullptr;
        size_t slot = 0;
        while (slot < ept_split_count && ept.split_owner[slot] != unused_split)
            ++slot;
        if (slot == ept_split_count)
            return nullptr;
        ept.large_original[slot] = large.flags;
        for (size_t i = 0; i < 512; ++i)
            ept.split[slot][i].flags =
                ((address & ~0x1fffffull) + (i << 12)) | (large.flags & 0x7f);
        ept.split_owner[slot] = owner;
        large.flags = (ept.split_pfn[slot] << 12) | 7;
    }
    for (size_t i = 0; i < ept_split_count; ++i)
        if (ept.split_owner[i] == owner)
            return &ept.split[i][(address >> 12) & 511];
    return nullptr;
}

bool prepare_ept(vcpu_ept_data& ept) {
    memset(&ept, 0, sizeof(ept));
    ept.pml4[0].flags = platform::physical_address(ept.pdpt) | 7;
    const auto mtrrs = read_mtrr_data();
    for (size_t i = 0; i < ept_split_count; ++i) {
        ept.split_pfn[i] = platform::physical_address(ept.split[i]) >> 12;
        ept.split_owner[i] = unused_split;
    }
    for (size_t i = 0; i < blook::max_hooks; ++i)
        ept.hooks[i].shadow_pfn =
            platform::physical_address(ept.shadow[i]) >> 12;
    for (size_t i = 0; i < ept_pd_count; ++i) {
        ept.pdpt[i].flags = platform::physical_address(ept.pds[i]) | 7;
        for (size_t j = 0; j < 512; ++j) {
            uint64_t address = (i * 512 + j) << 21;
            ept.pds[i][j].flags =
                address | 0x87 |
                (uint64_t{calc_mtrr_mem_type(mtrrs, address, 1ull << 21)} << 3);
        }
    }
    // Split every MTRR boundary inside a 2-MiB leaf instead of mixing cache
    // types.
    for (unsigned i = 0; i < mtrrs.count; ++i) {
        const uint64_t boundaries[] = {mtrrs.ranges[i].begin,
                                       mtrrs.ranges[i].end};
        for (auto address : boundaries) {
            if (address >= physical_limit || !(address & 0x1fffff))
                continue;
            if (!get_ept_pte(ept, address, true))
                return false;
        }
    }
    for (size_t i = 0; i < ept_split_count; ++i) {
        if (ept.split_owner[i] == unused_split)
            continue;
        ept.permanent_split[i] = true;
        for (auto& pte : ept.split[i])
            pte.memory_type =
                calc_mtrr_mem_type(mtrrs, pte.page_frame_number << 12, 4096);
    }
    return true;
}

void update_ept_memory_type(vcpu_ept_data& ept) {
    const auto mtrrs = read_mtrr_data();
    // Runtime MTRR boundary changes must not leave a mixed-type large leaf.
    for (unsigned i = 0; i < mtrrs.count; ++i) {
        const uint64_t boundaries[] = {mtrrs.ranges[i].begin,
                                       mtrrs.ranges[i].end};
        for (auto a : boundaries)
            if (a < physical_limit && (a & 0x1fffff)) {
                if (!get_ept_pte(ept, a, true))
                    fatal_root_error();
                for (size_t k = 0; k < ept_split_count; ++k)
                    if (ept.split_owner[k] == (a >> 21))
                        ept.permanent_split[k] = true;
            }
    }
    for (size_t i = 0; i < ept_pd_count; ++i)
        for (size_t j = 0; j < 512; ++j)
            if (ept.pds[i][j].large_page)
                ept.pds[i][j].memory_type =
                    calc_mtrr_mem_type(mtrrs, (i * 512 + j) << 21, 1ull << 21);
    for (size_t i = 0; i < ept_split_count; ++i)
        if (ept.split_owner[i] != unused_split) {
            auto base = uint64_t{ept.split_owner[i]} << 21;
            ept.large_original[i] =
                base | 0x87 |
                (uint64_t{calc_mtrr_mem_type(mtrrs, base, 1ull << 21)} << 3);
            for (auto& pte : ept.split[i])
                pte.memory_type = calc_mtrr_mem_type(
                    mtrrs, pte.page_frame_number << 12, 4096);
        }
}

void set_ept_memory_type(vcpu_ept_data& ept, uint8_t type) {
    for (auto& pd : ept.pds)
        for (auto& pde : pd)
            if (pde.large_page)
                pde.memory_type = type;
    for (size_t i = 0; i < ept_split_count; ++i)
        if (ept.split_owner[i] != unused_split) {
            ept.large_original[i] =
                (ept.large_original[i] & ~0x38ull) | (uint64_t{type} << 3);
            for (auto& pte : ept.split[i])
                pte.memory_type = type;
        }
}

void rearm_ept(vcpu_ept_data& ept) {
    for (size_t i = 0; i < ept.temporary_count; ++i) {
        auto& pte = *ept.temporary[i];
        // A page whose call-original window is still open must go back to the
        // unpatched execute view, not to the armed (non-executable) one:
        // otherwise the code the handler is in the middle of calling would
        // trap again and re-enter its own hook.
        auto const pfn = pte.page_frame_number;
        map(pte, blook::select_view(armed_view(ept, pfn), pfn, 0));
    }
    ept.temporary_count = 0;
    platform::single_step(false);
    invalidate();
}

void reset_ept_context(vcpu_ept_data& ept) {
    if (ept.temporary_count)
        rearm_ept(ept);
    for (const auto& hook : ept.hooks)
        if (hook.active)
            map(*get_ept_pte(ept, hook.spec.pfn << 12),
                blook::select_view(armed_view(ept, hook.spec.pfn),
                                   hook.spec.pfn, hook.shadow_pfn));
    invalidate();
}

bool install_ept_hook(vcpu_ept_data& ept, const blook::hook_spec& spec) {
    if (!blook::valid_patch(spec.target, spec.length))
        return false;
    size_t index = blook::max_hooks;
    for (size_t i = 0; i < blook::max_hooks; ++i) {
        const auto& hook = ept.hooks[i];
        if (!hook.active) {
            if (index == blook::max_hooks)
                index = i;
            continue;
        }
        const bool same_page = hook.spec.pfn == spec.pfn;
        const bool shared = hook.spec.address_space == spec.address_space;
        const bool global = hook.spec.domain == blook::hook_domain::kernel ||
                            spec.domain == blook::hook_domain::kernel;
        if (hook.spec.id == spec.id || (same_page && (global || shared)))
            return false;
    }
    if (index == blook::max_hooks)
        return false;
    auto pte = get_ept_pte(ept, spec.pfn << 12, true);
    if (!pte || pte->memory_type != MEMORY_TYPE_WRITE_BACK)
        return false;
    ept.hooks[index].spec = spec;
    ept.window_depth[index] = 0;
    copy_shadow(ept, index);
    ept.hooks[index].active = true;
    map(*pte, blook::select_view(blook::ept_view::original_data, spec.pfn, 0));
    invalidate();
    return true;
}

void refresh_ept_hook(vcpu_ept_data& ept, uint64_t id) {
    const auto index = hook_index(ept, id);
    if (index == blook::max_hooks)
        return;
    const auto pfn = ept.hooks[index].spec.pfn;
    copy_shadow(ept, index);
    map(*get_ept_pte(ept, pfn << 12),
        blook::select_view(armed_view(ept, pfn), pfn,
                           ept.hooks[index].shadow_pfn));
    invalidate();
}

void remove_ept_hook(vcpu_ept_data& ept, uint64_t id) {
    const auto index = hook_index(ept, id);
    if (index == blook::max_hooks)
        return;
    auto& hook = ept.hooks[index];
    const auto pfn = hook.spec.pfn;
    hook.active = false;
    ept.window_depth[index] = 0;
    // Hooks that share nothing with this page get their execute permission
    // back; pages that still carry a hook keep trapping.
    const auto view = page_hooked(ept, pfn) ? blook::ept_view::original_data
                                            : blook::ept_view::original_step;
    map(*get_ept_pte(ept, pfn << 12), blook::select_view(view, pfn, 0));
    // Reclaim a split only when every hook sharing that 2-MiB range is gone.
    bool in_use = false;
    for (const auto& other : ept.hooks)
        if (other.active && (other.spec.pfn >> 9) == (pfn >> 9))
            in_use = true;
    if (!in_use)
        for (size_t i = 0; i < ept_split_count; ++i)
            if (!ept.permanent_split[i] && ept.split_owner[i] == (pfn >> 9)) {
                ept.pds[pfn >> 18][(pfn >> 9) & 511].flags =
                    ept.large_original[i];
                ept.split_owner[i] = unused_split;
            }
    invalidate();
}

bool begin_ept_window(vcpu_ept_data& ept, uint64_t id) {
    const auto index = hook_index(ept, id);
    if (index == blook::max_hooks)
        return false;
    auto& hook = ept.hooks[index];
    auto pte = get_ept_pte(ept, hook.spec.pfn << 12);
    if (!pte)
        return false;
    ++ept.window_depth[index];
    // The mapping is applied on every open, including nested ones. Treating a
    // repeated open as a no-op is not safe: an MTF rearm (or any other view
    // change) can have moved the page back to "patched" in the meantime, and
    // the caller is about to execute that page to reach the original code.
    // With a stale patch in place the call lands on the hook again and the
    // handler re-enters itself without bound.
    map(*pte, blook::select_view(blook::ept_view::window_execute, hook.spec.pfn,
                                 hook.shadow_pfn));
    invalidate();
    return true;
}

bool end_ept_window(vcpu_ept_data& ept, uint64_t id) {
    const auto index = hook_index(ept, id);
    if (index == blook::max_hooks || !ept.window_depth[index])
        return false;
    if (--ept.window_depth[index])
        return true;
    // The window is closed: trap the page again, so the next execution runs the
    // owner check instead of leaving a patched page visible.
    const auto pfn = ept.hooks[index].spec.pfn;
    if (auto pte = get_ept_pte(ept, pfn << 12))
        map(*pte, blook::select_view(blook::ept_view::original_data, pfn,
                                     ept.hooks[index].shadow_pfn));
    invalidate();
    return true;
}

void handle_page_access(vcpu_ept_data& ept, uint64_t physical, bool execute,
                        uint64_t guest_rip) {
    const auto pfn = physical >> 12;
    auto pte = get_ept_pte(ept, physical);
    if (!pte || !page_hooked(ept, pfn))
        fatal_root_error();
    if (execute) {
        // An open call-original window keeps the page unpatched until the
        // handler closes it.
        if (window_open(ept, pfn)) {
            map(*pte,
                blook::select_view(blook::ept_view::window_execute, pfn, 0));
            invalidate();
            return;
        }
        for (size_t index = 0; index < blook::max_hooks; ++index) {
            const auto& hook = ept.hooks[index];
            if (!hook.active || hook.spec.pfn != pfn)
                continue;
            uint64_t identity = 0;
            if (hook.spec.domain == blook::hook_domain::user)
                identity =
                    platform::translate_user(platform::guest_cr3(),
                                            hook.spec.identity_address) >> 12;
            if (!blook::same_owner(hook.spec, identity))
                continue;
            // A fetch inside the patched bytes that is not exactly the hook
            // target is an internal entry (code jumping past the prologue, a
            // retry label, ...). The shadow is a jump there, so hand out the
            // untouched page for that case instead - the same thing
            // momo5502/hypervisor gets by keeping its fake page a faithful copy
            // and only ever entering the patch at offset zero.
            const auto target = hook.spec.target;
            if (guest_rip != ~0ull && guest_rip > target &&
                guest_rip < target + hook.spec.length) {
                continue;
            }
            // Everything else on the page gets the patched copy, which is
            // byte-identical outside the patched range. Re-sync it first: a
            // page the guest hot-patched after the hook was installed must not
            // execute stale bytes here.
            copy_shadow(ept, index);
            map(*pte, blook::select_view(blook::ept_view::shadow_execute, pfn,
                                         hook.shadow_pfn));
            invalidate();
            return;
        }
        // No hook owns this address space, or the fetch is an internal entry
        // into the bytes a hook patched: run the untouched code - but only for
        // the instruction that is about to execute. Leaving the page unpatched
        // until some unrelated event re-armed it silently disabled the hook for
        // every later execution on this processor; that is what made ~20% of a
        // user-mode hook call return the original value. The monitor trap flag
        // makes the very next vm-exit re-arm the page (rearm_ept maps the armed
        // view again), so exactly one instruction runs unpatched.
        map(*pte, blook::select_view(blook::ept_view::original_step, pfn, 0));
        if (ept.temporary_count < blook::max_hooks) {
            bool known = false;
            for (size_t i = 0; i < ept.temporary_count; ++i)
                if (ept.temporary[i] == pte) known = true;
            if (!known) {
                ept.temporary[ept.temporary_count++] = pte;
                platform::single_step(true);
            }
        }
        invalidate();
        return;
    }
    // Data access on a hooked page always gets the untouched original with
    // read/write and *no* execute, and it stays that way until the next event
    // that re-arms the page (a CR3 write for process-specific views, a hook
    // refresh, or the next violation). This mirrors momo5502/hypervisor, whose
    // hooked pages only ever expose two stable views: execute -> the patched
    // copy, anything else -> the original without execute. Handing out an
    // execute-capable original for one instruction and re-arming afterwards
    // (monitor trap flag) is what made an in-flight instruction stream able to
    // land on the patched entry bytes without being a function entry.
    map(*pte, blook::select_view(blook::ept_view::original_data, pfn, 0));
    invalidate();
}
}  // namespace hv
