#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include "driver/hv/ept.h"
#include "driver/hv/ept_platform.hpp"
#include "driver/hv/mtrr.h"
namespace {
uint64_t current_cr3{1}, next_physical{0x1000000};
unsigned invalidations{};
bool mtf{};
std::unordered_map<const void*, uint64_t> physical;
hv::mtrr_data memory_types{};
void require_impl(bool ok, int line) {
    if (!ok) {
        std::printf("FAIL: check at line %d\n", line);
        std::fflush(stdout);
        std::_Exit(1);
    }
}
#define require(x) require_impl((x), __LINE__)
}  // namespace
namespace hv {
[[noreturn]] void fatal_root_error() {
    throw std::runtime_error("unexpected EPT fatal");
}
mtrr_data read_mtrr_data() {
    return memory_types;
}
}  // namespace hv
namespace hv::platform {
uint64_t physical_address(const void* p) {
    auto [i, inserted] = physical.try_emplace(p, next_physical);
    if (inserted)
        next_physical += 4096;
    return i->second;
}
void invalidate() {
    ++invalidations;
}
void single_step(bool enabled) {
    mtf = enabled;
}
uint64_t guest_cr3() {
    return current_cr3;
}
uint64_t translate_user(uint64_t cr3, uint64_t) {
    return cr3 == 1 ? 100ull << 12 : cr3 == 2 ? 200ull << 12 : 0;
}
}  // namespace hv::platform

namespace {
// Shadow page of the group the given hook joined.
uint32_t shadow_pfn_of(const hv::vcpu_ept_data& cpu, size_t hook) {
    return cpu.groups[cpu.hooks[hook].group].shadow_pfn;
}
}  // namespace

void test_ept_engine() {
    using namespace hv;
    memory_types.default_type = 6;
    auto cpu = std::make_unique<vcpu_ept_data>();
    require(prepare_ept(*cpu));
    uint8_t original[4096]{};
    original[1] = 7;
    original[0x11] = 3;
    // Owner-process user hook: one group, one shadow, armed page.
    blook::hook_spec a{};
    a.id = 1;
    a.pfn = 0x400;
    a.target = 0x100000;
    a.address_space = 100;
    a.identity_address = 0x200000;
    a.original = original;
    a.length = 1;
    a.patch[0] = 42;
    a.domain = blook::hook_domain::user;
    require(install_ept_hook(*cpu, a));
    auto pte = get_ept_pte(*cpu, a.pfn << 12);
    require(pte && pte->page_frame_number == a.pfn && (pte->flags & 7) == 3);
    require(cpu->hooks[0].active && cpu->hooks[0].group == 0);
    require(cpu->groups[0].active && cpu->groups[0].pfn == a.pfn &&
            cpu->groups[0].domain == blook::hook_domain::user &&
            cpu->groups[0].address_space == 100);
    require(cpu->shadow[0][0] == 42 && cpu->shadow[0][1] == 7 &&
            original[0] == 0);
    handle_page_access(*cpu, a.pfn << 12, true);
    require(pte->page_frame_number == shadow_pfn_of(*cpu, 0) &&
            (pte->flags & 7) == 4);
    handle_page_access(*cpu, a.pfn << 12, false);
    // Data access hands out the untouched original read/write and *without*
    // execute, and does not single-step any more: the two stable views are
    // execute -> patched copy, anything else -> original without execute.
    require(!mtf && pte->page_frame_number == a.pfn && (pte->flags & 7) == 3);
    rearm_ept(*cpu);
    require(!mtf && (pte->flags & 7) == 3);
    current_cr3 = 3;
    reset_ept_context(*cpu);
    handle_page_access(*cpu, a.pfn << 12, true);
    require(pte->page_frame_number == a.pfn && (pte->flags & 7) == 7);

    // A second hook in the SAME process on the SAME page merges into the
    // group: one shadow carries both patches.
    auto mate = a;
    mate.id = 2;
    mate.target = 0x100010;
    mate.length = 2;
    mate.patch[0] = 11;
    mate.patch[1] = 22;
    require(install_ept_hook(*cpu, mate));
    require(cpu->hooks[1].active && cpu->hooks[1].group == 0);
    require(cpu->shadow[0][0] == 42 && cpu->shadow[0][0x10] == 11 &&
            cpu->shadow[0][0x11] == 22);
    current_cr3 = 1;
    reset_ept_context(*cpu);
    handle_page_access(*cpu, a.pfn << 12, true);
    require(pte->page_frame_number == shadow_pfn_of(*cpu, 0) &&
            (pte->flags & 7) == 4);
    // A fetch inside the second patch's range that is not its entry is an
    // internal entry: exactly one original instruction, then re-arm.
    handle_page_access(*cpu, a.pfn << 12, true, 0x100011);
    require(pte->page_frame_number == a.pfn && (pte->flags & 7) == 7 && mtf);
    rearm_ept(*cpu);
    require(!mtf && (pte->flags & 7) == 3);

    // Covered ranges that overlap - in any direction - are refused.
    auto overlap = a;
    overlap.id = 3;
    overlap.length = 1;
    require(!install_ept_hook(*cpu, overlap));
    auto overlap_mate = mate;
    overlap_mate.id = 4;
    overlap_mate.target = 0x100011;
    overlap_mate.length = 1;
    require(!install_ept_hook(*cpu, overlap_mate));
    // The same id is still one hook.
    require(!install_ept_hook(*cpu, mate));

    // Refreshing one member re-syncs the whole group: the current original
    // bytes come back, every member patch is re-applied.
    original[2] = 0x5a;
    refresh_ept_hook(*cpu, 1);
    require(cpu->shadow[0][0] == 42 && cpu->shadow[0][2] == 0x5a &&
            cpu->shadow[0][0x10] == 11 && cpu->shadow[0][0x11] == 22);

    // Dropping one member rebuilds the shadow without its patch and keeps
    // the page armed for the survivor.
    remove_ept_hook(*cpu, 2);
    require(cpu->hooks[0].active && !cpu->hooks[1].active);
    require(cpu->shadow[0][0] == 42 && cpu->shadow[0][0x10] == 0);
    require((pte->flags & 7) == 3 && pte->page_frame_number == a.pfn);

    // Another process sharing the physical page gets its own group and its
    // own shadow; the two owners never see each other's patch.
    auto other = a;
    other.id = 5;
    other.address_space = 200;
    other.identity_address = 0x300000;
    other.patch[0] = 99;
    require(install_ept_hook(*cpu, other));
    // The freed slot from id 2 is reused, so the second process lands in
    // slot 1 with its own group.
    require(cpu->hooks[1].group == 1 && cpu->groups[1].active &&
            cpu->groups[1].address_space == 200);
    current_cr3 = 2;
    reset_ept_context(*cpu);
    handle_page_access(*cpu, a.pfn << 12, true);
    require(pte->page_frame_number == shadow_pfn_of(*cpu, 1) &&
            cpu->shadow[1][0] == 99 && cpu->shadow[1][0x10] == 0);

    // A kernel (global) hook never joins a page that already carries a
    // per-process hook.
    auto kernel = a;
    kernel.id = 6;
    kernel.domain = blook::hook_domain::kernel;
    kernel.address_space = 0;
    kernel.identity_address = 0;
    require(!install_ept_hook(*cpu, kernel));

    // ... but kernel hooks merge with each other on one page - the layout
    // hide::nt lives with, where several services share a 4 KiB page. The
    // page is 0x800 so the kernel group lives in its own 2-MiB region: the
    // user groups on 0x400 keep that region's split alive until they go.
    kernel.pfn = 0x800;
    kernel.target = 0x800000;
    kernel.length = 1;
    kernel.patch[0] = 0x66;
    auto kernel_mate = kernel;
    kernel_mate.id = 7;
    kernel_mate.target = 0x800020;
    kernel_mate.patch[0] = 0x77;
    require(install_ept_hook(*cpu, kernel));
    require(install_ept_hook(*cpu, kernel_mate));
    // Slot 2 carries id 6, slot 3 carries id 7, both in the same group.
    require(cpu->hooks[2].group == cpu->hooks[3].group);
    auto kernel_pte = get_ept_pte(*cpu, kernel.pfn << 12);
    handle_page_access(*cpu, kernel.pfn << 12, true);
    require(kernel_pte->page_frame_number ==
            cpu->groups[cpu->hooks[2].group].shadow_pfn);
    require(cpu->shadow[cpu->hooks[2].group][0] == 0x66 &&
            cpu->shadow[cpu->hooks[2].group][0x20] == 0x77);
    auto kernel_overlap = kernel;
    kernel_overlap.id = 8;
    kernel_overlap.target = 0x500000;  // exactly the range id 6 covers
    require(!install_ept_hook(*cpu, kernel_overlap));
    remove_ept_hook(*cpu, 6);
    require((kernel_pte->flags & 7) == 3 &&
            kernel_pte->page_frame_number == kernel.pfn);
    // With id 6 gone the range is free again and the group accepts a new
    // member whose patch is then part of the shared shadow. The replacement
    // ends up in the freed slot 2.
    require(install_ept_hook(*cpu, kernel_overlap));
    require(cpu->hooks[2].group == cpu->hooks[3].group);
    require(cpu->shadow[cpu->hooks[2].group][0] == 0x66);
    remove_ept_hook(*cpu, kernel_overlap.id);
    remove_ept_hook(*cpu, 7);
    require(get_ept_pte(*cpu, kernel.pfn << 12) == nullptr);

    // Tearing the page down: the last group of the 2-MiB range restores the
    // large leaf.
    remove_ept_hook(*cpu, 1);
    require((pte->flags & 7) == 3 && pte->page_frame_number == a.pfn);
    remove_ept_hook(*cpu, 5);
    require(get_ept_pte(*cpu, a.pfn << 12) == nullptr);
    // Hundreds of install/remove cycles in different regions must recycle
    // split slots.
    for (unsigned i = 0; i < 320; ++i) {
        a.id = i + 20;
        a.pfn = 0x1000ull + (uint64_t{i} << 9);
        require(install_ept_hook(*cpu, a));
        remove_ept_hook(*cpu, a.id);
    }
    auto second_cpu = std::make_unique<vcpu_ept_data>();
    require(prepare_ept(*second_cpu));
    a.id = 400;
    a.pfn = 0x600;
    require(install_ept_hook(*cpu, a) && install_ept_hook(*second_cpu, a));
    require(shadow_pfn_of(*cpu, 0) != shadow_pfn_of(*second_cpu, 0));
    auto bad = a;
    bad.id++;
    bad.target = 0x1fffff;
    bad.length = 2;
    require(!install_ept_hook(*cpu, bad));
    // MTRR overlaps and fixed 4-KiB boundaries use the same production policy.
    mtrr_data types{};
    types.default_type = 6;
    types.count = 2;
    types.ranges[0] = {0, 0x400000, 6};
    types.ranges[1] = {0x100000, 0x200000, 4};
    require(calc_mtrr_mem_type(types, 0x100000, 4096) == 4);
    types.ranges[1].type = 0;
    require(calc_mtrr_mem_type(types, 0x100000, 4096) == 0);
    require(calc_mtrr_mem_type(types, 0x800000, 4096) == 6);
    require(invalidations > 600);
    std::puts(
        "PASS: production EPT engine with mocked VMX/physical-address "
        "operations");
}
