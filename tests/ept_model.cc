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
// Mocked guest address spaces for the watch tests: (cr3, VA page) -> physical
// address the dump engine resolves, and physical page -> backing bytes.
// Addresses absent from the first map fall back to the legacy identity PFNs.
std::unordered_map<uint64_t, uint64_t> mock_translate;
std::unordered_map<uint64_t, const uint8_t*> mock_physical;
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
uint64_t translate_user(uint64_t cr3, uint64_t address) {
    const auto key = (cr3 << 48) | ((address >> 12) & 0xfffffffffull);
    if (const auto it = mock_translate.find(key); it != mock_translate.end())
        return it->second | (address & 0xfff);
    return cr3 == 1 ? 100ull << 12 : cr3 == 2 ? 200ull << 12 : 0;
}
void copy_from_physical(void* dst, uint64_t physical, size_t size) {
    const auto it = mock_physical.find(physical & ~0xfffull);
    if (it == mock_physical.end())
        return;  // unmapped: the dump loop pre-zeroed the destination
    std::memcpy(dst, it->second + (physical & 0xfff), size);
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

// JIT-behaviour model. A JIT (or a self-decrypting shell) rewrites the hooked
// page *in place* - the typical VirtualAlloc(PAGE_EXECUTE_READWRITE) buffer,
// where the physical page never changes. The build_shadow re-sync inside
// handle_page_access must fold the new bytes into the shadow while keeping the
// patch on top. The second part pins the documented limitation: when the
// rewrite goes through copy-on-write (VirtualProtect on a shared image page),
// the guest VA moves to a NEW physical page and the hook stays armed on the
// old one. Nothing faults on the new page today; re-arming after a
// protection change is the VirtualProtect-hook follow-up, asserted here as
// the current state so the fix has a failing test to flip.
void test_ept_jit_resync() {
    using namespace hv;
    memory_types = {};
    memory_types.default_type = 6;
    current_cr3 = 1;  // translate_user mock: cr3 1 -> address space 100
    auto cpu = std::make_unique<vcpu_ept_data>();
    require(prepare_ept(*cpu));

    uint8_t page[4096]{};
    page[0x10] = 0x11;
    blook::hook_spec jit{};
    jit.id = 501;
    jit.pfn = 0x900;
    jit.target = 0x400040;
    jit.address_space = 100;
    jit.identity_address = 0x500000;
    jit.original = page;
    jit.length = 1;
    jit.patch[0] = 0xAA;
    jit.domain = blook::hook_domain::user;
    require(install_ept_hook(*cpu, jit));
    require(cpu->hooks[0].active && cpu->hooks[0].group == 0);
    // The patch lands at the in-page offset of the target (0x40 here), not at
    // the start of the shadow page.
    require(cpu->shadow[0][0x40] == 0xAA && cpu->shadow[0][0x10] == 0x11);
    auto* pte = get_ept_pte(*cpu, jit.pfn << 12);
    require(pte && (pte->flags & 7) == 3);

    // 1) In-place rewrite while the hook is armed: the next execute fault
    //    rebuilds the shadow - fresh bytes everywhere, patch still on top.
    page[0x10] = 0x33;
    page[0x20] = 0x44;
    handle_page_access(*cpu, jit.pfn << 12, true, jit.target);
    require((pte->flags & 7) == 4 &&
            pte->page_frame_number == cpu->groups[0].shadow_pfn);
    require(cpu->shadow[0][0x40] == 0xAA && cpu->shadow[0][0x10] == 0x33 &&
            cpu->shadow[0][0x20] == 0x44);

    // A rewrite landing on the patched byte itself loses: the patch is
    // re-applied over whatever the JIT wrote at the entry point.
    page[0x40] = 0x90;
    handle_page_access(*cpu, jit.pfn << 12, true, jit.target);
    require(cpu->shadow[0][0x40] == 0xAA);

    // 2) The write instruction itself faults as a data access: the page flips
    //    to the read/write view without execute, the store lands, and the next
    //    execute fault re-syncs the shadow again.
    handle_page_access(*cpu, jit.pfn << 12, false);
    require(!mtf && (pte->flags & 7) == 3 &&
            pte->page_frame_number == jit.pfn);
    page[0x50] = 0x77;
    handle_page_access(*cpu, jit.pfn << 12, true, jit.target);
    require((pte->flags & 7) == 4 && cpu->shadow[0][0x50] == 0x77 &&
            cpu->shadow[0][0x40] == 0xAA);

    // 3) refresh_ept_hook re-syncs the same way from a caller that quiesced
    //    the target first: new original bytes, patch on top.
    page[0x60] = 0x88;
    refresh_ept_hook(*cpu, jit.id);
    require(cpu->shadow[0][0x60] == 0x88 && cpu->shadow[0][0x40] == 0xAA);

    // 4) Copy-on-write moves the guest VA to a new physical page: until the
    //    driver's VM post-pass (NtProtectVirtualMemory / NtWriteVirtualMemory)
    //    moves the hook, nothing traps the new page - a PTE in the split
    //    region keeps the identity RWX flags the split loop wrote...
    auto* stale = get_ept_pte(*cpu, 0x901ull << 12);
    require(stale && stale->page_frame_number == 0x901 &&
            (stale->flags & 7) == 7);
    require(cpu->hooks[0].active && cpu->hooks[0].spec.pfn == jit.pfn);
    // ... and the rebind itself is a remove + install on the same id with the
    // new backing page: the patch rides the copied bytes and faults again.
    uint8_t copied_page[4096]{};
    std::memcpy(copied_page, page, sizeof(page));
    copied_page[0x10] = 0x55;  // the write that triggered the copy
    auto rebound = jit;
    rebound.pfn = 0x901;
    rebound.original = copied_page;
    remove_ept_hook(*cpu, jit.id);
    require(install_ept_hook(*cpu, rebound));
    require(cpu->hooks[0].active && cpu->hooks[0].spec.pfn == 0x901);
    handle_page_access(*cpu, 0x901ull << 12, true, jit.target);
    require((stale->flags & 7) == 4 &&
            stale->page_frame_number == cpu->groups[0].shadow_pfn);
    require(cpu->shadow[0][0x40] == 0xAA && cpu->shadow[0][0x10] == 0x55);

    remove_ept_hook(*cpu, rebound.id);
    require(get_ept_pte(*cpu, 0x901ull << 12) == nullptr);
    std::puts("PASS: in-place JIT rewrite re-syncs the shadow; "
              "CoW remap followed by the rebind");
}

// Execute watch model (dump-on-execute): the watched page is armed
// not-executable, non-target fetches are single-stepped, and an exact hit
// dumps the configured range out of (mocked) physical memory and disarms
// itself.
void test_ept_watch() {
    using namespace hv;
    memory_types = {};
    memory_types.default_type = 6;
    current_cr3 = 1;
    mock_translate.clear();
    mock_physical.clear();
    auto cpu = std::make_unique<vcpu_ept_data>();
    require(prepare_ept(*cpu));

    blook::watch_spec spec{};
    spec.id = 700;
    spec.pfn = 0x2000;
    spec.target = 0x700080;
    spec.address_space = 100;
    spec.identity_address = 0x900000;
    spec.owner_pid = 1234;

    // Two physical pages behind the dumped range [0x710000, 0x712020).
    static uint8_t source_a[4096]{};
    static uint8_t source_b[4096]{};
    for (size_t i = 0; i < 4096; ++i) {
        source_a[i] = static_cast<uint8_t>(i);
        source_b[i] = static_cast<uint8_t>(i * 7);
    }
    mock_translate[(current_cr3 << 48) | (0x710000 >> 12)] = 0x4700000;
    mock_translate[(current_cr3 << 48) | (0x711000 >> 12)] = 0x4701000;
    mock_physical[0x4700000] = source_a;
    mock_physical[0x4701000] = source_b;
    std::vector<uint8_t> dump(0x2000);
    blook::watch_record record{};
    record.dump_base = 0x710000;
    record.dump_size = 0x1020;
    record.buffer = dump.data();

    // Hooks and watches refuse to share a page, ids and pages are unique.
    require(install_ept_watch(*cpu, spec, &record));
    auto* pte = get_ept_pte(*cpu, spec.pfn << 12);
    require(pte && (pte->flags & 7) == 3 &&
            pte->page_frame_number == spec.pfn);
    require(!install_ept_watch(*cpu, spec, &record));
    auto sibling = spec;
    sibling.id = 701;
    require(!install_ept_watch(*cpu, sibling, &record));
    uint8_t hooked[4096]{};
    blook::hook_spec clash{};
    clash.id = 702;
    clash.pfn = spec.pfn;
    clash.target = 0x700040;
    clash.address_space = 100;
    clash.identity_address = 0x900000;
    clash.original = hooked;
    clash.length = 1;
    clash.patch[0] = 1;
    clash.domain = blook::hook_domain::user;
    require(!install_ept_hook(*cpu, clash));
    // ... and a hook page refuses a watch just the same (0x4000 lives in a
    // different 2-MiB region than the watch, so split accounting is clean).
    clash.pfn = 0x4000;
    require(install_ept_hook(*cpu, clash));
    auto clash_watch = spec;
    clash_watch.id = 703;
    clash_watch.pfn = clash.pfn;
    require(!install_ept_watch(*cpu, clash_watch, &record));

    // A fetch next to the target is not the target: single-stepped on the
    // original, re-armed by the MTF exit.
    handle_page_access(*cpu, spec.pfn << 12, true, spec.target - 4);
    require((pte->flags & 7) == 7 && mtf &&
            record.state == blook::watch_pending);
    rearm_ept(*cpu);
    require(!mtf && (pte->flags & 7) == 3);

    // A different address space never fires (cr3 2 -> identity 200 != 100).
    current_cr3 = 2;
    handle_page_access(*cpu, spec.pfn << 12, true, spec.target);
    require(record.state == blook::watch_pending &&
            cpu->watches[0].active);
    rearm_ept(*cpu);
    require((pte->flags & 7) == 3);
    current_cr3 = 1;

    // The exact hit: range dumped straight out of physical memory (the mock
    // page table above), watch disarmed, page runs free again.
    handle_page_access(*cpu, spec.pfn << 12, true, spec.target);
    require(record.state == blook::watch_hit);
    require(record.hit_rip == spec.target && record.hit_cr3 == current_cr3);
    require(!cpu->watches[0].active);
    require((pte->flags & 7) == 7 &&
            pte->page_frame_number == spec.pfn);
    for (size_t i = 0; i < 4096; ++i)
        require(dump[i] == source_a[i]);
    for (size_t i = 0; i < 0x20; ++i)
        require(dump[4096 + i] == source_b[i]);
    // The whole 2-MiB split went back to a large leaf.
    require(get_ept_pte(*cpu, spec.pfn << 12) == nullptr);
    // ... while the unrelated hook page is still split and armed.
    require(get_ept_pte(*cpu, clash.pfn << 12) != nullptr);
    remove_ept_hook(*cpu, clash.id);
    require(get_ept_pte(*cpu, clash.pfn << 12) == nullptr);
    std::puts("PASS: execute watch dumps from physical memory on hit");
}
