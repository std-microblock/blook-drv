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
void test_ept_engine() {
    using namespace hv;
    memory_types.default_type = 6;
    auto cpu = std::make_unique<vcpu_ept_data>();
    require(prepare_ept(*cpu));
    uint8_t original[4096]{};
    original[1] = 7;
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
    require(cpu->shadow[0][0] == 42 && cpu->shadow[0][1] == 7 &&
            original[0] == 0);
    handle_page_access(*cpu, a.pfn << 12, true);
    require(pte->page_frame_number == cpu->hooks[0].shadow_pfn &&
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
    auto b = a;
    b.id = 2;
    b.address_space = 200;
    b.patch[0] = 99;
    require(install_ept_hook(*cpu, b));
    current_cr3 = 2;
    reset_ept_context(*cpu);
    handle_page_access(*cpu, a.pfn << 12, true);
    require(pte->page_frame_number == cpu->hooks[1].shadow_pfn &&
            cpu->shadow[1][0] == 99);
    require(!install_ept_hook(*cpu, b));
    original[1] = 9;
    refresh_ept_hook(*cpu, 2);
    require(cpu->shadow[1][0] == 99 && cpu->shadow[1][1] == 9);
    remove_ept_hook(*cpu, 1);
    require((pte->flags & 7) == 3 && pte->page_frame_number == a.pfn);
    remove_ept_hook(*cpu, 2);
    require(get_ept_pte(*cpu, a.pfn << 12) == nullptr);
    // Hundreds of install/remove cycles in different regions must recycle split
    // slots.
    for (unsigned i = 0; i < 320; ++i) {
        a.id = i + 3;
        a.pfn = 0x1000ull + (uint64_t{i} << 9);
        require(install_ept_hook(*cpu, a));
        remove_ept_hook(*cpu, a.id);
    }
    auto second_cpu = std::make_unique<vcpu_ept_data>();
    require(prepare_ept(*second_cpu));
    a.id = 400;
    a.pfn = 0x500;
    require(install_ept_hook(*cpu, a) && install_ept_hook(*second_cpu, a));
    require(cpu->hooks[0].shadow_pfn != second_cpu->hooks[0].shadow_pfn);
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
