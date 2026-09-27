#include "platform_mock.hpp"

#include <cstring>
#include <stdexcept>

#include "driver/hv/ept_platform.hpp"
#include "driver/hv/stats.h"

namespace ept_test {
PlatformMock& platform() {
    static PlatformMock state;
    return state;
}
void PlatformMock::Reset() {
    *this = PlatformMock{};
    memory_types.default_type = 6;
    hv::g_stats = {};
    for (auto& row : hv::g_hook_diag)
        row = {};
}
void PlatformMock::MapUser(uint64_t cr3, uint64_t address,
                           uint64_t physical_address) {
    translations[{cr3, address >> 12}] = physical_address & ~uint64_t{0xfff};
}
void PlatformMock::MapPhysical(uint64_t physical_address,
                               const uint8_t* bytes) {
    physical_pages[physical_address & ~uint64_t{0xfff}] = bytes;
}
}  // namespace ept_test

namespace hv {
[[noreturn]] void fatal_root_error() {
    throw std::runtime_error("unexpected EPT fatal");
}
mtrr_data read_mtrr_data() {
    return ept_test::platform().memory_types;
}
}  // namespace hv
namespace hv::platform {
uint64_t physical_address(const void* pointer) {
    auto& mock = ept_test::platform();
    auto [entry, inserted] =
        mock.physical.try_emplace(pointer, mock.next_physical);
    if (inserted)
        mock.next_physical += 4096;
    return entry->second;
}
void invalidate() {
    ++ept_test::platform().invalidations;
}
void single_step(bool enabled) {
    ept_test::platform().mtf = enabled;
}
uint64_t guest_cr3() {
    return ept_test::platform().current_cr3;
}
uint64_t translate_user(uint64_t cr3, uint64_t address) {
    const auto& mappings = ept_test::platform().translations;
    const auto found = mappings.find({cr3, address >> 12});
    if (found != mappings.end())
        return found->second ? found->second | (address & 0xfff) : 0;
    return cr3 == 1 ? 100ull << 12 : cr3 == 2 ? 200ull << 12 : 0;
}
void copy_from_physical(void* destination, uint64_t physical, size_t size) {
    const auto& pages = ept_test::platform().physical_pages;
    const auto found = pages.find(physical & ~uint64_t{0xfff});
    if (found != pages.end())
        std::memcpy(destination, found->second + (physical & 0xfff), size);
}
}  // namespace hv::platform
