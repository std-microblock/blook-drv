#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <unordered_map>
#include <utility>

#include "driver/hv/mtrr.h"

namespace ept_test {
// Independent of GoogleTest. One process-local platform; tests using it must
// run serially within a process (GoogleTest's normal execution model).
struct PlatformMock {
    uint64_t current_cr3{1};
    uint64_t next_physical{0x1000000};
    unsigned invalidations{};
    bool mtf{};
    hv::mtrr_data memory_types{};
    std::unordered_map<const void*, uint64_t> physical;
    std::map<std::pair<uint64_t, uint64_t>, uint64_t> translations;
    std::unordered_map<uint64_t, const uint8_t*> physical_pages;

    // Reset also clears production diagnostics, not merely the platform maps.
    void Reset();
    // Explicit mappings override the legacy identity fallback, including zero
    // (unmapped). Full CR3 and VA page values are retained without packed keys.
    void MapUser(uint64_t cr3, uint64_t address, uint64_t physical_address);
    // Backing storage is borrowed and must remain alive until use completes.
    void MapPhysical(uint64_t physical_address, const uint8_t* bytes);
};
PlatformMock& platform();
}  // namespace ept_test
