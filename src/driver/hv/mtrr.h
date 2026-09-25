#pragma once
#include "policy/integer.hpp"
namespace hv {
struct memory_range { uint64_t begin{}, end{}; uint8_t type{}; };
struct mtrr_data {
    memory_range ranges[344]{};
    unsigned count{};
    uint8_t default_type{};
    bool fixed{};
};
mtrr_data read_mtrr_data();
uint8_t calc_mtrr_mem_type(const mtrr_data&, uint64_t address, uint64_t size);
}
