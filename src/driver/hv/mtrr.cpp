#include "mtrr.h"
#include "arch.h"
namespace hv {
mtrr_data read_mtrr_data() {
    mtrr_data result{};
    auto def = __readmsr(IA32_MTRR_DEF_TYPE);
    if (!(def & (1ull << 11))) return result;
    result.default_type = static_cast<uint8_t>(def);
    auto cap = __readmsr(IA32_MTRR_CAPABILITIES);
    result.fixed = (cap & (1ull << 8)) && (def & (1ull << 10));
    if (result.fixed) {
        constexpr uint32_t msrs[] = {0x250,0x258,0x259,0x268,0x269,0x26a,0x26b,0x26c,0x26d,0x26e,0x26f};
        uint64_t base{};
        for (unsigned i = 0; i < 11; ++i) {
            auto value = __readmsr(msrs[i]);
            auto size = i == 0 ? 0x10000ull : i < 3 ? 0x4000ull : 0x1000ull;
            for (unsigned j = 0; j < 8; ++j, base += size)
                result.ranges[result.count++] = {base, base + size, static_cast<uint8_t>(value >> (j * 8))};
        }
    }
    int regs[4]; __cpuid(regs, 0x80000008);
    auto mask = ((1ull << (regs[0] & 0xff)) - 1) & ~0xfffull;
    for (unsigned i = 0; i < (cap & 0xff); ++i) {
        auto range_mask = __readmsr(0x201 + i * 2);
        if (!(range_mask & 0x800)) continue;
        auto base = __readmsr(0x200 + i * 2);
        auto size = ((~range_mask) & mask) + 0x1000;
        auto begin = base & mask;
        result.ranges[result.count++] = {begin, begin + size, static_cast<uint8_t>(base)};
    }
    return result;
}
}
