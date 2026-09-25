#include "mtrr.h"
namespace hv {
uint8_t calc_mtrr_mem_type(const mtrr_data& data, uint64_t address, uint64_t size) {
    uint8_t type = 0xff;
    for (unsigned i = 0; i < data.count; ++i) {
        auto const& r = data.ranges[i];
        if (address >= r.end || address + size <= r.begin) continue;
        // A large mapping crossing a cache-type boundary is conservatively UC.
        if (address < r.begin || address + size > r.end) return 0;
        if (data.fixed && address < 0x100000 && i < 88) return r.type;
        if (r.type == 0) return 0;
        if (type == 0xff || type == r.type) type = r.type;
        else if ((type == 6 && r.type == 4) || (type == 4 && r.type == 6)) type = 4;
        else return 0; // Undefined overlap: do not invent a cache policy.
    }
    return type == 0xff ? data.default_type : type;
}
}
