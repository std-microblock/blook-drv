#include "fixture.hpp"

namespace ept_test {
TEST_F(EptTest, MtrrWriteThroughOverridesOverlappingWriteBackAt4KiB) {
    hv::mtrr_data types{};
    types.default_type = 6;
    types.count = 2;
    types.ranges[0] = {0, 0x400000, 6};
    types.ranges[1] = {0x100000, 0x200000, 4};
    EXPECT_EQ(hv::calc_mtrr_mem_type(types, 0x100000, 4096), 4);
}

TEST_F(EptTest, MtrrUncacheableOverridesOverlappingWriteBackAt4KiB) {
    hv::mtrr_data types{};
    types.default_type = 6;
    types.count = 2;
    types.ranges[0] = {0, 0x400000, 6};
    types.ranges[1] = {0x100000, 0x200000, 0};
    EXPECT_EQ(hv::calc_mtrr_mem_type(types, 0x100000, 4096), 0);
}

TEST_F(EptTest, MtrrUncoveredAddressUsesDefaultMemoryType) {
    hv::mtrr_data types{};
    types.default_type = 6;
    types.count = 2;
    types.ranges[0] = {0, 0x400000, 6};
    types.ranges[1] = {0x100000, 0x200000, 0};
    EXPECT_EQ(hv::calc_mtrr_mem_type(types, 0x800000, 4096), 6);
}
}  // namespace ept_test
