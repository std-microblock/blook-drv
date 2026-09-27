#include "driver/hv/ept_platform.hpp"
#include "fixture.hpp"

namespace ept_test {
TEST_F(EptTest, PlatformResetClearsAllProcessGlobalState) {
    auto& mock = platform();
    mock.current_cr3 = 0x123456789;
    mock.invalidations = 9;
    mock.mtf = true;
    mock.memory_types.count = 1;
    mock.memory_types.default_type = 0;
    mock.MapUser(1, 0x400000, 0x500000);
    mock.MapPhysical(0x500000, original.data());
    hv::g_stats.watch_dumps = 8;
    hv::g_stats.exit_reasons[1] = 3;
    hv::g_hook_diag[0].active = 1;
    hv::g_hook_diag[0].shadow_mapped = 4;
    ASSERT_FALSE(mock.physical.empty());  // prepare_ept populated this map.
    mock.Reset();
    EXPECT_EQ(mock.current_cr3, 1u);
    EXPECT_EQ(mock.next_physical, 0x1000000u);
    EXPECT_EQ(mock.invalidations, 0u);
    EXPECT_FALSE(mock.mtf);
    EXPECT_EQ(mock.memory_types.count, 0u);
    EXPECT_EQ(mock.memory_types.default_type, 6);
    EXPECT_TRUE(mock.physical.empty());
    EXPECT_TRUE(mock.translations.empty());
    EXPECT_TRUE(mock.physical_pages.empty());
    EXPECT_EQ(hv::g_stats.watch_dumps, 0);
    EXPECT_EQ(hv::g_stats.exit_reasons[1], 0);
    EXPECT_EQ(hv::g_hook_diag[0].active, 0);
    EXPECT_EQ(hv::g_hook_diag[0].shadow_mapped, 0);
}

TEST_F(EptTest, PlatformTranslationsKeepFullCr3AndVirtualPageKeys) {
    // These CR3 values collided in the legacy (cr3 << 48) packed key.
    platform().MapUser(1, 0x400000, 0x500000);
    platform().MapUser(0x10001, 0x400000, 0x600000);
    EXPECT_EQ(hv::platform::translate_user(1, 0x400123), 0x500123u);
    EXPECT_EQ(hv::platform::translate_user(0x10001, 0x400123), 0x600123u);
    // An explicit absent page suppresses the CR3-1 identity fallback even for
    // an unaligned address; zero must not become a nonzero offset-only PA.
    platform().MapUser(1, 0x700000, 0);
    EXPECT_EQ(hv::platform::translate_user(1, 0x700123), 0u);
}
}  // namespace ept_test
