#include "ept/fixture.hpp"

namespace ept_test {
TEST_F(EptTest, SplitPoolExhaustionDoesNotPublishPartialHook) {
    // Reserve all split tables through the real allocator, not fake metadata.
    for (size_t i = 0; i < hv::ept_split_count; ++i)
        ASSERT_NE(hv::get_ept_pte(*cpu, uint64_t{i} << 21, true), nullptr) << i;
    auto hook = Hook();
    hook.pfn = uint64_t{hv::ept_split_count} << 9;
    EXPECT_FALSE(hv::install_ept_hook(*cpu, hook));
    EXPECT_FALSE(cpu->hooks[0].active);
    EXPECT_FALSE(cpu->groups[0].active);
    EXPECT_EQ(hv::get_ept_pte(*cpu, hook.pfn << 12), nullptr);
    // Exhaustion must not prevent joining a region that already has a table.
    hook.pfn = 0x400;
    EXPECT_TRUE(hv::install_ept_hook(*cpu, hook));
}

TEST_F(EptTest, RemovingOnePageDoesNotReclaimSplitNeededByNeighbour) {
    auto a = Hook();
    auto b = Hook(2, a.pfn + 1, a.target + 4096);
    ASSERT_TRUE(hv::install_ept_hook(*cpu, a));
    ASSERT_TRUE(hv::install_ept_hook(*cpu, b));
    hv::remove_ept_hook(*cpu, a.id);
    auto* pte = hv::get_ept_pte(*cpu, a.pfn << 12);
    ASSERT_NE(pte, nullptr);
    EXPECT_EQ(pte->flags & 7, 7u);
    hv::handle_page_access(*cpu, b.pfn << 12, true, b.target);
    EXPECT_EQ(hv::get_ept_pte(*cpu, b.pfn << 12)->page_frame_number,
              ShadowPfn(1));
    hv::remove_ept_hook(*cpu, b.id);
    EXPECT_EQ(hv::get_ept_pte(*cpu, a.pfn << 12), nullptr);
}

TEST_F(EptTest, RefreshInNestedWindowKeepsLatestOriginalExecutable) {
    auto hook = Hook();
    ASSERT_TRUE(hv::install_ept_hook(*cpu, hook));
    ASSERT_TRUE(hv::begin_ept_window(*cpu, hook.id));
    ASSERT_TRUE(hv::begin_ept_window(*cpu, hook.id));
    original[99] = 0xcd;
    hv::refresh_ept_hook(*cpu, hook.id);
    auto* pte = hv::get_ept_pte(*cpu, hook.pfn << 12);
    ASSERT_NE(pte, nullptr);
    EXPECT_EQ(pte->page_frame_number, hook.pfn);
    EXPECT_EQ(pte->flags & 7, 7u);
    EXPECT_EQ(cpu->shadow[cpu->hooks[0].group][99], 0xcd);
    ASSERT_TRUE(hv::end_ept_window(*cpu, hook.id));
    EXPECT_EQ(pte->flags & 7, 7u);
    ASSERT_TRUE(hv::end_ept_window(*cpu, hook.id));
    EXPECT_EQ(pte->flags & 7, 3u);
    hv::handle_page_access(*cpu, hook.pfn << 12, true, hook.target);
    EXPECT_EQ(pte->page_frame_number, ShadowPfn());
}

TEST_F(EptTest, ContextSwitchDuringOriginalStepRearmsBeforeNewOwnerExecutes) {
    auto hook = Hook();
    ASSERT_TRUE(hv::install_ept_hook(*cpu, hook));
    platform().current_cr3 = 2;
    hv::handle_page_access(*cpu, hook.pfn << 12, true, hook.target);
    ASSERT_TRUE(platform().mtf);
    platform().current_cr3 = 1;
    hv::reset_ept_context(*cpu);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(cpu->temporary_count, 0u);
    hv::handle_page_access(*cpu, hook.pfn << 12, true, hook.target);
    EXPECT_EQ(hv::get_ept_pte(*cpu, hook.pfn << 12)->page_frame_number,
              ShadowPfn());
}
}  // namespace ept_test
