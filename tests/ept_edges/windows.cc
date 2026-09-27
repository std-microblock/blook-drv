#include "ept/fixture.hpp"

namespace ept_test {
TEST_F(EptTest, SiblingWindowsRemainOriginalUntilLastMemberCloses) {
    auto a = Hook();
    auto b = Hook(2, a.pfn, a.target + 32);
    ASSERT_TRUE(hv::install_ept_hook(*cpu, a));
    ASSERT_TRUE(hv::install_ept_hook(*cpu, b));
    ASSERT_TRUE(hv::begin_ept_window(*cpu, a.id));
    ASSERT_TRUE(hv::begin_ept_window(*cpu, b.id));
    ASSERT_TRUE(hv::end_ept_window(*cpu, a.id));
    hv::reset_ept_context(*cpu);
    hv::handle_page_access(*cpu, b.pfn << 12, true, b.target);
    auto* pte = hv::get_ept_pte(*cpu, b.pfn << 12);
    ASSERT_NE(pte, nullptr);
    EXPECT_EQ(pte->page_frame_number, b.pfn);
    EXPECT_EQ(pte->flags & 7, 7u);
    ASSERT_TRUE(hv::end_ept_window(*cpu, b.id));
    EXPECT_EQ(pte->flags & 7, 3u);
    hv::handle_page_access(*cpu, b.pfn << 12, true, b.target);
    EXPECT_EQ(pte->page_frame_number, ShadowPfn(1));
}

TEST_F(EptTest, RemovingWindowOwnerKeepsSiblingHookArmedAndResetsReusedDepth) {
    auto a = Hook();
    auto b = Hook(2, a.pfn, a.target + 32);
    ASSERT_TRUE(hv::install_ept_hook(*cpu, a));
    ASSERT_TRUE(hv::install_ept_hook(*cpu, b));
    ASSERT_TRUE(hv::begin_ept_window(*cpu, a.id));
    hv::remove_ept_hook(*cpu, a.id);
    EXPECT_EQ(cpu->window_depth[0], 0u);
    EXPECT_FALSE(hv::end_ept_window(*cpu, a.id));
    hv::handle_page_access(*cpu, b.pfn << 12, true, b.target);
    EXPECT_EQ(hv::get_ept_pte(*cpu, b.pfn << 12)->page_frame_number,
              ShadowPfn(1));
    a.id = 3;
    ASSERT_TRUE(hv::install_ept_hook(*cpu, a));
    EXPECT_EQ(cpu->window_depth[0], 0u);
    EXPECT_FALSE(hv::end_ept_window(*cpu, a.id));
}

TEST_F(EptTest,
       DataFaultInOriginalWindowReturnsDataViewAndNextFetchStaysOriginal) {
    auto a = Hook();
    ASSERT_TRUE(hv::install_ept_hook(*cpu, a));
    ASSERT_TRUE(hv::begin_ept_window(*cpu, a.id));
    hv::handle_page_access(*cpu, a.pfn << 12, false);
    auto* pte = hv::get_ept_pte(*cpu, a.pfn << 12);
    ASSERT_NE(pte, nullptr);
    EXPECT_EQ(pte->page_frame_number, a.pfn);
    EXPECT_EQ(pte->flags & 7, 3u);
    hv::handle_page_access(*cpu, a.pfn << 12, true, a.target);
    EXPECT_EQ(pte->page_frame_number, a.pfn);
    EXPECT_EQ(pte->flags & 7, 7u);
    EXPECT_FALSE(platform().mtf);
    ASSERT_TRUE(hv::end_ept_window(*cpu, a.id));
    EXPECT_EQ(pte->flags & 7, 3u);
}
}  // namespace ept_test
