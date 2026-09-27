#include "fixture.hpp"

namespace ept_test {
using namespace hv;
class JitTest : public EptTest {
   protected:
    void SetUp() override {
        EptTest::SetUp();
        ASSERT_FALSE(HasFatalFailure());
        original.fill(0);
        original[0x10] = 0x11;
        jit = Hook(501, 0x900, 0x400040);
        jit.identity_address = 0x500000;
        jit.patch[0] = 0xaa;
        ASSERT_TRUE(install_ept_hook(*cpu, jit));
        pte = get_ept_pte(*cpu, jit.pfn << 12);
        ASSERT_NE(pte, nullptr);
    }
    blook::hook_spec jit{};
    ept_pte* pte{};
};

TEST_F(JitTest, InstallsPatchAtTargetOffsetRatherThanPageStart) {
    EXPECT_TRUE(cpu->hooks[0].active);
    EXPECT_EQ(cpu->hooks[0].group, 0u);
    EXPECT_EQ(cpu->shadow[0][0x40], 0xaa);
    EXPECT_EQ(cpu->shadow[0][0x10], 0x11);
    EXPECT_EQ(pte->flags & 7, 3u);
}

TEST_F(JitTest, ExecuteFaultRefreshesInPlaceRewriteAndReappliesPatch) {
    original[0x10] = 0x33;
    original[0x20] = 0x44;
    handle_page_access(*cpu, jit.pfn << 12, true, jit.target);
    EXPECT_EQ(pte->flags & 7, 4u);
    EXPECT_EQ(pte->page_frame_number, ShadowPfn());
    EXPECT_EQ(cpu->shadow[0][0x40], 0xaa);
    EXPECT_EQ(cpu->shadow[0][0x10], 0x33);
    EXPECT_EQ(cpu->shadow[0][0x20], 0x44);
    original[0x40] = 0x90;
    handle_page_access(*cpu, jit.pfn << 12, true, jit.target);
    EXPECT_EQ(cpu->shadow[0][0x40], 0xaa);
}

TEST_F(JitTest, DataWriteThenExecuteResyncsWithoutSingleStep) {
    handle_page_access(*cpu, jit.pfn << 12, true, jit.target);
    handle_page_access(*cpu, jit.pfn << 12, false);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(pte->flags & 7, 3u);
    EXPECT_EQ(pte->page_frame_number, jit.pfn);
    original[0x50] = 0x77;
    handle_page_access(*cpu, jit.pfn << 12, true, jit.target);
    EXPECT_EQ(pte->flags & 7, 4u);
    EXPECT_EQ(cpu->shadow[0][0x50], 0x77);
    EXPECT_EQ(cpu->shadow[0][0x40], 0xaa);
}

TEST_F(JitTest, ExplicitRefreshResyncsQuiescedOriginal) {
    original[0x60] = 0x88;
    refresh_ept_hook(*cpu, jit.id);
    EXPECT_EQ(cpu->shadow[0][0x60], 0x88);
    EXPECT_EQ(cpu->shadow[0][0x40], 0xaa);
}

TEST_F(JitTest, CopyOnWriteNeedsRemoveAndReinstallOnNewPhysicalPage) {
    auto* stale = get_ept_pte(*cpu, 0x901ull << 12);
    ASSERT_NE(stale, nullptr);
    EXPECT_EQ(stale->page_frame_number, 0x901u);
    EXPECT_EQ(stale->flags & 7, 7u);
    EXPECT_TRUE(cpu->hooks[0].active);
    EXPECT_EQ(cpu->hooks[0].spec.pfn, jit.pfn);
    auto copied = original;
    copied[0x10] = 0x55;
    auto rebound = jit;
    rebound.pfn = 0x901;
    rebound.original = copied.data();
    remove_ept_hook(*cpu, jit.id);
    ASSERT_TRUE(install_ept_hook(*cpu, rebound));
    EXPECT_TRUE(cpu->hooks[0].active);
    EXPECT_EQ(cpu->hooks[0].spec.pfn, 0x901u);
    // Reacquire after split reclamation; do not assume the old slot is reused.
    auto* rebound_pte = get_ept_pte(*cpu, rebound.pfn << 12);
    ASSERT_NE(rebound_pte, nullptr);
    handle_page_access(*cpu, rebound.pfn << 12, true, jit.target);
    EXPECT_EQ(rebound_pte->flags & 7, 4u);
    EXPECT_EQ(rebound_pte->page_frame_number, ShadowPfn());
    EXPECT_EQ(cpu->shadow[0][0x40], 0xaa);
    EXPECT_EQ(cpu->shadow[0][0x10], 0x55);
    remove_ept_hook(*cpu, rebound.id);
    EXPECT_EQ(get_ept_pte(*cpu, rebound.pfn << 12), nullptr);
}
}  // namespace ept_test
