#include "fixture.hpp"

namespace ept_test {
using namespace hv;

TEST_F(EptTest, InstallsOwnerHookIntoArmedGroupAndCopiesOriginal) {
    const auto a = Hook();
    ASSERT_TRUE(install_ept_hook(*cpu, a));
    const auto* pte = get_ept_pte(*cpu, a.pfn << 12);
    ASSERT_NE(pte, nullptr);
    EXPECT_EQ(pte->page_frame_number, a.pfn);
    EXPECT_EQ(pte->flags & 7, 3u);
    EXPECT_TRUE(cpu->hooks[0].active);
    EXPECT_EQ(cpu->hooks[0].group, 0u);
    EXPECT_TRUE(cpu->groups[0].active);
    EXPECT_EQ(cpu->groups[0].pfn, a.pfn);
    EXPECT_EQ(cpu->groups[0].domain, blook::hook_domain::user);
    EXPECT_EQ(cpu->groups[0].address_space, 100u);
    EXPECT_EQ(cpu->shadow[0][0], 42);
    EXPECT_EQ(cpu->shadow[0][1], 7);
    EXPECT_EQ(original[0], 0);
}

TEST_F(EptTest, ExecuteAndDataAccessSelectStableSeparateViews) {
    const auto a = Hook();
    ASSERT_TRUE(install_ept_hook(*cpu, a));
    auto* pte = get_ept_pte(*cpu, a.pfn << 12);
    ASSERT_NE(pte, nullptr);
    handle_page_access(*cpu, a.pfn << 12, true);
    EXPECT_EQ(pte->page_frame_number, ShadowPfn());
    EXPECT_EQ(pte->flags & 7, 4u);
    handle_page_access(*cpu, a.pfn << 12, false);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(pte->page_frame_number, a.pfn);
    EXPECT_EQ(pte->flags & 7, 3u);
    rearm_ept(*cpu);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(pte->flags & 7, 3u);
}

TEST_F(EptTest, UnknownAddressSpaceExecutesOriginalAfterContextReset) {
    const auto a = Hook();
    ASSERT_TRUE(install_ept_hook(*cpu, a));
    auto* pte = get_ept_pte(*cpu, a.pfn << 12);
    ASSERT_NE(pte, nullptr);
    platform().current_cr3 = 3;
    reset_ept_context(*cpu);
    handle_page_access(*cpu, a.pfn << 12, true);
    EXPECT_EQ(pte->page_frame_number, a.pfn);
    EXPECT_EQ(pte->flags & 7, 7u);
}

class GroupTest : public EptTest {
   protected:
    void SetUp() override {
        EptTest::SetUp();
        ASSERT_FALSE(HasFatalFailure());
        a = Hook();
        mate = Hook(2, a.pfn, 0x100010);
        mate.length = 2;
        mate.patch[0] = 11;
        mate.patch[1] = 22;
        ASSERT_TRUE(install_ept_hook(*cpu, a));
        ASSERT_TRUE(install_ept_hook(*cpu, mate));
        pte = get_ept_pte(*cpu, a.pfn << 12);
        ASSERT_NE(pte, nullptr);
    }
    blook::hook_spec a{}, mate{};
    ept_pte* pte{};
};

TEST_F(GroupTest, SameProcessPageMatesMergeBothPatches) {
    EXPECT_TRUE(cpu->hooks[1].active);
    EXPECT_EQ(cpu->hooks[1].group, 0u);
    EXPECT_EQ(cpu->shadow[0][0], 42);
    EXPECT_EQ(cpu->shadow[0][0x10], 11);
    EXPECT_EQ(cpu->shadow[0][0x11], 22);
    reset_ept_context(*cpu);
    handle_page_access(*cpu, a.pfn << 12, true);
    EXPECT_EQ(pte->page_frame_number, ShadowPfn());
    EXPECT_EQ(pte->flags & 7, 4u);
}

TEST_F(GroupTest, InternalPatchEntrySingleStepsOriginalThenRearms) {
    handle_page_access(*cpu, a.pfn << 12, true, 0x100011);
    EXPECT_EQ(pte->page_frame_number, a.pfn);
    EXPECT_EQ(pte->flags & 7, 7u);
    EXPECT_TRUE(platform().mtf);
    rearm_ept(*cpu);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(pte->flags & 7, 3u);
}

TEST_F(GroupTest, RejectsOverlappingRangesAndDuplicateId) {
    auto overlap = a;
    overlap.id = 3;
    EXPECT_FALSE(install_ept_hook(*cpu, overlap));
    auto overlap_mate = mate;
    overlap_mate.id = 4;
    overlap_mate.target = 0x100011;
    overlap_mate.length = 1;
    EXPECT_FALSE(install_ept_hook(*cpu, overlap_mate));
    EXPECT_FALSE(install_ept_hook(*cpu, mate));
}

TEST_F(GroupTest, RefreshRebuildsAllMemberPatchesOverFreshOriginal) {
    original[2] = 0x5a;
    refresh_ept_hook(*cpu, a.id);
    EXPECT_EQ(cpu->shadow[0][0], 42);
    EXPECT_EQ(cpu->shadow[0][2], 0x5a);
    EXPECT_EQ(cpu->shadow[0][0x10], 11);
    EXPECT_EQ(cpu->shadow[0][0x11], 22);
}

TEST_F(GroupTest, RemovingMemberRebuildsAndKeepsSurvivorArmed) {
    remove_ept_hook(*cpu, mate.id);
    EXPECT_TRUE(cpu->hooks[0].active);
    EXPECT_FALSE(cpu->hooks[1].active);
    EXPECT_EQ(cpu->shadow[0][0], 42);
    EXPECT_EQ(cpu->shadow[0][0x10], 0);
    EXPECT_EQ(pte->flags & 7, 3u);
    EXPECT_EQ(pte->page_frame_number, a.pfn);
}

TEST_F(GroupTest, SharedPhysicalPageSeparatesOwnersAndReusesFreedSlot) {
    remove_ept_hook(*cpu, mate.id);
    auto other = a;
    other.id = 5;
    other.address_space = 200;
    other.identity_address = 0x300000;
    other.patch[0] = 99;
    ASSERT_TRUE(install_ept_hook(*cpu, other));
    EXPECT_EQ(cpu->hooks[1].group, 1u);
    EXPECT_TRUE(cpu->groups[1].active);
    EXPECT_EQ(cpu->groups[1].address_space, 200u);
    platform().current_cr3 = 2;
    reset_ept_context(*cpu);
    handle_page_access(*cpu, a.pfn << 12, true);
    EXPECT_EQ(pte->page_frame_number, ShadowPfn(1));
    EXPECT_EQ(cpu->shadow[1][0], 99);
    EXPECT_EQ(cpu->shadow[1][0x10], 0);
    // Last group, not last individual hook, owns split reclamation.
    remove_ept_hook(*cpu, a.id);
    EXPECT_EQ(pte->flags & 7, 3u);
    EXPECT_EQ(pte->page_frame_number, a.pfn);
    remove_ept_hook(*cpu, other.id);
    EXPECT_EQ(get_ept_pte(*cpu, a.pfn << 12), nullptr);
}

TEST_F(EptTest, KernelHookCannotJoinUserPage) {
    auto a = Hook();
    ASSERT_TRUE(install_ept_hook(*cpu, a));
    a.id = 6;
    a.domain = blook::hook_domain::kernel;
    a.address_space = 0;
    a.identity_address = 0;
    EXPECT_FALSE(install_ept_hook(*cpu, a));
}

TEST_F(EptTest, KernelPageMatesMergeAndReuseRemovedRange) {
    // Keep the user region split while the independent kernel region is freed.
    auto user = Hook();
    ASSERT_TRUE(install_ept_hook(*cpu, user));
    auto other = user;
    other.id = 5;
    other.address_space = 200;
    other.identity_address = 0x300000;
    ASSERT_TRUE(install_ept_hook(*cpu, other));
    auto kernel = Hook(6, 0x800, 0x800000);
    kernel.domain = blook::hook_domain::kernel;
    kernel.address_space = 0;
    kernel.identity_address = 0;
    kernel.patch[0] = 0x66;
    auto mate = kernel;
    mate.id = 7;
    mate.target = 0x800020;
    mate.patch[0] = 0x77;
    ASSERT_TRUE(install_ept_hook(*cpu, kernel));
    ASSERT_TRUE(install_ept_hook(*cpu, mate));
    EXPECT_EQ(cpu->hooks[2].group, cpu->hooks[3].group);
    auto* pte = get_ept_pte(*cpu, kernel.pfn << 12);
    ASSERT_NE(pte, nullptr);
    handle_page_access(*cpu, kernel.pfn << 12, true);
    EXPECT_EQ(pte->page_frame_number, ShadowPfn(2));
    const auto group = cpu->hooks[2].group;
    EXPECT_EQ(cpu->shadow[group][0], 0x66);
    EXPECT_EQ(cpu->shadow[group][0x20], 0x77);
    auto overlap = kernel;
    overlap.id = 8;
    overlap.target = 0x500000;  // Same physical-page offset, different VA.
    EXPECT_FALSE(install_ept_hook(*cpu, overlap));
    remove_ept_hook(*cpu, kernel.id);
    EXPECT_EQ(pte->flags & 7, 3u);
    EXPECT_EQ(pte->page_frame_number, kernel.pfn);
    ASSERT_TRUE(install_ept_hook(*cpu, overlap));
    EXPECT_EQ(cpu->hooks[2].group, cpu->hooks[3].group);
    EXPECT_EQ(cpu->shadow[cpu->hooks[2].group][0], 0x66);
    remove_ept_hook(*cpu, overlap.id);
    remove_ept_hook(*cpu, mate.id);
    EXPECT_EQ(get_ept_pte(*cpu, kernel.pfn << 12), nullptr);
    EXPECT_NE(get_ept_pte(*cpu, user.pfn << 12), nullptr);
}

TEST_F(EptTest, RecyclesSplitSlotsAcrossHundredsOfRegionsAndInvalidates) {
    for (unsigned i = 0; i < 320; ++i) {
        SCOPED_TRACE(i);
        const auto a = Hook(i + 20, 0x1000ull + (uint64_t{i} << 9));
        ASSERT_TRUE(install_ept_hook(*cpu, a));
        remove_ept_hook(*cpu, a.id);
        EXPECT_EQ(get_ept_pte(*cpu, a.pfn << 12), nullptr);
    }
    EXPECT_GT(platform().invalidations, 600u);
}

TEST_F(EptTest, EachProcessorOwnsDistinctShadowPhysicalPages) {
    auto second = std::make_unique<vcpu_ept_data>();
    ASSERT_TRUE(prepare_ept(*second));
    const auto a = Hook(400, 0x600);
    ASSERT_TRUE(install_ept_hook(*cpu, a));
    ASSERT_TRUE(install_ept_hook(*second, a));
    EXPECT_NE(ShadowPfn(), second->groups[second->hooks[0].group].shadow_pfn);
}

TEST_F(EptTest, RejectsPatchCrossingPhysicalPageBoundary) {
    const auto a = Hook(400, 0x600);
    ASSERT_TRUE(install_ept_hook(*cpu, a));
    auto bad = a;
    ++bad.id;
    bad.target = 0x1fffff;
    bad.length = 2;
    EXPECT_FALSE(install_ept_hook(*cpu, bad));
}
}  // namespace ept_test
