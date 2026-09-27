#include <algorithm>

#include "ept/fixture.hpp"

namespace ept_test {
class PatchBoundaryTest : public EptTest,
                          public testing::WithParamInterface<unsigned> {};
TEST_P(PatchBoundaryTest, MaximumPatchEndingExactlyAtPageBoundary) {
    auto hook = Hook();
    hook.length = GetParam();
    hook.target += 4096 - hook.length;
    std::fill_n(hook.patch, hook.length, uint8_t{0xe9});
    ASSERT_TRUE(hv::install_ept_hook(*cpu, hook));
    EXPECT_EQ(cpu->shadow[cpu->hooks[0].group][4095], 0xe9);
    auto crossing = Hook(2, 0x401);
    crossing.length = hook.length + 1;
    crossing.target = hook.target;
    EXPECT_FALSE(hv::install_ept_hook(*cpu, crossing));
    EXPECT_FALSE(cpu->hooks[1].active);
}
INSTANTIATE_TEST_SUITE_P(Lengths, PatchBoundaryTest,
                         testing::Values(1u, 5u, 63u, 64u));

TEST_F(EptTest, EveryInternalEntrySingleStepsButEndpointsUseShadow) {
    auto hook = Hook();
    hook.length = 64;
    ASSERT_TRUE(hv::install_ept_hook(*cpu, hook));
    auto* pte = hv::get_ept_pte(*cpu, hook.pfn << 12);
    ASSERT_NE(pte, nullptr);
    for (unsigned offset = 0; offset <= hook.length; ++offset) {
        SCOPED_TRACE(offset);
        hv::handle_page_access(*cpu, hook.pfn << 12, true,
                               hook.target + offset);
        if (offset > 0 && offset < hook.length) {
            EXPECT_EQ(pte->page_frame_number, hook.pfn);
            EXPECT_EQ(pte->flags & 7, 7u);
            EXPECT_TRUE(platform().mtf);
            EXPECT_EQ(cpu->temporary_count, 1u);
            hv::rearm_ept(*cpu);
            EXPECT_EQ(pte->flags & 7, 3u);
            EXPECT_FALSE(platform().mtf);
        } else {
            EXPECT_EQ(pte->page_frame_number, ShadowPfn());
            EXPECT_EQ(pte->flags & 7, 4u);
        }
    }
}

TEST_F(EptTest, HookCapacityFailureIsAtomicAndRemovedSlotReusable) {
    for (size_t i = 0; i < blook::max_hooks; ++i) {
        auto hook = Hook(i + 1);
        hook.target += i;
        hook.length = 1;
        ASSERT_TRUE(hv::install_ept_hook(*cpu, hook)) << i;
    }
    auto extra = Hook(blook::max_hooks + 1);
    extra.target += blook::max_hooks;
    const auto invalidations = platform().invalidations;
    EXPECT_FALSE(hv::install_ept_hook(*cpu, extra));
    EXPECT_EQ(platform().invalidations, invalidations);
    hv::remove_ept_hook(*cpu, 1);
    EXPECT_TRUE(hv::install_ept_hook(*cpu, extra));
    EXPECT_EQ(cpu->hooks[0].spec.id, extra.id);
}

TEST_F(EptTest, PhysicalLimitRejectedWithoutPublishingHook) {
    auto hook = Hook();
    hook.pfn = hv::physical_limit >> 12;
    EXPECT_FALSE(hv::install_ept_hook(*cpu, hook));
    EXPECT_FALSE(cpu->hooks[0].active);
    EXPECT_FALSE(cpu->groups[0].active);
    EXPECT_EQ(hv::get_ept_pte(*cpu, hv::physical_limit, true), nullptr);
}

TEST_F(EptTest, UnknownOperationsLeaveExistingHookAndMappingUnchanged) {
    auto hook = Hook();
    ASSERT_TRUE(hv::install_ept_hook(*cpu, hook));
    auto* pte = hv::get_ept_pte(*cpu, hook.pfn << 12);
    ASSERT_NE(pte, nullptr);
    const auto flags = pte->flags;
    const auto invalidations = platform().invalidations;
    hv::remove_ept_hook(*cpu, 9999);
    hv::refresh_ept_hook(*cpu, 9999);
    EXPECT_FALSE(hv::begin_ept_window(*cpu, 9999));
    EXPECT_FALSE(hv::end_ept_window(*cpu, 9999));
    EXPECT_FALSE(hv::end_ept_window(*cpu, hook.id));
    EXPECT_EQ(pte->flags, flags);
    EXPECT_EQ(platform().invalidations, invalidations);
    EXPECT_TRUE(cpu->hooks[0].active);
}

TEST_F(EptTest, RepeatedFaultOnSameInternalEntryDoesNotDuplicateTemporarySlot) {
    auto hook = Hook();
    hook.length = 5;
    ASSERT_TRUE(hv::install_ept_hook(*cpu, hook));
    for (unsigned i = 0; i < 10; ++i)
        hv::handle_page_access(*cpu, hook.pfn << 12, true, hook.target + 1);
    EXPECT_EQ(cpu->temporary_count, 1u);
    hv::reset_ept_context(*cpu);
    EXPECT_EQ(cpu->temporary_count, 0u);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(hv::get_ept_pte(*cpu, hook.pfn << 12)->flags & 7, 3u);
}
}  // namespace ept_test
