#include "fixture.hpp"

namespace ept_test {
// The VM-exit dispatcher rearms pending single steps before a removal vmcall.
// Preserve that required ordering before recycling the split's PTE storage.
TEST_F(EptTest, RearmBeforeRemovalKeepsReusedSplitEntriesIndependent) {
    auto old = Hook(1, 0x400, 0x100010);
    old.length = 2;
    old.patch[1] = 43;
    ASSERT_TRUE(hv::install_ept_hook(*cpu, old));
    hv::handle_page_access(*cpu, old.pfn << 12, true, old.target + 1);
    ASSERT_TRUE(platform().mtf);
    ASSERT_EQ(cpu->temporary_count, 1u);
    // src/driver/hv/vcpu.cpp dispatches non-EPT exits only after this rearm.
    hv::rearm_ept(*cpu);
    ASSERT_FALSE(platform().mtf);
    ASSERT_EQ(cpu->temporary_count, 0u);
    hv::remove_ept_hook(*cpu, old.id);
    ASSERT_EQ(hv::get_ept_pte(*cpu, old.pfn << 12), nullptr);

    // New hook occupies offset 1; offset 0 is an unrelated identity RWX page
    // at the exact storage location of the old temporary PTE.
    const auto fresh = Hook(2, 0x801, 0x200010);
    ASSERT_TRUE(hv::install_ept_hook(*cpu, fresh));
    auto* unrelated = hv::get_ept_pte(*cpu, 0x800ull << 12);
    ASSERT_NE(unrelated, nullptr);
    ASSERT_EQ(unrelated->page_frame_number, 0x800u);
    ASSERT_EQ(unrelated->flags & 7, 7u);
    hv::rearm_ept(*cpu);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(unrelated->page_frame_number, 0x800u);
    EXPECT_EQ(unrelated->flags & 7, 7u)
        << "stale temporary PTE re-armed an unhooked page in a reused split";
}
}  // namespace ept_test
