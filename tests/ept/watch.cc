#include <vector>

#include "fixture.hpp"

namespace ept_test {
using namespace hv;
class WatchTest : public EptTest {
   protected:
    void SetUp() override {
        EptTest::SetUp();
        ASSERT_FALSE(HasFatalFailure());
        spec.id = 700;
        spec.pfn = 0x2000;
        spec.target = 0x700080;
        spec.address_space = 100;
        spec.identity_address = 0x900000;
        spec.owner_pid = 1234;
        for (size_t i = 0; i < source_a.size(); ++i) {
            source_a[i] = static_cast<uint8_t>(i);
            source_b[i] = static_cast<uint8_t>(i * 7);
        }
        platform().MapUser(1, 0x710000, 0x4700000);
        platform().MapUser(1, 0x711000, 0x4701000);
        platform().MapPhysical(0x4700000, source_a.data());
        platform().MapPhysical(0x4701000, source_b.data());
        dump.resize(0x2000);
        record.dump_base = 0x710000;
        record.dump_size = 0x1020;
        record.buffer = dump.data();
        ASSERT_TRUE(install_ept_watch(*cpu, spec, &record));
        pte = get_ept_pte(*cpu, spec.pfn << 12);
        ASSERT_NE(pte, nullptr);
    }
    blook::watch_spec spec{};
    blook::watch_record record{};
    std::array<uint8_t, 4096> source_a{}, source_b{};
    std::vector<uint8_t> dump;
    ept_pte* pte{};
};

TEST_F(WatchTest, ArmsOriginalPageAndRejectsDuplicateIdOrPage) {
    EXPECT_EQ(pte->flags & 7, 3u);
    EXPECT_EQ(pte->page_frame_number, spec.pfn);
    EXPECT_FALSE(install_ept_watch(*cpu, spec, &record));
    auto sibling = spec;
    sibling.id = 701;
    EXPECT_FALSE(install_ept_watch(*cpu, sibling, &record));
}

TEST_F(WatchTest, HooksAndWatchesRejectSharingPageInEitherDirection) {
    auto clash = Hook(702, spec.pfn, 0x700040);
    clash.identity_address = 0x900000;
    clash.patch[0] = 1;
    EXPECT_FALSE(install_ept_hook(*cpu, clash));
    clash.pfn = 0x4000;
    ASSERT_TRUE(install_ept_hook(*cpu, clash));
    auto clash_watch = spec;
    clash_watch.id = 703;
    clash_watch.pfn = clash.pfn;
    EXPECT_FALSE(install_ept_watch(*cpu, clash_watch, &record));
}

TEST_F(WatchTest, NeighborFetchSingleStepsAndRearmsWithoutDump) {
    handle_page_access(*cpu, spec.pfn << 12, true, spec.target - 4);
    EXPECT_EQ(pte->flags & 7, 7u);
    EXPECT_TRUE(platform().mtf);
    EXPECT_EQ(record.state, blook::watch_pending);
    rearm_ept(*cpu);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(pte->flags & 7, 3u);
}

TEST_F(WatchTest, ExactTargetInDifferentAddressSpaceDoesNotFire) {
    platform().current_cr3 = 2;
    handle_page_access(*cpu, spec.pfn << 12, true, spec.target);
    EXPECT_EQ(record.state, blook::watch_pending);
    EXPECT_TRUE(cpu->watches[0].active);
    rearm_ept(*cpu);
    EXPECT_EQ(pte->flags & 7, 3u);
}

TEST_F(WatchTest, ExactOwnerHitDumpsAcrossPagesAndReclaimsOnlyWatchRegion) {
    auto clash = Hook(702, 0x4000, 0x700040);
    clash.identity_address = 0x900000;
    clash.patch[0] = 1;
    ASSERT_TRUE(install_ept_hook(*cpu, clash));
    handle_page_access(*cpu, spec.pfn << 12, true, spec.target);
    EXPECT_EQ(record.state, blook::watch_hit);
    EXPECT_EQ(record.hit_rip, spec.target);
    EXPECT_EQ(record.hit_cr3, platform().current_cr3);
    EXPECT_FALSE(cpu->watches[0].active);
    EXPECT_EQ(pte->flags & 7, 7u);
    EXPECT_EQ(pte->page_frame_number, spec.pfn);
    for (size_t i = 0; i < source_a.size(); ++i) {
        SCOPED_TRACE(i);
        EXPECT_EQ(dump[i], source_a[i]);
    }
    for (size_t i = 0; i < 0x20; ++i) {
        SCOPED_TRACE(i);
        EXPECT_EQ(dump[4096 + i], source_b[i]);
    }
    EXPECT_EQ(get_ept_pte(*cpu, spec.pfn << 12), nullptr);
    EXPECT_NE(get_ept_pte(*cpu, clash.pfn << 12), nullptr);
    remove_ept_hook(*cpu, clash.id);
    EXPECT_EQ(get_ept_pte(*cpu, clash.pfn << 12), nullptr);
}
}  // namespace ept_test
