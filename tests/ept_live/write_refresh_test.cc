#include "fixture.hpp"

namespace blook::tests::ept_live {

TEST_F(EptLive, RefreshPublishesLatestCodeButKeepsPatchAndTransparentData) {
    ASSERT_TRUE(Allocate());
    constexpr size_t target = 0x100;
    constexpr size_t neighbour = 0x200;
    constexpr size_t marker = 0x380;
    Write(target, return_value(7));
    Write(neighbour, return_value(11));
    auto expected_page = Read(0, page_size);
    ASSERT_TRUE(Publish());
    ASSERT_TRUE(Install(target, return_value(42)));
    ASSERT_EQ(Execute(target), 42);
    ASSERT_EQ(Execute(neighbour), 11);

    // No other thread executes this allocation. refresh() requires execution
    // quiescence during both mutation and snapshot publication. Do NOT assume
    // writes automatically update the shadow, or require stale execution before
    // refresh: protection maintenance may republish a snapshot on some paths.
    for (uint32_t generation = 1; generation <= 3; ++generation) {
        SCOPED_TRACE(generation);
        ASSERT_TRUE(Protect(PAGE_READWRITE));
        const auto latest_target = return_value(70 + generation);
        const auto latest_neighbour = return_value(110 + generation);
        Write(target, latest_target);
        Write(neighbour, latest_neighbour);
        std::memcpy(expected_page.data() + target, latest_target.data(),
                    latest_target.size());
        std::memcpy(expected_page.data() + neighbour, latest_neighbour.data(),
                    latest_neighbour.size());
        const std::array<uint8_t, 4> data{
            0x5a, static_cast<uint8_t>(generation), 0xa5, 0x3c};
        Write(marker, data);
        std::memcpy(expected_page.data() + marker, data.data(), data.size());
        ASSERT_EQ(Read(0, page_size), expected_page);
        ASSERT_TRUE(Publish());
        ASSERT_TRUE(Refresh());  // explicit client API: IOCTL_BLOOK_REFRESH
        EXPECT_EQ(Read(0, page_size), expected_page);
        EXPECT_EQ(Execute(target), 42);
        EXPECT_EQ(Execute(neighbour), static_cast<int>(110 + generation));
        EXPECT_EQ(Read(0, page_size), expected_page);
    }
    ASSERT_TRUE(Remove());
    EXPECT_EQ(Execute(target), 73);  // never restore the pre-hook value 7
    EXPECT_EQ(Execute(neighbour), 113);
    EXPECT_EQ(Read(0, page_size), expected_page);
}

TEST_F(EptLive, RemovalPreservesWritesEvenWithoutExplicitRefresh) {
    ASSERT_TRUE(Allocate());
    Write(0, return_value(7));
    auto expected_page = Read(0, page_size);
    ASSERT_TRUE(Publish());
    ASSERT_TRUE(Install(0, return_value(42)));
    ASSERT_EQ(Execute(), 42);

    ASSERT_TRUE(Protect(PAGE_READWRITE));
    const auto latest_target = return_value(99);
    Write(0, latest_target);
    const std::array<uint8_t, 3> data{0xde, 0xad, 0x5a};
    Write(0x300, data);
    std::memcpy(expected_page.data(), latest_target.data(),
                latest_target.size());
    std::memcpy(expected_page.data() + 0x300, data.data(), data.size());
    ASSERT_EQ(Read(0, page_size), expected_page);
    ASSERT_TRUE(Publish());
    // Removal should unmap the execution shadow, not copy an old snapshot over
    // the backing page. No assertion about shadow freshness before removal.
    ASSERT_TRUE(Remove());
    EXPECT_EQ(Execute(), 99);
    EXPECT_EQ(Read(0, page_size), expected_page);
}

}  // namespace blook::tests::ept_live
