#include "fixture.hpp"

namespace blook::tests::ept_live {

TEST_F(EptLive, ClientRejectsPatchBytesThatCrossPageBoundary) {
    ASSERT_TRUE(Allocate(2));
    constexpr size_t target = page_size - 3;
    Write(target, return_value(7));
    const auto original = Read(0, 2 * page_size);
    ASSERT_TRUE(Publish());
    ASSERT_EQ(Execute(target), 7);
    auto rejected =
        state_->session->patch(state_->memory + target, return_value(42));
    // Own an unexpectedly accepted hook BEFORE asserting, to preserve safe
    // cleanup even when this regression test fails.
    if (rejected)
        state_->hook.emplace(std::move(*rejected));
    ASSERT_FALSE(rejected.has_value()) << "Cross-page patch was accepted";
    EXPECT_EQ(rejected.error().value(), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(Read(0, 2 * page_size), original);
    EXPECT_EQ(Execute(target), 7);
}

TEST_F(EptLive, DriverRejectsInstructionCoverageThatCrossesPageBoundary) {
    ASSERT_TRUE(Allocate(2));
    constexpr size_t target = page_size - 2;
    Write(target, return_value(7));  // mov eax,imm32 straddles the boundary
    const auto original = Read(0, 2 * page_size);
    ASSERT_TRUE(Publish());
    ASSERT_EQ(Execute(target), 7);
    const std::array<uint8_t, 1> replacement{0xc3};
    // The requested ONE byte fits; client validation permits the IOCTL. The
    // driver's whole-instruction decoder must reject an incomplete mov in the
    // remainder of the first page rather than decoding beyond its locked page.
    ASSERT_TRUE(
        blook::valid_patch(reinterpret_cast<uint64_t>(state_->memory + target),
                           replacement.size()));
    auto rejected =
        state_->session->patch(state_->memory + target, replacement);
    if (rejected)
        state_->hook.emplace(std::move(*rejected));
    ASSERT_FALSE(rejected.has_value()) << "Cross-page instruction was accepted";
    EXPECT_EQ(rejected.error().value(), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(Read(0, 2 * page_size), original);
    EXPECT_EQ(Execute(target), 7);
}

}  // namespace blook::tests::ept_live
