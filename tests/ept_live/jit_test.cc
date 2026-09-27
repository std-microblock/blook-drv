#include "fixture.hpp"

namespace blook::tests::ept_live {

TEST_F(EptLive, JitRwToRxSeparatesExecutionFromFullPageDataReads) {
    ASSERT_TRUE(Allocate());
    // A nonzero offset catches shadow copies taken from target instead of the
    // page base. Neighbours must execute their own unmodified instructions.
    constexpr size_t target = 0x180;
    constexpr size_t neighbour = 0x300;
    Write(target, return_value(7));
    Write(neighbour, return_value(19));
    const auto original_page = Read(0, page_size);
    ASSERT_TRUE(Publish());  // JIT starts RW, never RWX, then becomes RX
    ASSERT_EQ(Execute(target), 7);
    ASSERT_EQ(Execute(neighbour), 19);

    ASSERT_TRUE(Install(target, return_value(42)));
    for (int iteration = 0; iteration < 32; ++iteration) {
        SCOPED_TRACE(iteration);
        ASSERT_EQ(Execute(target), 42);
        ASSERT_EQ(Read(0, page_size), original_page);
        ASSERT_EQ(Execute(neighbour), 19);
        ASSERT_EQ(Execute(target), 42);  // execute again after data faults
    }
    ASSERT_TRUE(Remove());
    EXPECT_EQ(state_->hook->id(), 0u);
    EXPECT_EQ(Execute(target), 7);
    EXPECT_EQ(Execute(neighbour), 19);
    EXPECT_EQ(Read(0, page_size), original_page);
    EXPECT_TRUE(Remove());  // API promises idempotent successful removal
}

TEST_F(EptLive, HookedCodeReadsOriginalBytesFromItsOwnExecutionPage) {
    ASSERT_TRUE(Allocate());
    constexpr size_t target = 0x180;
    Write(target, return_value(7));
    const auto original_page = Read(0, page_size);
    ASSERT_TRUE(Publish());
    ASSERT_EQ(Execute(target), 7);

    // mov eax,[rip-5]; add eax,35; ret
    // The load addresses target+1: the ORIGINAL mov eax,7 immediate. Reading
    // the shadow instead would load fffffb05 (ModRM plus displacement bytes),
    // not 7. Fetch and data access target the same EPT
    // page in one instruction: broken MTF handling can hang here, not merely
    // return the wrong value. Run only on the explicitly opted-in lab machine.
    const std::array<uint8_t, 10> replacement{0x8b, 0x05, 0xfb, 0xff, 0xff,
                                              0xff, 0x83, 0xc0, 0x23, 0xc3};
    ASSERT_TRUE(Install(target, replacement));
    for (int iteration = 0; iteration < 16; ++iteration) {
        SCOPED_TRACE(iteration);
        EXPECT_EQ(Execute(target), 42);
        EXPECT_EQ(Read(0, page_size), original_page);
    }
    ASSERT_TRUE(Remove());
    EXPECT_EQ(Execute(target), 7);
    EXPECT_EQ(Read(0, page_size), original_page);
}

}  // namespace blook::tests::ept_live
