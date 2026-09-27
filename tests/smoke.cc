#include <atomic>
#include <thread>
#include <vector>

#include "ept_live/fixture.hpp"

namespace blook::tests::ept_live {
class EptSmoke : public EptLive {};

TEST_F(EptSmoke, ConcurrentExecutionKeepsOriginalDataTransparent) {
    ASSERT_TRUE(Allocate());
    const auto original = return_value(7);
    Write(0, original);
    ASSERT_TRUE(Publish());
    ASSERT_EQ(Execute(), 7);
    ASSERT_TRUE(Install(0, return_value(42)));
    std::atomic<unsigned> bad_execute{}, bad_data{};
    // jthread joins even if thread creation throws. No fatal assertions while
    // worker threads hold executable pointers into fixture-owned memory.
    {
        std::vector<std::jthread> threads;
        for (unsigned i = 0; i < 4; ++i)
            threads.emplace_back([&] {
                for (unsigned j = 0; j < 10000; ++j) {
                    if (Execute() != 42)
                        ++bad_execute;
                    const volatile uint8_t* bytes = state_->memory;
                    for (size_t k = 0; k < original.size(); ++k)
                        if (bytes[k] != original[k]) {
                            ++bad_data;
                            break;
                        }
                }
            });
    }
    EXPECT_EQ(bad_execute.load(), 0u);
    EXPECT_EQ(bad_data.load(), 0u);
    ASSERT_TRUE(Remove());
    EXPECT_EQ(Execute(), 7);
}

TEST_F(EptSmoke, QuiescedWriteRefreshAndRemovalPreserveOriginal) {
    ASSERT_TRUE(Allocate());
    Write(0, return_value(7));
    ASSERT_TRUE(Publish());
    ASSERT_TRUE(Install(0, return_value(42)));
    ASSERT_TRUE(Protect(PAGE_READWRITE));
    Write(64, std::array<uint8_t, 1>{0x5a});
    ASSERT_TRUE(Publish());
    ASSERT_TRUE(Refresh());
    EXPECT_EQ(Read(64, 1), std::vector<uint8_t>{0x5a});
    EXPECT_EQ(Execute(), 42);
    ASSERT_TRUE(Remove());
    EXPECT_EQ(Execute(), 7);
    EXPECT_EQ(Read(64, 1), std::vector<uint8_t>{0x5a});
}
}  // namespace blook::tests::ept_live
