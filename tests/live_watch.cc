#include <chrono>
#include <thread>

#include "ept_live/fixture.hpp"

namespace blook::tests::ept_live {
class LiveWatch : public EptLive {
   protected:
    std::optional<client::watch> watch_;
    std::vector<uint8_t> expected_;
    void SetUp() override {
        EptLive::SetUp();
        if (HasFatalFailure() || IsSkipped())
            return;
        ASSERT_TRUE(Allocate());
        Write(0, return_value(1337));
        for (size_t i = 0x40; i < page_size; ++i)
            state_->memory[i] = static_cast<uint8_t>(i * 13);
        expected_ = Read(0, page_size);
        ASSERT_TRUE(Publish());
        ASSERT_EQ(Execute(), 1337);
        auto armed = state_->session->watch_execute(state_->memory,
                                                    state_->memory, page_size);
        ASSERT_TRUE(armed.has_value()) << armed.error().message();
        watch_.emplace(std::move(*armed));
    }
    void TearDown() override {
        if (watch_ && *watch_) {
            const auto disarmed = watch_->disarm();
            if (!disarmed) {
                MarkCleanupFailed();
                ADD_FAILURE()
                    << "DISARM failed: " << disarmed.error().message();
                (void)new client::watch(std::move(*watch_));
                (void)state_.release();
                return;
            }
        }
        EptLive::TearDown();
    }
    void TriggerAndCheckDump() {
        ASSERT_EQ(Execute(), 1337);
        bool ready = false;
        client::watch_hit hit{};
        for (unsigned i = 0; i < 100; ++i) {
            auto polled = watch_->poll();
            ASSERT_TRUE(polled.has_value()) << polled.error().message();
            if (polled->ready) {
                hit = *polled;
                ready = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        ASSERT_TRUE(ready) << "Watch did not fire";
        EXPECT_EQ(hit.rip, reinterpret_cast<uint64_t>(state_->memory));
        EXPECT_EQ(hit.total, page_size);
        const auto dump = watch_->dump();
        ASSERT_TRUE(dump.has_value()) << dump.error().message();
        ASSERT_EQ(dump->size(), page_size);
        EXPECT_EQ(std::memcmp(dump->data(), expected_.data(), page_size), 0);
    }
};
TEST_F(LiveWatch, PendingWatchRejectsDumpBeforeExecution) {
    const auto pending = watch_->poll();
    ASSERT_TRUE(pending.has_value()) << pending.error().message();
    EXPECT_FALSE(pending->ready);
    const auto dump = watch_->dump();
    EXPECT_FALSE(dump.has_value());
}
TEST_F(LiveWatch, OwnerExecutionDumpsExactPhysicalBytes) {
    ASSERT_NO_FATAL_FAILURE(TriggerAndCheckDump());
}
TEST_F(LiveWatch, OneShotHitKeepsCodeRunningAndDisarmsCleanly) {
    ASSERT_NO_FATAL_FAILURE(TriggerAndCheckDump());
    for (unsigned i = 0; i < 10000; ++i)
        ASSERT_EQ(Execute(), 1337) << i;
    const auto disarmed = watch_->disarm();
    ASSERT_TRUE(disarmed.has_value()) << disarmed.error().message();
    EXPECT_EQ(Execute(), 1337);
}
}  // namespace blook::tests::ept_live
