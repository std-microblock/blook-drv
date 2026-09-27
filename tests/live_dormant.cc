#include <chrono>
#include <cstring>
#include <thread>

#include "ept_live/fixture.hpp"

namespace blook::tests::ept_live {
// Dormant registration: a hook or watch installed while the page is still
// read/write must succeed instead of failing with
// STATUS_INVALID_PAGE_PROTECTION, and must arm on the protection change that
// makes the page executable - before that VirtualProtect returns.
class LiveDormant : public EptLive {
   protected:
    std::optional<client::watch> watch_;
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
};

TEST_F(LiveDormant, HookOnWritablePageArmsWhenItTurnsExecutable) {
    ASSERT_TRUE(Allocate());
    Write(0, return_value(7));
    // PAGE_READWRITE here: this must register dormant, not fail.
    ASSERT_TRUE(Install(0, return_value(42)));
    // The RX transition arms the dormant hook before VirtualProtect returns.
    ASSERT_TRUE(Publish());
    EXPECT_EQ(Execute(), 42);
    ASSERT_TRUE(Remove());
    EXPECT_EQ(Execute(), 7);
}

TEST_F(LiveDormant, WatchOnWritablePageArmsWhenItTurnsExecutable) {
    ASSERT_TRUE(Allocate());
    Write(0, return_value(1337));
    for (size_t i = 0x40; i < page_size; ++i)
        state_->memory[i] = static_cast<uint8_t>(i * 13);
    const auto expected = Read(0, page_size);
    auto armed = state_->session->watch_execute(state_->memory, state_->memory,
                                                page_size);
    ASSERT_TRUE(armed.has_value()) << armed.error().message();
    watch_.emplace(std::move(*armed));
    {
        const auto pending = watch_->poll();
        ASSERT_TRUE(pending.has_value()) << pending.error().message();
        EXPECT_FALSE(pending->ready);
    }
    ASSERT_TRUE(Publish());
    ASSERT_EQ(Execute(), 1337);
    bool ready = false;
    for (unsigned i = 0; i < 100 && !ready; ++i) {
        auto polled = watch_->poll();
        ASSERT_TRUE(polled.has_value()) << polled.error().message();
        ready = polled->ready;
        if (!ready)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    ASSERT_TRUE(ready) << "Dormant watch did not fire";
    const auto dump = watch_->dump();
    ASSERT_TRUE(dump.has_value()) << dump.error().message();
    ASSERT_EQ(dump->size(), page_size);
    EXPECT_EQ(std::memcmp(dump->data(), expected.data(), page_size), 0);
}

TEST_F(LiveDormant, DormantHookCanBeRemovedBeforeItArms) {
    ASSERT_TRUE(Allocate());
    Write(0, return_value(7));
    ASSERT_TRUE(Install(0, return_value(42)));
    // Removed while still dormant: the RX transition must not arm anything.
    ASSERT_TRUE(Remove());
    ASSERT_TRUE(Publish());
    EXPECT_EQ(Execute(), 7);
}
}  // namespace blook::tests::ept_live
