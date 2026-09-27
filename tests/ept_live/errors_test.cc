#include <utility>

#include "fixture.hpp"

namespace blook::tests::ept_live {
namespace {

class EptErrors : public EptLive {
   protected:
    // Normally empty. Keep an unexpectedly accepted overlapping hook alive
    // until teardown, rather than relying on a best-effort local destructor.
    std::optional<client::hook> unexpected_overlap_;

    void TearDown() override {
        if (unexpected_overlap_ && *unexpected_overlap_) {
            const auto removed = unexpected_overlap_->remove();
            if (!removed) {
                MarkCleanupFailed();
                ADD_FAILURE() << "Unexpected overlapping hook cleanup failed: "
                              << removed.error().message()
                              << "; retaining all backing resources";
                // Neither hook may outlive its allocation. Preserve both
                // connections as well if the driver cannot acknowledge REMOVE.
                (void)new client::hook(std::move(*unexpected_overlap_));
                (void)state_.release();
                return;
            }
        }
        EptLive::TearDown();
    }

    void Prepare() {
        ASSERT_TRUE(Allocate());
        Write(0, return_value(7));
        ASSERT_TRUE(Publish());
        ASSERT_EQ(Execute(), 7);
    }

    void CheckSession(uint32_t hooks = 0) {
        const auto queried = state_->session->query();
        ASSERT_TRUE(queried.has_value()) << queried.error().message();
        EXPECT_TRUE(queried->running);
        EXPECT_TRUE(queried->enabled);
        EXPECT_EQ(queried->hooks, hooks);
    }

    // Every rejected operation is followed by a complete, acknowledged
    // install/execute/remove cycle on the SAME connection and allocation.
    void CheckRecovery() {
        ASSERT_NO_FATAL_FAILURE(CheckSession());
        EXPECT_EQ(Execute(), 7);
        ASSERT_TRUE(Install(0, return_value(42)));
        ASSERT_NO_FATAL_FAILURE(CheckSession(1));
        EXPECT_EQ(Execute(), 42);
        EXPECT_EQ(Read(0, stub{}.size()),
                  (std::vector<uint8_t>{0xb8, 7, 0, 0, 0, 0xc3}));
        ASSERT_TRUE(Remove());
        EXPECT_EQ(Execute(), 7);
        ASSERT_NO_FATAL_FAILURE(CheckSession());
    }

    void OwnUnexpected(client::result<client::hook>& result) {
        if (result)
            state_->hook.emplace(std::move(*result));
    }
};

TEST_F(EptErrors, EmptyPatchReturnsInvalidParameterAndSessionRecovers) {
    ASSERT_NO_FATAL_FAILURE(Prepare());
    const std::array<uint8_t, 0> empty{};
    auto rejected = state_->session->patch(state_->memory, empty);
    OwnUnexpected(rejected);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error(),
              std::error_code(ERROR_INVALID_PARAMETER, std::system_category()));
    ASSERT_NO_FATAL_FAILURE(CheckRecovery());
}

TEST_F(EptErrors, OversizedPatchReturnsInvalidParameterAndSessionRecovers) {
    ASSERT_NO_FATAL_FAILURE(Prepare());
    const std::array<uint8_t, blook::max_patch + 1> oversized{};
    auto rejected = state_->session->patch(state_->memory, oversized);
    OwnUnexpected(rejected);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error(),
              std::error_code(ERROR_INVALID_PARAMETER, std::system_category()));
    ASSERT_NO_FATAL_FAILURE(CheckRecovery());
}

TEST_F(EptErrors, NullTargetReturnsInvalidParameterAndSessionRecovers) {
    ASSERT_NO_FATAL_FAILURE(Prepare());
    auto rejected = state_->session->patch(nullptr, return_value(42));
    OwnUnexpected(rejected);
    ASSERT_FALSE(rejected.has_value());
    // valid_patch checks length/page geometry, not null. prepare_hook rejects
    // null with STATUS_INVALID_PARAMETER before dereferencing the target.
    EXPECT_EQ(rejected.error(),
              std::error_code(ERROR_INVALID_PARAMETER, std::system_category()));
    ASSERT_NO_FATAL_FAILURE(CheckRecovery());
}

TEST_F(EptErrors, NoAccessTargetReturnsErrorAndSessionRecovers) {
    ASSERT_NO_FATAL_FAILURE(Prepare());
    ASSERT_TRUE(Protect(PAGE_NOACCESS));
    auto rejected = state_->session->patch(state_->memory, return_value(42));
    OwnUnexpected(rejected);
    ASSERT_FALSE(rejected.has_value());
    // check_user_page rejects this with STATUS_INVALID_PAGE_PROTECTION before
    // MDL locking or decoding. Do not guess the NTSTATUS-to-Win32 mapping.
    EXPECT_EQ(rejected.error().category(), std::system_category());
    EXPECT_NE(rejected.error().value(), ERROR_SUCCESS);
    ASSERT_NO_FATAL_FAILURE(CheckSession());
    // Never read or execute PAGE_NOACCESS. Restore RX before the health cycle.
    ASSERT_TRUE(Publish());
    ASSERT_NO_FATAL_FAILURE(CheckRecovery());
}

TEST_F(EptErrors, OverlapRejectionPreservesExistingHookAndSessionRecovers) {
    ASSERT_NO_FATAL_FAILURE(Prepare());
    ASSERT_TRUE(Install(0, return_value(42)));
    const auto installed_id = state_->hook->id();
    ASSERT_EQ(Execute(), 42);
    auto rejected = state_->session->patch(state_->memory, return_value(99));
    if (rejected)
        unexpected_overlap_.emplace(std::move(*rejected));
    ASSERT_FALSE(rejected.has_value());
    // prepare_hook returns STATUS_OBJECT_NAME_COLLISION for incompatible
    // covered ranges. Only require the stable SDK error contract here.
    EXPECT_EQ(rejected.error().category(), std::system_category());
    EXPECT_NE(rejected.error().value(), ERROR_SUCCESS);
    EXPECT_EQ(state_->hook->id(), installed_id);
    ASSERT_NO_FATAL_FAILURE(CheckSession(1));
    EXPECT_EQ(Execute(), 42);
    ASSERT_TRUE(Refresh());
    EXPECT_EQ(Execute(), 42);
    EXPECT_EQ(Read(0, stub{}.size()),
              (std::vector<uint8_t>{0xb8, 7, 0, 0, 0, 0xc3}));
    ASSERT_TRUE(Remove());
    ASSERT_NO_FATAL_FAILURE(CheckRecovery());
}

TEST_F(EptErrors, RefreshAfterRemoveReturnsInvalidHandleAndSessionRecovers) {
    ASSERT_NO_FATAL_FAILURE(Prepare());
    ASSERT_TRUE(Install(0, return_value(42)));
    EXPECT_EQ(Execute(), 42);
    ASSERT_TRUE(Remove());
    EXPECT_EQ(state_->hook->id(), 0u);
    EXPECT_FALSE(static_cast<bool>(*state_->hook));
    const auto rejected = state_->hook->refresh();
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error(),
              std::error_code(ERROR_INVALID_HANDLE, std::system_category()));
    ASSERT_TRUE(
        Remove());  // remove on an inert handle is explicitly idempotent
    ASSERT_NO_FATAL_FAILURE(CheckRecovery());
}

TEST_F(EptErrors, MovedFromSessionQueryReturnsInvalidHandleAndOwnerRecovers) {
    ASSERT_NO_FATAL_FAILURE(Prepare());
    auto invalid = std::move(*state_->session);
    *state_->session =
        std::move(invalid);  // restore owner; invalid is now inert
    const auto rejected = invalid.query();
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error(),
              std::error_code(ERROR_INVALID_HANDLE, std::system_category()));
    ASSERT_NO_FATAL_FAILURE(CheckRecovery());
}

TEST_F(EptErrors, MovedFromSessionPatchReturnsInvalidHandleAndOwnerRecovers) {
    ASSERT_NO_FATAL_FAILURE(Prepare());
    auto invalid = std::move(*state_->session);
    *state_->session = std::move(invalid);
    // Valid arguments ensure local patch validation does not mask the missing
    // connection: malformed bytes would instead yield INVALID_PARAMETER.
    auto rejected = invalid.patch(state_->memory, return_value(42));
    OwnUnexpected(rejected);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error(),
              std::error_code(ERROR_INVALID_HANDLE, std::system_category()));
    ASSERT_NO_FATAL_FAILURE(CheckRecovery());
}

}  // namespace
}  // namespace blook::tests::ept_live
