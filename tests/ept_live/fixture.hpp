#pragma once

#include <gtest/gtest.h>

#include <array>
#include <memory>
#include <optional>
#include <span>

#include "client/ept.hpp"

namespace blook::tests::ept_live {

inline constexpr size_t page_size = 4096;
using stub = std::array<uint8_t, 6>;
[[nodiscard]] stub return_value(uint32_t value);

// This fixture never loads a driver. No device is opened without explicit
// opt-in. All generated-code calls and mutations are synchronous on the test
// thread.
class EptLive : public ::testing::Test {
   protected:
    struct resources {
        std::optional<client::session> session;
        std::optional<client::hook> hook;
        uint8_t* memory{};
        size_t size{};
        ~resources();
    };
    std::unique_ptr<resources> state_;

    static void MarkCleanupFailed();
    void SetUp() override;
    void TearDown() override;
    ::testing::AssertionResult Allocate(size_t pages = 1);
    ::testing::AssertionResult Protect(DWORD protection);
    ::testing::AssertionResult Publish();
    ::testing::AssertionResult Install(size_t offset,
                                       std::span<const uint8_t> bytes);
    ::testing::AssertionResult Refresh();
    ::testing::AssertionResult Remove();
    void Write(size_t offset, std::span<const uint8_t> bytes);
    [[nodiscard]] int Execute(size_t offset = 0) const;
    [[nodiscard]] std::vector<uint8_t> Read(size_t offset, size_t length) const;
};

}  // namespace blook::tests::ept_live
