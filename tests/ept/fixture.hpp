#pragma once

#include <gtest/gtest.h>

#include <array>
#include <memory>

#include "driver/hv/ept.h"
#include "platform_mock.hpp"

namespace ept_test {
// A freshly prepared real EPT and a page with stable lifetime per TEST_F.
// Derive for domain-specific setup; call EptTest::SetUp() first.
class EptTest : public ::testing::Test {
   protected:
    void SetUp() override;
    void TearDown() override;
    blook::hook_spec Hook(uint64_t id = 1, uint64_t pfn = 0x400,
                          uint64_t target = 0x100000);
    uint32_t ShadowPfn(size_t slot = 0) const;

    std::unique_ptr<hv::vcpu_ept_data> cpu;
    std::array<uint8_t, 4096> original{};
};
}  // namespace ept_test
