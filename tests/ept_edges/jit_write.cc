#include <algorithm>
#include <array>
#include <random>

#include "ept/fixture.hpp"

namespace ept_test {
class JitWriteTest : public EptTest,
                     public testing::WithParamInterface<unsigned> {};

// The model drives EPT exits, not an x86 emulator: data writes below mutate the
// pinned physical backing after the engine grants its original RW/NX view.
TEST_P(JitWriteTest, WriteAfterHookRebuildsEveryByteOnNextExecute) {
    for (size_t i = 0; i < original.size(); ++i)
        original[i] = static_cast<uint8_t>(i * 37);
    auto hook = Hook();
    hook.target += 0x100;
    hook.length = 5;
    std::fill_n(hook.patch, hook.length, uint8_t{0xcc});
    ASSERT_TRUE(hv::install_ept_hook(*cpu, hook));
    hv::handle_page_access(*cpu, hook.pfn << 12, true, hook.target);
    hv::handle_page_access(*cpu, hook.pfn << 12, false);
    auto* pte = hv::get_ept_pte(*cpu, hook.pfn << 12);
    ASSERT_NE(pte, nullptr);
    ASSERT_EQ(pte->page_frame_number, hook.pfn);
    ASSERT_EQ(pte->flags & 7, 3u);
    original[GetParam()] ^= 0x5a;
    auto expected = original;
    std::fill_n(expected.begin() + 0x100, 5, uint8_t{0xcc});
    hv::handle_page_access(*cpu, hook.pfn << 12, true, hook.target);
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(),
                           cpu->shadow[cpu->hooks[0].group]));
    EXPECT_EQ(pte->flags & 7, 4u);
    EXPECT_EQ(pte->page_frame_number, ShadowPfn());
    EXPECT_FALSE(platform().mtf);
    // Removing a hook must never restore an obsolete saved prologue to backing.
    auto latest = original;
    hv::remove_ept_hook(*cpu, hook.id);
    EXPECT_EQ(original, latest);
}
INSTANTIATE_TEST_SUITE_P(PageAndPatchEdges, JitWriteTest,
                         testing::Values(0u, 0xffu, 0x100u, 0x101u, 0x104u,
                                         0x105u, 4095u));

TEST_F(EptTest, SeededJitRewriteSequencesMatchIndependentShadowOracle) {
    auto a = Hook();
    a.target += 32;
    a.length = 5;
    std::fill_n(a.patch, a.length, uint8_t{0xa1});
    auto b = Hook(2);
    b.target += 4000;
    b.length = 64;
    std::fill_n(b.patch, b.length, uint8_t{0xb2});
    ASSERT_TRUE(hv::install_ept_hook(*cpu, a));
    ASSERT_TRUE(hv::install_ept_hook(*cpu, b));
    std::mt19937 random(0x455054);
    for (unsigned round = 0; round < 256; ++round) {
        SCOPED_TRACE(round);
        hv::handle_page_access(*cpu, a.pfn << 12, false);
        const auto start = random() % original.size();
        const auto length =
            std::min<size_t>(1 + random() % 128, original.size() - start);
        for (size_t i = start; i < start + length; ++i)
            original[i] = static_cast<uint8_t>(random());
        auto expected = original;
        std::copy_n(a.patch, a.length, expected.begin() + 32);
        std::copy_n(b.patch, b.length, expected.begin() + 4000);
        if (round % 2)
            hv::refresh_ept_hook(*cpu, b.id);
        hv::handle_page_access(*cpu, a.pfn << 12, true, a.target);
        EXPECT_TRUE(std::equal(expected.begin(), expected.end(),
                               cpu->shadow[cpu->hooks[0].group]));
        EXPECT_EQ(hv::get_ept_pte(*cpu, a.pfn << 12)->page_frame_number,
                  ShadowPfn());
    }
}

TEST_F(EptTest, TwoVcpusRebuildFromSharedBackingIndependently) {
    auto second = std::make_unique<hv::vcpu_ept_data>();
    ASSERT_TRUE(hv::prepare_ept(*second));
    auto hook = Hook();
    ASSERT_TRUE(hv::install_ept_hook(*cpu, hook));
    ASSERT_TRUE(hv::install_ept_hook(*second, hook));
    hv::handle_page_access(*cpu, hook.pfn << 12, true, hook.target);
    hv::handle_page_access(*second, hook.pfn << 12, true, hook.target);
    hv::handle_page_access(*cpu, hook.pfn << 12, false);
    original[2048] = 0xda;
    // A model cannot promise remote TLB coherence. Explicit refresh on both
    // vCPUs models the driver's broadcast publication contract.
    hv::refresh_ept_hook(*cpu, hook.id);
    hv::refresh_ept_hook(*second, hook.id);
    EXPECT_EQ(cpu->shadow[cpu->hooks[0].group][2048], 0xda);
    EXPECT_EQ(second->shadow[second->hooks[0].group][2048], 0xda);
    EXPECT_EQ(hv::get_ept_pte(*cpu, hook.pfn << 12)->flags & 7, 3u);
    EXPECT_EQ(hv::get_ept_pte(*second, hook.pfn << 12)->flags & 7, 3u);
}
}  // namespace ept_test
