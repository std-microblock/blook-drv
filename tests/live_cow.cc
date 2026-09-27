#include "ept_live/fixture.hpp"

namespace blook::tests::ept_live {
namespace {
// Keep a genuine image-backed code page, rather than replacing the CoW
// regression with a private VirtualAlloc allocation. Volatile indirect calls
// prevent interprocedural optimization from folding the constant return.
__declspec(noinline) int image_function() {
    return 7;
}
int (*volatile image_entry)() = &image_function;
}  // namespace
class LiveCow : public EptLive {
   protected:
    void* page_{};
    DWORD original_protection_{};
    bool protection_changed_{};
    void TearDown() override {
        if (protection_changed_) {
            DWORD discarded{};
            EXPECT_TRUE(VirtualProtect(page_, page_size, original_protection_,
                                       &discarded));
        }
        EptLive::TearDown();
    }
};
TEST_F(LiveCow, ImageHookSurvivesWritableProtectionAndCopyOnWriteRebind) {
    EXPECT_EQ(image_entry(), 7);
    auto* entry = reinterpret_cast<void*>(&image_function);
    auto installed = state_->session->patch(entry, return_value(42));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    state_->hook.emplace(std::move(*installed));
    ASSERT_EQ(image_entry(), 42);
    page_ = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(entry) &
                                    ~uintptr_t{0xfff});
    ASSERT_TRUE(VirtualProtect(page_, page_size, PAGE_EXECUTE_READWRITE,
                               &original_protection_));
    protection_changed_ = true;
    DWORD discarded{};
    ASSERT_TRUE(
        VirtualProtect(page_, page_size, PAGE_EXECUTE_READ, &discarded));
    EXPECT_EQ(image_entry(), 42)
        << "Hook lost after image-page CoW/protection transition";
    ASSERT_TRUE(Remove());
    EXPECT_EQ(image_entry(), 7);
}
}  // namespace blook::tests::ept_live
