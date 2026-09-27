#include "fixture.hpp"

namespace blook::tests::ept_live {
namespace {
// Keep SEH in a leaf with no C++ objects requiring unwinding (/EHsc
// compatible). Capture only the requested architectural fault: other faults
// must fail the isolated test process instead of being hidden by an
// EXCEPTION_EXECUTE_HANDLER.
DWORD ExecuteAndCatch(void* code, DWORD expected, int* returned) {
    __try {
        *returned = reinterpret_cast<int (*)()>(code)();
        return 0;
    } __except (GetExceptionCode() == expected ? EXCEPTION_EXECUTE_HANDLER
                                               : EXCEPTION_CONTINUE_SEARCH) {
        return GetExceptionCode();
    }
}
}  // namespace

TEST_F(EptLive, IllegalInstructionInShadowReachesGuestExceptionHandler) {
    ASSERT_TRUE(Allocate());
    Write(0, return_value(7));
    ASSERT_TRUE(Publish());
    // UD2 must be injected to the guest as #UD, not turn into a root-mode
    // fatal.
    const std::array<uint8_t, 2> fault{0x0f, 0x0b};
    ASSERT_TRUE(Install(0, fault));
    int returned = -1;
    EXPECT_EQ(ExecuteAndCatch(state_->memory, EXCEPTION_ILLEGAL_INSTRUCTION,
                              &returned),
              EXCEPTION_ILLEGAL_INSTRUCTION);
    EXPECT_EQ(returned, -1);
    const auto original = return_value(7);
    EXPECT_EQ(Read(0, 6),
              std::vector<uint8_t>(original.begin(), original.end()));
    ASSERT_TRUE(Remove());
    EXPECT_EQ(Execute(), 7);
    ASSERT_TRUE(Install(0, return_value(42)));
    EXPECT_EQ(Execute(), 42);
    ASSERT_TRUE(Remove());
    EXPECT_EQ(Execute(), 7);
}

TEST_F(EptLive, AccessViolationInShadowReachesGuestExceptionHandler) {
    ASSERT_TRUE(Allocate(2));
    Write(0, return_value(7));
    // mov rax, guard_address; mov eax,[rax]; ret. The data page is distinct
    // from the execute page so this specifically tests guest #PF forwarding.
    std::array<uint8_t, 13> fault{0x48, 0xb8};
    const auto guard = reinterpret_cast<uintptr_t>(state_->memory + page_size);
    std::memcpy(fault.data() + 2, &guard, sizeof(guard));
    fault[10] = 0x8b;
    fault[11] = 0x00;
    fault[12] = 0xc3;
    ASSERT_TRUE(Publish());
    DWORD old{};
    ASSERT_TRUE(VirtualProtect(state_->memory + page_size, page_size,
                               PAGE_NOACCESS, &old));
    ASSERT_TRUE(Install(0, fault));
    int returned = -1;
    EXPECT_EQ(
        ExecuteAndCatch(state_->memory, EXCEPTION_ACCESS_VIOLATION, &returned),
        EXCEPTION_ACCESS_VIOLATION);
    EXPECT_EQ(returned, -1);
    ASSERT_TRUE(Remove());
    EXPECT_EQ(Execute(), 7);
    ASSERT_TRUE(Install(0, return_value(42)));
    EXPECT_EQ(Execute(), 42);
    ASSERT_TRUE(Remove());
    EXPECT_EQ(Execute(), 7);
}
}  // namespace blook::tests::ept_live
