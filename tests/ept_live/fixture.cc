#include "fixture.hpp"

#include <atomic>
#include <cstring>

namespace blook::tests::ept_live {
namespace {
// A failed remove means the machine may still have a live hook. Do not keep
// installing more hooks in the same process, even with --gtest_repeat.
std::atomic<bool> cleanup_failed{false};
}  // namespace

stub return_value(uint32_t value) {
    stub bytes{0xb8, 0, 0, 0, 0, 0xc3};  // mov eax,imm32; ret
    std::memcpy(bytes.data() + 1, &value, sizeof(value));
    return bytes;
}

EptLive::resources::~resources() {
    // Defensive fallback as well as TearDown: never free memory when removal
    // has not been positively acknowledged. The hook destructor is best effort.
    if (hook && *hook) {
        if (!hook->remove()) {
            cleanup_failed.store(true);
            return;  // deliberately retain the allocation
        }
    }
    if (memory)
        VirtualFree(memory, 0, MEM_RELEASE);
}

void EptLive::MarkCleanupFailed() {
    cleanup_failed.store(true);
}

void EptLive::SetUp() {
    wchar_t value[2]{};
    if (GetEnvironmentVariableW(L"BLOOK_EPT_LIVE", value, 2) != 1 ||
        value[0] != L'1') {
        GTEST_SKIP()
            << "Real-driver EPT tests disabled; isolated supported Intel "
               "x64 host only: explicitly set BLOOK_EPT_LIVE=1.";
    }
    ASSERT_FALSE(cleanup_failed.load())
        << "Earlier hook removal failed; refusing further live tests.";
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    ASSERT_EQ(info.dwPageSize, page_size);
    ASSERT_EQ(sizeof(void*), 8u) << "These stubs require Windows x64.";

    state_ = std::make_unique<resources>();
    auto opened = client::session::open();
    ASSERT_TRUE(opened.has_value())
        << "Opt-in requires a preloaded, supported driver: "
        << opened.error().message();
    state_->session.emplace(std::move(*opened));
    const auto info_result = state_->session->query();
    ASSERT_TRUE(info_result.has_value()) << info_result.error().message();
    ASSERT_TRUE(info_result->running)
        << "Hypervisor not running; backend status="
        << info_result->backend_status;
    ASSERT_TRUE(info_result->enabled);
}

void EptLive::TearDown() {
    if (!state_)
        return;
    if (state_->hook && *state_->hook) {
        const auto removed = state_->hook->remove();
        if (!removed) {
            cleanup_failed.store(true);
            ADD_FAILURE()
                << "REMOVE failed: " << removed.error().message()
                << "; retaining hook, connection and backing allocation "
                   "until process exit. Stop live testing this machine.";
            (void)state_.release();
            return;
        }
    }
    state_.reset();
}

::testing::AssertionResult EptLive::Allocate(size_t pages) {
    if (state_->memory)
        return ::testing::AssertionFailure() << "Fixture already allocated";
    state_->size = pages * page_size;
    state_->memory = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, state_->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!state_->memory)
        return ::testing::AssertionFailure()
               << "VirtualAlloc: " << GetLastError();
    std::memset(state_->memory, 0x90, state_->size);
    return ::testing::AssertionSuccess();
}

::testing::AssertionResult EptLive::Protect(DWORD protection) {
    DWORD old{};
    if (!VirtualProtect(state_->memory, state_->size, protection, &old))
        return ::testing::AssertionFailure()
               << "VirtualProtect: " << GetLastError();
    return ::testing::AssertionSuccess();
}

::testing::AssertionResult EptLive::Publish() {
    const auto protected_rx = Protect(PAGE_EXECUTE_READ);
    if (!protected_rx)
        return protected_rx;
    if (!FlushInstructionCache(GetCurrentProcess(), state_->memory,
                               state_->size))
        return ::testing::AssertionFailure()
               << "FlushInstructionCache: " << GetLastError();
    return ::testing::AssertionSuccess();
}

::testing::AssertionResult EptLive::Install(size_t offset,
                                            std::span<const uint8_t> bytes) {
    if (state_->hook && *state_->hook)
        return ::testing::AssertionFailure() << "Fixture already owns a hook";
    auto installed = state_->session->patch(state_->memory + offset, bytes);
    if (!installed)
        return ::testing::AssertionFailure()
               << "INSTALL: " << installed.error().message();
    state_->hook.emplace(std::move(*installed));
    if (!*state_->hook)
        return ::testing::AssertionFailure() << "INSTALL returned a zero id";
    return ::testing::AssertionSuccess();
}

::testing::AssertionResult EptLive::Refresh() {
    const auto refreshed = state_->hook->refresh();
    if (!refreshed)
        return ::testing::AssertionFailure()
               << "REFRESH: " << refreshed.error().message();
    return ::testing::AssertionSuccess();
}

::testing::AssertionResult EptLive::Remove() {
    const auto removed = state_->hook->remove();
    if (!removed)
        return ::testing::AssertionFailure()
               << "REMOVE: " << removed.error().message();
    return ::testing::AssertionSuccess();
}

void EptLive::Write(size_t offset, std::span<const uint8_t> bytes) {
    std::memcpy(state_->memory + offset, bytes.data(), bytes.size());
}

int EptLive::Execute(size_t offset) const {
    return reinterpret_cast<int (*)()>(state_->memory + offset)();
}

std::vector<uint8_t> EptLive::Read(size_t offset, size_t length) const {
    std::vector<uint8_t> bytes(length);
    // Volatile loads prevent optimization from substituting the bytes written
    // by the test: every assertion really observes the hooked data mapping.
    const volatile uint8_t* source = state_->memory + offset;
    for (size_t i = 0; i < length; ++i)
        bytes[i] = source[i];
    return bytes;
}
}  // namespace blook::tests::ept_live
