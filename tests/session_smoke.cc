// Real-driver regression for session ownership. Runs only on demand; never
// injects into an existing process. The child below is an isolated test target.
#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <cwchar>
#include <memory>
#include <stdexcept>
#include <string>

#include "client/handle.hpp"
#include "ipc/protocol.hpp"

namespace {
using blook::client::unique_handle;

void require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

bool ioctl(HANDLE device, DWORD code, const void* input, DWORD input_size,
           void* output = nullptr, DWORD output_size = 0) {
    DWORD returned{};
    return DeviceIoControl(device, code, const_cast<void*>(input), input_size,
                           output, output_size, &returned, nullptr) &&
           returned == output_size;
}

unique_handle open_device(bool enabled = false) {
    unique_handle device{CreateFileW(ipc::kUserModePath,
                                     GENERIC_READ | GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     nullptr, OPEN_EXISTING, 0, nullptr)};
    require(static_cast<bool>(device),
            "open driver (requires loaded driver and device access)");
    if (enabled) {
        const auto request = ipc::request<ipc::EnableRequest>();
        require(ioctl(device.get(), ipc::IOCTL_BLOOK_ENABLE, &request,
                      sizeof(request)),
                "enable session");
    }
    return device;
}

uint32_t hook_count(HANDLE device) {
    ipc::QueryResponse response{};
    require(ioctl(device, ipc::IOCTL_BLOOK_QUERY, nullptr, 0, &response,
                  sizeof(response)),
            "query active hooks");
    return response.hooks;
}

uint64_t install(HANDLE device, uint64_t address, uint32_t pid = 0) {
    auto request = ipc::request<ipc::InstallRequest>();
    request.target = address;
    request.pid = pid;
    const uint8_t code[] = {0xb8, 42, 0, 0, 0, 0xc3};  // mov eax,42; ret
    request.length = sizeof(code);
    std::memcpy(request.bytes, code, sizeof(code));
    ipc::InstallResponse response{};
    require(ioctl(device, ipc::IOCTL_BLOOK_INSTALL, &request, sizeof(request),
                  &response, sizeof(response)),
            "install patch");
    return response.id;
}

bool hook_command(HANDLE device, DWORD code, uint64_t id) {
    auto request = ipc::request<ipc::HookRequest>();
    request.id = id;
    return ioctl(device, code, &request, sizeof(request));
}

class code_page {
    uint8_t* memory_{};
    bool process_lifetime_{};

   public:
    explicit code_page(bool process_lifetime = false)
        : process_lifetime_(process_lifetime) {
        memory_ = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        require(memory_ != nullptr, "allocate test code");
        const uint8_t code[] = {0xb8, 7, 0, 0, 0, 0xc3};  // mov eax,7; ret
        std::memcpy(memory_, code, sizeof(code));
        std::memcpy(memory_ + 0x80, code, sizeof(code));
        DWORD old{};
        if (!VirtualProtect(memory_, 4096, PAGE_EXECUTE_READ, &old) ||
            !FlushInstructionCache(GetCurrentProcess(), memory_, 4096)) {
            VirtualFree(memory_, 0, MEM_RELEASE);
            memory_ = nullptr;
            throw std::runtime_error("make test code executable");
        }
    }
    ~code_page() {
        // The child deliberately leaves its backing mapped until process
        // teardown: target-exit cleanup must run while hooks still have
        // backing.
        if (memory_ && !process_lifetime_)
            VirtualFree(memory_, 0, MEM_RELEASE);
    }
    code_page(const code_page&) = delete;
    uint64_t address(size_t offset = 0) const {
        return reinterpret_cast<uint64_t>(memory_ + offset);
    }
    int call(size_t offset = 0) const {
        return reinterpret_cast<int (*)()>(memory_ + offset)();
    }
};

class SessionSmoke : public ::testing::Test {
   protected:
    void SetUp() override {
        wchar_t enabled[2]{};
        if (GetEnvironmentVariableW(L"BLOOK_EPT_LIVE", enabled, 2) != 1 ||
            enabled[0] != L'1') {
            GTEST_SKIP() << "Real-driver tests require BLOOK_EPT_LIVE=1";
        }
    }
};

class LocalSessionSmoke : public SessionSmoke {
   protected:
    // Backing is constructed before handles and destroyed after them, including
    // fatal assertions and exceptions. Do not move it into individual tests.
    std::unique_ptr<code_page> page;
    unique_handle owner;
    uint64_t id{};

    void SetUp() override {
        SessionSmoke::SetUp();
        if (IsSkipped())
            return;
        page = std::make_unique<code_page>();
        owner = open_device(true);
        ASSERT_EQ(page->call(), 7);
        id = install(owner.get(), page->address());
        ASSERT_EQ(page->call(), 42);
        ASSERT_EQ(hook_count(owner.get()), 1u);
    }

    void TearDown() override {
        owner.reset();
        page.reset();
    }
};

TEST_F(LocalSessionSmoke, ObserverClosePreservesOwnerHook) {
    // Raw device handles are intentional: SDK hook destructors send REMOVE
    // before closing, which would hide bugs in IRP_MJ_CLEANUP / IRP_MJ_CLOSE.
    {
        // SDK read_only means no ENABLE; the ABI still requires an RW handle.
        auto observer = open_device();
        EXPECT_EQ(hook_count(observer.get()), 1u);
    }
    EXPECT_EQ(hook_count(owner.get()), 1u);
    EXPECT_EQ(page->call(), 42);
}

TEST_F(LocalSessionSmoke, StatsHandleClosePreservesOwnerHook) {
    // Exactly the epdiag sequence: query on a non-enabled RW handle, close it,
    // then execute patched code.
    {
        auto observer = open_device();
        ipc::StatsResponse stats{};
        ASSERT_TRUE(ioctl(observer.get(), ipc::IOCTL_BLOOK_STATS, nullptr, 0,
                          &stats, sizeof(stats)));
    }
    EXPECT_EQ(page->call(), 42);
}

TEST_F(LocalSessionSmoke, ProbeHandleClosePreservesOwnerHook) {
    {
        auto observer = open_device();
        ipc::ProbeRequest request{};
        request.header.version = ipc::abi_version;
        request.header.size = sizeof(request);
        request.address = page->address();
        ipc::ProbeResponse response{};
        ASSERT_TRUE(ioctl(observer.get(), ipc::IOCTL_BLOOK_PROBE, &request,
                          sizeof(request), &response, sizeof(response)));
    }
    EXPECT_EQ(page->call(), 42);
}

TEST_F(LocalSessionSmoke, EmptyEnabledSessionClosePreservesOwnerHook) {
    {
        auto empty_session = open_device(true);
    }
    EXPECT_EQ(page->call(), 42);
}

TEST_F(LocalSessionSmoke, SamePageOwnersAreIsolatedAndCleanedUp) {
    {
        auto second = open_device(true);
        install(second.get(), page->address(0x80));
        ASSERT_EQ(page->call(), 42);
        ASSERT_EQ(page->call(0x80), 42);
        ASSERT_EQ(hook_count(owner.get()), 2u);
        const bool removed =
            hook_command(second.get(), ipc::IOCTL_BLOOK_REMOVE, id);
        const DWORD remove_error = GetLastError();
        EXPECT_FALSE(removed);
        EXPECT_EQ(remove_error, ERROR_ACCESS_DENIED);
        const bool refreshed =
            hook_command(second.get(), ipc::IOCTL_BLOOK_REFRESH, id);
        const DWORD refresh_error = GetLastError();
        EXPECT_FALSE(refreshed);
        EXPECT_EQ(refresh_error, ERROR_ACCESS_DENIED);
    }
    EXPECT_EQ(page->call(), 42);
    EXPECT_EQ(page->call(0x80), 7);
    EXPECT_EQ(hook_count(owner.get()), 1u);
    EXPECT_TRUE(hook_command(owner.get(), ipc::IOCTL_BLOOK_REFRESH, id));
    owner.reset();
    EXPECT_EQ(page->call(), 7);
    EXPECT_EQ(page->call(0x80), 7);
    auto observer = open_device();
    EXPECT_EQ(hook_count(observer.get()), 0u);
}

struct child_state {
    uint64_t address{};
    LONG command{};  // 1 = execute first function, 2 = second, 3 = exit
    int result{};
};

struct mapped_state {
    child_state* value{};
    ~mapped_state() {
        if (value)
            UnmapViewOfFile(value);
    }
};

int child_main(const wchar_t* name) {
    const std::wstring base{name};
    unique_handle mapping{OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name)};
    unique_handle request{
        OpenEventW(SYNCHRONIZE, FALSE, (base + L"-request").c_str())};
    unique_handle response{
        OpenEventW(EVENT_MODIFY_STATE, FALSE, (base + L"-response").c_str())};
    require(mapping && request && response, "child opens test channel");
    mapped_state state{static_cast<child_state*>(MapViewOfFile(
        mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, sizeof(child_state)))};
    require(state.value != nullptr, "child maps channel");
    code_page page{/*process_lifetime=*/true};
    state.value->address = page.address();
    require(SetEvent(response.get()) != FALSE, "child ready");
    while (WaitForSingleObject(request.get(), 15000) == WAIT_OBJECT_0) {
        if (state.value->command == 3)
            return 0;
        state.value->result = page.call(state.value->command == 2 ? 0x80 : 0);
        require(SetEvent(response.get()) != FALSE, "child response");
    }
    return 2;  // Parent died or stopped making progress; never linger
               // indefinitely.
}

TEST_F(SessionSmoke, RemoteOwnerCloseAndTargetExit) {
    const auto base = L"Local\\blook-session-smoke-" +
                      std::to_wstring(GetCurrentProcessId()) + L"-" +
                      std::to_wstring(GetTickCount64());
    unique_handle mapping{
        CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                           sizeof(child_state), base.c_str())};
    unique_handle request{
        CreateEventW(nullptr, FALSE, FALSE, (base + L"-request").c_str())};
    unique_handle response{
        CreateEventW(nullptr, FALSE, FALSE, (base + L"-response").c_str())};
    require(mapping && request && response, "create test channel");
    mapped_state state{static_cast<child_state*>(MapViewOfFile(
        mapping.get(), FILE_MAP_ALL_ACCESS, 0, 0, sizeof(child_state)))};
    require(state.value != nullptr, "map test channel");
    wchar_t path[32768]{};
    require(GetModuleFileNameW(nullptr, path, 32768) != 0,
            "locate test executable");
    std::wstring command =
        L"\"" + std::wstring(path) + L"\" --child \"" + base + L"\"";
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION info{};
    require(CreateProcessW(path, command.data(), nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                           &info) != FALSE,
            "launch isolated target");
    unique_handle process{info.hProcess}, thread{info.hThread};
    struct stop_child {
        HANDLE process;
        ~stop_child() {
            if (WaitForSingleObject(process, 0) != WAIT_OBJECT_0) {
                TerminateProcess(process,
                                 2);  // Only the process created by this test.
                WaitForSingleObject(process, 10000);
            }
        }
    } cleanup{process.get()};
    const HANDLE waits[] = {response.get(), process.get()};
    auto wait_response = [&] {
        require(WaitForMultipleObjects(2, waits, FALSE, 10000) == WAIT_OBJECT_0,
                "target response (timeout or child exited)");
    };
    wait_response();
    auto call = [&](LONG which) {
        state.value->command = which;
        require(SetEvent(request.get()) != FALSE, "request remote call");
        wait_response();
        return state.value->result;
    };
    auto first = open_device(true);
    auto second = open_device(true);
    const auto first_id =
        install(first.get(), state.value->address, info.dwProcessId);
    const auto second_id =
        install(second.get(), state.value->address + 0x80, info.dwProcessId);
    ASSERT_EQ(call(1), 42);
    ASSERT_EQ(call(2), 42);
    first.reset();
    EXPECT_EQ(call(1), 7);
    EXPECT_EQ(call(2), 42);
    // Reinstall so target exit has to clean two independent sessions.
    first = open_device(true);
    const auto new_id =
        install(first.get(), state.value->address, info.dwProcessId);
    EXPECT_NE(new_id, first_id);
    ASSERT_EQ(call(1), 42);
    state.value->command = 3;
    ASSERT_NE(SetEvent(request.get()), FALSE);
    ASSERT_EQ(WaitForSingleObject(process.get(), 10000), WAIT_OBJECT_0);
    DWORD exit_code{};
    ASSERT_NE(GetExitCodeProcess(process.get(), &exit_code), FALSE);
    EXPECT_EQ(exit_code, 0u);
    const bool removed_first =
        hook_command(first.get(), ipc::IOCTL_BLOOK_REMOVE, new_id);
    const DWORD first_error = GetLastError();
    EXPECT_FALSE(removed_first);
    EXPECT_EQ(first_error, ERROR_NOT_FOUND);
    const bool removed_second =
        hook_command(second.get(), ipc::IOCTL_BLOOK_REMOVE, second_id);
    const DWORD second_error = GetLastError();
    EXPECT_FALSE(removed_second);
    EXPECT_EQ(second_error, ERROR_NOT_FOUND);
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 3 && std::wcscmp(argv[1], L"--child") == 0)
            return child_main(argv[2]);
        // Preserve the legacy alias while allowing normal GoogleTest flags.
        // --remote is equivalent to --gtest_filter=SessionSmoke.Remote*.
        bool remote_only = false;
        int output = 1;
        for (int index = 1; index < argc; ++index) {
            if (std::wcscmp(argv[index], L"--remote") == 0)
                remote_only = true;
            else
                argv[output++] = argv[index];
        }
        argc = output;
        argv[argc] = nullptr;
        ::testing::InitGoogleTest(&argc, argv);
        if (remote_only)
            GTEST_FLAG_SET(filter, "SessionSmoke.Remote*");
        return RUN_ALL_TESTS();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s (Win32=%lu)\n", error.what(),
                     GetLastError());
        return 1;
    }
}
