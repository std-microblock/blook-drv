// Real-driver regression for session ownership. Runs only on demand; never
// injects into an existing process. The child below is an isolated test target.
#include <cstdio>
#include <cstring>
#include <cwchar>
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

   public:
    code_page() {
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
        if (memory_)
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

void same_process() {
    // Raw device handles are intentional: SDK hook destructors send REMOVE
    // before closing, which would hide bugs in IRP_MJ_CLEANUP / IRP_MJ_CLOSE.
    code_page page;
    auto owner = open_device(true);
    require(page.call() == 7, "original result");
    const auto id = install(owner.get(), page.address());
    require(page.call() == 42 && hook_count(owner.get()) == 1,
            "patch is armed");
    {
        // SDK read_only means no ENABLE; the ABI still requires an RW handle.
        auto observer = open_device();
        require(hook_count(observer.get()) == 1,
                "read-only observer sees patch");
    }
    const auto after = hook_count(owner.get());
    const auto result = page.call();
    std::printf("read-only close: hooks 1 -> %u; result 42 -> %d\n", after,
                result);
    require(after == 1 && result == 42,
            "closing a read-only observer revoked another session's hook");

    // Exactly the epdiag sequence: open a non-enabled RW diagnostic handle,
    // read stats/probe, then CloseHandle before executing the patched code.
    {
        auto observer = open_device();
        ipc::StatsResponse stats{};
        require(ioctl(observer.get(), ipc::IOCTL_BLOOK_STATS, nullptr, 0,
                      &stats, sizeof(stats)),
                "temporary stats query");
    }
    require(page.call() == 42, "stats handle close must preserve patch");
    {
        auto observer = open_device();
        ipc::ProbeRequest request{};
        request.header.version = ipc::abi_version;
        request.header.size = sizeof(request);
        request.address = page.address();
        ipc::ProbeResponse response{};
        require(ioctl(observer.get(), ipc::IOCTL_BLOOK_PROBE, &request,
                      sizeof(request), &response, sizeof(response)),
                "temporary address probe");
    }
    require(page.call() == 42, "probe handle close must preserve patch");
    {
        auto empty_session = open_device(true);
    }
    require(page.call() == 42,
            "empty enabled session close must preserve patch");
    {
        auto second = open_device(true);
        install(second.get(), page.address(0x80));
        require(page.call() == 42 && page.call(0x80) == 42 &&
                    hook_count(owner.get()) == 2,
                "two sessions share a physical page");
        require(!hook_command(second.get(), ipc::IOCTL_BLOOK_REMOVE, id) &&
                    GetLastError() == ERROR_ACCESS_DENIED,
                "another session cannot remove owner hook");
        require(!hook_command(second.get(), ipc::IOCTL_BLOOK_REFRESH, id) &&
                    GetLastError() == ERROR_ACCESS_DENIED,
                "another session cannot refresh owner hook");
    }
    require(page.call() == 42 && page.call(0x80) == 7 &&
                hook_count(owner.get()) == 1,
            "owner close removes only that owner's page mate");
    require(hook_command(owner.get(), ipc::IOCTL_BLOOK_REFRESH, id),
            "owner can still refresh");
    owner.reset();
    require(page.call() == 7 && page.call(0x80) == 7,
            "final owner close restores originals");
    auto observer = open_device();
    require(hook_count(observer.get()) == 0, "no hooks remain after cleanup");
    std::puts(
        "PASS: observer/stats/probe/empty-session close, independent owners, "
        "same-page cleanup");
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
    code_page page;
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

void remote_process() {
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
    require(call(1) == 42 && call(2) == 42, "remote hooks armed");
    first.reset();
    require(call(1) == 7 && call(2) == 42,
            "closing creator removes remote hooks but preserves other owners");
    // Reinstall so target exit has to clean two independent sessions.
    first = open_device(true);
    const auto new_id =
        install(first.get(), state.value->address, info.dwProcessId);
    require(new_id != first_id && call(1) == 42, "remote hook reinstalled");
    state.value->command = 3;
    require(SetEvent(request.get()) != FALSE, "request target exit");
    require(WaitForSingleObject(process.get(), 10000) == WAIT_OBJECT_0,
            "target exited");
    require(!hook_command(first.get(), ipc::IOCTL_BLOOK_REMOVE, new_id) &&
                GetLastError() == ERROR_NOT_FOUND,
            "target exit revoked first session's hook");
    require(!hook_command(second.get(), ipc::IOCTL_BLOOK_REMOVE, second_id) &&
                GetLastError() == ERROR_NOT_FOUND,
            "target exit revoked second session's hook");
    std::puts(
        "PASS: remote-owner close, other-owner isolation, target-process exit");
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 3 && std::wcscmp(argv[1], L"--child") == 0)
            return child_main(argv[2]);
        if (argc == 2 && std::wcscmp(argv[1], L"--remote") == 0) {
            remote_process();
        } else {
            same_process();
            remote_process();
        }
        std::puts("PASS: session ownership regression");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s (Win32=%lu)\n", error.what(),
                     GetLastError());
        return 1;
    }
}
