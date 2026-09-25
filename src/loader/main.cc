#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <string>
#include <vector>

#include "client/ept.hpp"

namespace {
class service_handle final {
    SC_HANDLE value_{};

   public:
    explicit service_handle(SC_HANDLE value) : value_(value) {}
    ~service_handle() {
        if (value_)
            CloseServiceHandle(value_);
    }
    service_handle(const service_handle&) = delete;
    SC_HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ != nullptr; }
};

int error(const char* action) {
    std::fprintf(stderr, "%s failed: %lu\n", action, GetLastError());
    return 1;
}

void usage() {
    std::puts(
        "Blook Intel EPT analysis driver\n"
        "  blook-loader install <absolute-path-to-signed.sys>\n"
        "  blook-loader start | stop | uninstall\n"
        "  blook-loader ping | version | status\n"
        "  blook-loader hide on|off | hide windows on|off\n"
        "  blook-loader pin tool|target <pid> | unpin <pid>\n"
        "  blook-loader apply [blook.ini]\n"
        "  blook-loader scrub <pid>\n"
        "  blook-loader hook <self|pid> <hex-address> <hex-bytes>\n"
        "Session commands need the driver started and this process elevated.");
}

std::vector<uint8_t> parse_bytes(const std::wstring& text) {
    std::vector<uint8_t> bytes;
    if (text.empty() || text.size() % 2)
        return bytes;
    for (size_t i = 0; i + 1 < text.size(); i += 2) {
        const wchar_t pair[3] = {text[i], text[i + 1], 0};
        wchar_t* end{};
        const auto value = wcstoul(pair, &end, 16);
        if (!end || *end)
            return {};
        bytes.push_back(static_cast<uint8_t>(value));
    }
    return bytes;
}

int service_command(const std::wstring& command, int argc, wchar_t** argv) {
    service_handle scm{OpenSCManagerW(
        nullptr, nullptr,
        SC_MANAGER_CONNECT |
            (command == L"install" ? SC_MANAGER_CREATE_SERVICE : 0))};
    if (!scm)
        return error("OpenSCManager");
    if (command == L"install") {
        if (argc != 3) {
            usage();
            return 1;
        }
        wchar_t absolute[32768];
        const auto length = GetFullPathNameW(argv[2], 32768, absolute, nullptr);
        if (!length || length >= 32768 ||
            GetFileAttributesW(absolute) == INVALID_FILE_ATTRIBUTES)
            return error("Driver path");
        // NtLoadDriver rejects a bare DOS image path: SCM accepts the create
        // call and StartService then fails with ERROR_INVALID_NAME (123). The
        // path is stored in NT form, which is also what a driver installed by
        // hand looks like (\??\C:\path\to\driver.sys).
        std::wstring image_path = L"\\??\\" + std::wstring{absolute};
        service_handle service{CreateServiceW(
            scm.get(), L"BlookDrv", L"Blook Intel EPT analysis driver",
            SERVICE_QUERY_STATUS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, image_path.c_str(), nullptr, nullptr, nullptr,
            nullptr, nullptr)};
        if (!service)
            return error(
                "CreateService (an existing service is not overwritten)");
        std::puts("Installed, NOT started.");
        return 0;
    }
    const DWORD access = command == L"start" ? SERVICE_START
                         : command == L"stop"
                             ? SERVICE_STOP | SERVICE_QUERY_STATUS
                             : DELETE | SERVICE_QUERY_STATUS;
    service_handle service{OpenServiceW(scm.get(), L"BlookDrv", access)};
    if (!service)
        return error("OpenService");
    if (command == L"start") {
        if (!StartServiceW(service.get(), 0, nullptr))
            return error("StartService");
        std::puts("Started.");
        return 0;
    }
    SERVICE_STATUS status{};
    if (command == L"stop") {
        if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &status) &&
            GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
            return error("ControlService");
        const auto deadline = GetTickCount64() + 30000;
        do {
            if (!QueryServiceStatus(service.get(), &status))
                return error("QueryServiceStatus");
            if (status.dwCurrentState == SERVICE_STOPPED) {
                std::puts("Stopped.");
                return 0;
            }
            Sleep(100);
        } while (GetTickCount64() < deadline);
        std::fputs("Timed out waiting for stop; the service was not deleted.\n",
                   stderr);
        return 1;
    }
    if (!QueryServiceStatus(service.get(), &status))
        return error("QueryServiceStatus");
    if (status.dwCurrentState != SERVICE_STOPPED) {
        std::fputs("Stop the driver before uninstalling.\n", stderr);
        return 1;
    }
    if (!DeleteService(service.get()))
        return error("DeleteService");
    std::puts("Service removed; the driver file is left untouched.");
    return 0;
}

// ---------------------------------------------------------------------------
// blook.ini
//
//   [device] allow_users = true           -> service key AllowUsers (DWORD)
//   [hooks]  hook_mask / window_hook_mask -> HookMask / WindowHookMask (DWORD)
//   [roles]  tool / target                -> pin tool / pin target
//
// Device values are read by the driver when it starts; roles need the driver
// running and are pinned right away. Names are matched against the image name
// of every running process, pids are pinned directly.
std::wstring trimmed(std::wstring text) {
    const auto space = [](wchar_t c) { return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n'; };
    while (!text.empty() && space(text.front())) text.erase(text.begin());
    while (!text.empty() && space(text.back())) text.pop_back();
    return text;
}
std::wstring lowered(std::wstring text) {
    for (auto& c : text)
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    return text;
}
std::vector<std::wstring> split_list(const std::wstring& text) {
    std::vector<std::wstring> items;
    std::wstring current;
    for (const wchar_t c : text) {
        if (c == L',' || c == L';') {
            const auto item = trimmed(current);
            if (!item.empty()) items.push_back(item);
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    const auto item = trimmed(current);
    if (!item.empty()) items.push_back(item);
    return items;
}
bool all_digits(const std::wstring& text) {
    if (text.empty()) return false;
    for (const wchar_t c : text)
        if (c < L'0' || c > L'9') return false;
    return true;
}
struct config {
    bool have_allow_users{}, allow_users{};
    bool have_hook_mask{}, have_window_mask{};
    uint32_t hook_mask{}, window_hook_mask{};
    std::vector<std::wstring> tools, targets;
};
bool read_config(const std::wstring& path, config& out) {
    std::string bytes;
    if (auto* file = _wfopen(path.c_str(), L"rb")) {
        char buffer[4096];
        size_t got = 0;
        while ((got = std::fread(buffer, 1, sizeof(buffer), file)) > 0) bytes.append(buffer, got);
        std::fclose(file);
    } else {
        return false;
    }
    if (bytes.size() >= 3 && static_cast<unsigned char>(bytes[0]) == 0xef &&
        static_cast<unsigned char>(bytes[1]) == 0xbb && static_cast<unsigned char>(bytes[2]) == 0xbf)
        bytes.erase(0, 3);
    const auto length = MultiByteToWideChar(CP_UTF8, 0, bytes.data(),
                                            static_cast<int>(bytes.size()), nullptr, 0);
    std::wstring text(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()),
                        text.data(), length);

    std::wstring section;
    size_t start = 0;
    while (start <= text.size()) {
        const auto end = text.find(L'\n', start);
        auto line = trimmed(text.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start));
        start = end == std::wstring::npos ? text.size() + 1 : end + 1;
        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;
        if (line.front() == L'[' && line.back() == L']') {
            section = lowered(trimmed(line.substr(1, line.size() - 2)));
            continue;
        }
        const auto equals = line.find(L'=');
        if (equals == std::wstring::npos) continue;
        const auto key = lowered(trimmed(line.substr(0, equals)));
        const auto value = trimmed(line.substr(equals + 1));
        if (section == L"device" && key == L"allow_users") {
            out.have_allow_users = true;
            out.allow_users = !(value == L"0" || lowered(value) == L"false" || lowered(value) == L"no");
        } else if (section == L"hooks" && key == L"hook_mask") {
            out.have_hook_mask = true;
            out.hook_mask = static_cast<uint32_t>(wcstoul(value.c_str(), nullptr, 0));
        } else if (section == L"hooks" && key == L"window_hook_mask") {
            out.have_window_mask = true;
            out.window_hook_mask = static_cast<uint32_t>(wcstoul(value.c_str(), nullptr, 0));
        } else if (section == L"roles" && key == L"tool") {
            const auto items = split_list(value);
            out.tools.insert(out.tools.end(), items.begin(), items.end());
        } else if (section == L"roles" && key == L"target") {
            const auto items = split_list(value);
            out.targets.insert(out.targets.end(), items.begin(), items.end());
        }
    }
    return true;
}
int pin_roles(const config& cfg) {
    auto session = blook::client::session::open();
    if (!session) {
        std::fprintf(stderr, "Roles skipped: cannot open the driver (%lu).\n", session.error());
        return 1;
    }
    std::vector<std::pair<uint32_t, std::wstring>> running;
    if (const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                running.emplace_back(entry.th32ProcessID, lowered(entry.szExeFile));
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    uint32_t pinned = 0;
    const auto pin_one = [&](uint32_t pid, uint32_t role) {
        if (!pid) return;
        if (auto status = session->pin(pid, role)) {
            ++pinned;
            std::printf("  pinned %lu as %s\n", pid,
                        role == ipc::hide_role_tool ? "tool" : "target");
        } else {
            std::fprintf(stderr, "  pin %lu failed: %lu\n", pid, status.error());
        }
    };
    const auto apply_role = [&](const std::vector<std::wstring>& wanted, uint32_t role) {
        for (const auto& want : wanted) {
            if (all_digits(want)) {
                pin_one(static_cast<uint32_t>(wcstoul(want.c_str(), nullptr, 10)), role);
                continue;
            }
            const auto name = lowered(want);
            for (const auto& [pid, image] : running)
                if (image == name) pin_one(pid, role);
        }
    };
    apply_role(cfg.tools, ipc::hide_role_tool);
    apply_role(cfg.targets, ipc::hide_role_target);
    std::printf("Roles applied (%u pinned).\n", pinned);
    return 0;
}
int apply_command(const std::wstring& path) {
    config cfg{};
    if (!read_config(path, cfg)) {
        std::fwprintf(stderr, L"Cannot read %ls\n", path.c_str());
        return 1;
    }
    HKEY key{};
    const auto opened = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                                        L"SYSTEM\\CurrentControlSet\\Services\\BlookDrv",
                                        0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr);
    if (opened != ERROR_SUCCESS) {
        std::fprintf(stderr, "Cannot open the service key (needs elevation): %lu\n", opened);
    } else {
        const auto set_dword = [&](const wchar_t* name, uint32_t value) {
            RegSetValueExW(key, name, 0, REG_DWORD,
                           reinterpret_cast<const BYTE*>(&value), sizeof(value));
        };
        if (cfg.have_allow_users) set_dword(L"AllowUsers", cfg.allow_users ? 1u : 0u);
        if (cfg.have_hook_mask) set_dword(L"HookMask", cfg.hook_mask);
        if (cfg.have_window_mask) set_dword(L"WindowHookMask", cfg.window_hook_mask);
        RegCloseKey(key);
        std::puts("Device settings written; they take effect when the driver starts.");
    }
    if (cfg.tools.empty() && cfg.targets.empty()) return 0;
    return pin_roles(cfg);
}

int session_command(const std::wstring& command, int argc, wchar_t** argv) {
    // Reported before the driver is touched so it also works on a machine
    // where the driver is not loaded at all.
    // version is answered before the driver is touched, so this also works
    // on a machine where the driver is not loaded at all.
    if (command == L"version") {
        std::printf("Client ABI: %u\n", ipc::abi_version);
        std::fflush(stdout);
    }
    auto session = blook::client::session::open();
    if (!session) {
        SetLastError(session.error());
        return error("Open driver");
    }

    if (command == L"hide") {
        if (argc != 3 && argc != 4) {
            usage();
            return 1;
        }
        const bool windows = argc == 4 && std::wstring{argv[2]} == L"windows";
        if (argc == 4 && !windows) {
            usage();
            return 1;
        }
        const std::wstring mode{argv[argc - 1]};
        if (mode != L"on" && mode != L"off") {
            usage();
            return 1;
        }
        const bool enable = mode == L"on";
        auto status = windows ? session->hide_windows(enable) : session->hide(enable);
        if (!status) {
            SetLastError(status.error());
            return error("Hide profile");
        }
        std::printf("Hide profile %s%s.\n", windows ? "windows " : "",
                    enable ? "active" : "inactive");
        return 0;
    }
    if (command == L"pin") {
        if (argc != 4) {
            usage();
            return 1;
        }
        const std::wstring role{argv[2]};
        const auto pid = static_cast<uint32_t>(wcstoul(argv[3], nullptr, 10));
        const auto value = role == L"tool"     ? ipc::hide_role_tool
                           : role == L"target" ? ipc::hide_role_target
                                               : 0u;
        if (!pid || !value) {
            usage();
            return 1;
        }
        auto status = session->pin(pid, value);
        if (!status) {
            SetLastError(status.error());
            return error("Pin process");
        }
        std::printf("Pinned %u as %s.\n", pid,
                    value == ipc::hide_role_tool ? "tool" : "target");
        return 0;
    }
    if (command == L"unpin") {
        if (argc != 3) {
            usage();
            return 1;
        }
        auto status = session->unpin(
            static_cast<uint32_t>(wcstoul(argv[2], nullptr, 10)));
        if (!status) {
            SetLastError(status.error());
            return error("Unpin process");
        }
        std::puts("Unpinned.");
        return 0;
    }
    if (command == L"scrub") {
        if (argc != 3) {
            usage();
            return 1;
        }
        const auto pid = static_cast<uint32_t>(wcstoul(argv[2], nullptr, 10));
        auto status = session->scrub(pid);
        if (!status) {
            SetLastError(status.error());
            return error("Scrub process");
        }
        std::printf("Scrubbed %u.\n", pid);
        return 0;
    }
    if (command == L"hook") {
        if (argc != 5) {
            usage();
            return 1;
        }
        const std::wstring owner{argv[2]};
        const auto pid =
            owner == L"self"
                ? 0u
                : static_cast<uint32_t>(wcstoul(argv[2], nullptr, 10));
        auto* address = reinterpret_cast<void*>(wcstoull(argv[3], nullptr, 16));
        const auto bytes = parse_bytes(argv[4]);
        if (!address || bytes.empty() || bytes.size() > 64) {
            usage();
            return 1;
        }
        auto installed = session->patch(pid, address, bytes);
        if (!installed) {
            SetLastError(installed.error());
            return error("Install EPT hook");
        }
        std::printf("Hook %llu installed in %s.\n",
                    static_cast<unsigned long long>(installed->id()),
                    pid ? "the target process" : "this process");
        std::puts("Press Enter to remove it.");
        (void)std::getchar();
        return 0;
    }

    auto status = session->query();
    if (!status) {
        SetLastError(status.error());
        return error("Query driver");
    }
    std::printf(
        "Driver ABI: %u; VMX running: %u; session enabled: %u; hooks: %u; "
        "hide profile: %u; window hooks: %u; backend NTSTATUS: 0x%08x\n",
        status->version, status->running, status->enabled, status->hooks,
        status->hidden, status->window_hooks, static_cast<unsigned>(status->backend_status));
    return status->running ? 0 : 2;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        usage();
        return 1;
    }
    const std::wstring command{argv[1]};
    if (command == L"help" || command == L"--help") {
        usage();
        return 0;
    }
    if (command == L"install" || command == L"start" || command == L"stop" ||
        command == L"uninstall")
        return service_command(command, argc, argv);
    if (command == L"apply")
        return apply_command(argc >= 3 ? std::wstring{argv[2]} : std::wstring{L"blook.ini"});
    const bool known = command == L"ping" || command == L"version" ||
                       command == L"status" || command == L"hide" ||
                       command == L"pin" || command == L"unpin" ||
                       command == L"scrub" || command == L"hook";
    if (!known) {
        usage();
        return 1;
    }
    return session_command(command, argc, argv);
}
