#include "operations.hpp"

// Toolhelp declarations require Windows types before their own header.
// clang-format off
#include <windows.h>
#include <tlhelp32.h>
// clang-format on

#include <array>
#include <cstdio>
#include <memory>
#include <system_error>
#include <utility>

#include "client/ept.hpp"
#include "client/handle.hpp"
#include "config.hpp"

namespace blook::loader {
namespace {
template <class T, auto Close>
class owned_handle final {
    T value_{};

   public:
    explicit owned_handle(T value = {}) noexcept : value_(value) {}
    ~owned_handle() {
        if (value_) {
            const auto error = GetLastError();
            Close(value_);
            SetLastError(error);
        }
    }
    owned_handle(const owned_handle&) = delete;
    owned_handle& operator=(const owned_handle&) = delete;
    owned_handle(owned_handle&& other) noexcept
        : value_(std::exchange(other.value_, {})) {}
    owned_handle& operator=(owned_handle&&) = delete;
    [[nodiscard]] T get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ != nullptr; }
};
using service_handle = owned_handle<SC_HANDLE, CloseServiceHandle>;
using registry_handle = owned_handle<HKEY, RegCloseKey>;
using snapshot_handle = blook::client::unique_handle;
using result = std::expected<operation_result, failure>;

std::unexpected<failure> failed(std::string action, DWORD code = GetLastError(),
                                std::string detail = {},
                                std::string hint = {}) {
    if (hint.empty()) {
        if (code == ERROR_ACCESS_DENIED)
            hint =
                "Check access permissions and use an elevated terminal if "
                "required.";
        else if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND ||
                 code == ERROR_SERVICE_DOES_NOT_EXIST)
            hint =
                "Check that the signed driver is installed and running; no "
                "automatic changes were made.";
        else if (code == ERROR_INVALID_IMAGE_HASH)
            hint =
                "Use a driver signed and trusted under this machine's normal "
                "Windows policy.";
    }
    return std::unexpected(
        failure{std::move(action), code, std::move(detail), std::move(hint)});
}
std::unexpected<failure> failed(std::string action, std::error_code code,
                                std::string detail = {},
                                std::string hint = {}) {
    return failed(std::move(action), static_cast<DWORD>(code.value()),
                  std::move(detail), std::move(hint));
}

result service_command(const cli::command& command, output_sink& output) {
    using enum cli::kind;
    std::wstring image_path;
    if (command.action == install) {
        std::array<wchar_t, 32768> absolute{};
        const auto length = GetFullPathNameW(
            command.path.c_str(), static_cast<DWORD>(absolute.size()),
            absolute.data(), nullptr);
        if (!length)
            return failed("Resolve driver path");
        if (length >= absolute.size())
            return failed("Resolve driver path", ERROR_FILENAME_EXCED_RANGE);
        const auto attributes = GetFileAttributesW(absolute.data());
        if (attributes == INVALID_FILE_ATTRIBUTES)
            return failed("Read driver path");
        if (attributes & FILE_ATTRIBUTE_DIRECTORY)
            return failed("Read driver path", ERROR_DIRECTORY,
                          "Expected a driver file, not a directory.");
        // Preserve the existing NT-form service image path, without changing
        // signing policy.
        image_path = L"\\??\\" + std::wstring{absolute.data()};
    }
    service_handle scm{OpenSCManagerW(
        nullptr, nullptr,
        SC_MANAGER_CONNECT |
            (command.action == install ? SC_MANAGER_CREATE_SERVICE : 0))};
    if (!scm)
        return failed("Open service manager");
    if (command.action == install) {
        service_handle service{CreateServiceW(
            scm.get(), L"BlookDrv", L"Blook Intel EPT analysis driver",
            SERVICE_QUERY_STATUS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, image_path.c_str(), nullptr, nullptr, nullptr,
            nullptr, nullptr)};
        if (!service)
            return failed("Install service", GetLastError(),
                          "An existing service is not overwritten.");
        output.message("Installed, NOT started.");
        return operation_result{};
    }
    const DWORD access = command.action == start ? SERVICE_START
                         : command.action == stop
                             ? SERVICE_STOP | SERVICE_QUERY_STATUS
                             : DELETE | SERVICE_QUERY_STATUS;
    service_handle service{OpenServiceW(scm.get(), L"BlookDrv", access)};
    if (!service)
        return failed("Open service");
    if (command.action == start) {
        if (!StartServiceW(service.get(), 0, nullptr))
            return failed("Start service");
        output.message("Started.");
        return operation_result{};
    }
    SERVICE_STATUS service_status{};
    if (command.action == stop) {
        if (!ControlService(service.get(), SERVICE_CONTROL_STOP,
                            &service_status) &&
            GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
            return failed("Stop service");
        const auto deadline = GetTickCount64() + 30000;
        do {
            if (!QueryServiceStatus(service.get(), &service_status))
                return failed("Query service");
            if (service_status.dwCurrentState == SERVICE_STOPPED) {
                output.message("Stopped.");
                return operation_result{};
            }
            Sleep(100);
        } while (GetTickCount64() < deadline);
        return failed(
            "Stop service", ERROR_TIMEOUT,
            "Timed out after 30 seconds; the service was not deleted.");
    }
    if (!QueryServiceStatus(service.get(), &service_status))
        return failed("Query service");
    if (service_status.dwCurrentState != SERVICE_STOPPED)
        return failed("Uninstall service", ERROR_SERVICE_CANNOT_ACCEPT_CTRL,
                      "Stop the driver before uninstalling.");
    if (!DeleteService(service.get()))
        return failed("Uninstall service");
    output.message("Service removed; the driver file is left untouched.");
    return operation_result{};
}

std::expected<cli::configuration, failure> read_config(
    const std::wstring& path) {
    using file_ptr = std::unique_ptr<FILE, decltype(&std::fclose)>;
    FILE* raw_file{};
    const auto open_error = _wfopen_s(&raw_file, path.c_str(), L"rb");
    file_ptr file{raw_file, &std::fclose};
    if (open_error || !file)
        return failed(
            "Read configuration", 0, "Cannot open the configuration file.",
            "Check the path and file permissions; no settings were applied.");
    std::string bytes;
    std::array<char, 4096> buffer{};
    while (const auto count =
               std::fread(buffer.data(), 1, buffer.size(), file.get())) {
        bytes.append(buffer.data(), count);
        if (bytes.size() >
            static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            return failed("Read configuration", ERROR_FILE_TOO_LARGE);
    }
    if (std::ferror(file.get()))
        return failed("Read configuration", ERROR_READ_FAULT);
    if (bytes.starts_with("\xef\xbb\xbf"))
        bytes.erase(0, 3);
    std::wstring text;
    if (!bytes.empty()) {
        const auto length =
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
                                static_cast<int>(bytes.size()), nullptr, 0);
        if (!length)
            return failed("Decode configuration", GetLastError(),
                          "Configuration must be valid UTF-8.");
        text.resize(static_cast<std::size_t>(length));
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
                                 static_cast<int>(bytes.size()), text.data(),
                                 length))
            return failed("Decode configuration");
    }
    auto parsed = cli::parse_config(text);
    if (!parsed)
        return failed("Validate configuration", 0,
                      "Line " + std::to_string(parsed.error().line) + ": " +
                          parsed.error().message,
                      "Correct the configuration; no settings were applied.");
    return std::move(*parsed);
}

result pin_roles(const cli::configuration& config, output_sink& output) {
    const auto raw = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (raw == INVALID_HANDLE_VALUE)
        return failed("Enumerate processes");
    snapshot_handle snapshot{raw};
    std::vector<std::pair<std::uint32_t, std::wstring>> running;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot.get(), &entry)) {
        do {
            running.emplace_back(entry.th32ProcessID,
                                 cli::lower(entry.szExeFile));
        } while (Process32NextW(snapshot.get(), &entry));
        if (GetLastError() != ERROR_NO_MORE_FILES)
            return failed("Enumerate processes");
    } else if (GetLastError() != ERROR_NO_MORE_FILES)
        return failed("Enumerate processes");
    auto session = blook::client::session::open();
    if (!session)
        return failed("Open driver for roles", session.error());
    std::uint32_t pinned{};
    const auto apply_role =
        [&](const std::vector<std::wstring>& wanted,
            blook::client::process_role role) -> std::expected<void, failure> {
        for (const auto& want : wanted) {
            std::vector<std::uint32_t> matches;
            if (auto requested_pid = cli::parse_pid(want))
                matches.push_back(*requested_pid);
            else {
                const auto name = cli::lower(want);
                for (const auto& [pid, image] : running)
                    if (image == name && pid)
                        matches.push_back(pid);
            }
            for (const auto pid : matches) {
                auto status = session->pin(blook::client::pid{pid}, role);
                if (!status)
                    return failed("Pin process", status.error(),
                                  "PID " + std::to_string(pid) +
                                      "; earlier successful changes were not "
                                      "rolled back.");
                ++pinned;
                output.message("Pinned " + std::to_string(pid) +
                               (role == blook::client::process_role::tool
                                    ? " as tool."
                                    : " as target."));
            }
        }
        return {};
    };
    if (auto applied =
            apply_role(config.tools, blook::client::process_role::tool);
        !applied)
        return std::unexpected(applied.error());
    if (auto applied =
            apply_role(config.targets, blook::client::process_role::target);
        !applied)
        return std::unexpected(applied.error());
    output.message("Roles applied (" + std::to_string(pinned) + " pinned).");
    return operation_result{};
}

result apply_command(const std::wstring& path, output_sink& output) {
    auto config = read_config(path);
    if (!config)
        return std::unexpected(config.error());
    if (config->allow_users || config->hook_mask || config->window_hook_mask) {
        HKEY raw{};
        const auto opened =
            RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Services\\BlookDrv", 0,
                            nullptr, 0, KEY_SET_VALUE, nullptr, &raw, nullptr);
        if (opened != ERROR_SUCCESS)
            return failed("Open service settings", opened);
        registry_handle key{raw};
        const auto set =
            [&](const wchar_t* name,
                std::uint32_t value) -> std::expected<void, failure> {
            const auto code = RegSetValueExW(
                key.get(), name, 0, REG_DWORD,
                reinterpret_cast<const BYTE*>(&value), sizeof(value));
            if (code != ERROR_SUCCESS)
                return failed(
                    "Write service settings", code,
                    "Earlier successful writes were not rolled back.");
            return {};
        };
        if (config->allow_users)
            if (auto written =
                    set(L"AllowUsers", *config->allow_users ? 1u : 0u);
                !written)
                return std::unexpected(written.error());
        if (config->hook_mask)
            if (auto written = set(L"HookMask", *config->hook_mask); !written)
                return std::unexpected(written.error());
        if (config->window_hook_mask)
            if (auto written =
                    set(L"WindowHookMask", *config->window_hook_mask);
                !written)
                return std::unexpected(written.error());
        output.message(
            "Device settings written; they take effect when the driver "
            "starts.");
    }
    if (config->tools.empty() && config->targets.empty()) {
        if (!config->allow_users && !config->hook_mask &&
            !config->window_hook_mask)
            output.message("No recognized settings to apply; nothing changed.");
        return operation_result{};
    }
    return pin_roles(*config, output);
}
}  // namespace

std::uint32_t client_abi() noexcept {
    return ipc::abi_version;
}

std::expected<operation_result, failure> execute(const cli::command& command,
                                                 output_sink& output) {
    using enum cli::kind;
    switch (command.action) {
        case help:
            return operation_result{};
        case install:
        case start:
        case stop:
        case uninstall:
            return service_command(command, output);
        case apply:
            return apply_command(command.path, output);
        default:
            break;
    }
    // Information commands must not enable VMX as a side effect of opening a
    // session.
    const bool information = command.action == ping ||
                             command.action == version ||
                             command.action == status;
    auto session =
        information
            ? blook::client::session::open(blook::client::open_mode::read_only)
            : blook::client::session::open();
    if (!session)
        return failed("Open driver", session.error());
    switch (command.action) {
        case hide: {
            auto changed = command.windows
                               ? session->hide_windows(command.enable)
                               : session->hide(command.enable);
            if (!changed)
                return failed("Hide profile", changed.error());
            output.message(std::string{"Hide profile "} +
                           (command.windows ? "windows " : "") +
                           (command.enable ? "active." : "inactive."));
            break;
        }
        case pin: {
            auto changed =
                session->pin(blook::client::pid{command.pid},
                             command.process_role == cli::role::tool
                                 ? blook::client::process_role::tool
                                 : blook::client::process_role::target);
            if (!changed)
                return failed("Pin process", changed.error());
            output.message("Pinned " + std::to_string(command.pid) +
                           (command.process_role == cli::role::tool
                                ? " as tool."
                                : " as target."));
            break;
        }
        case unpin: {
            auto changed = session->unpin(blook::client::pid{command.pid});
            if (!changed)
                return failed("Unpin process", changed.error());
            output.message("Unpinned.");
            break;
        }
        case scrub: {
            auto changed = session->scrub(blook::client::pid{command.pid});
            if (!changed)
                return failed("Scrub process", changed.error());
            output.message("Scrubbed " + std::to_string(command.pid) + ".");
            break;
        }
        case hook: {
            auto installed =
                session->patch(reinterpret_cast<void*>(command.address),
                               command.bytes, blook::client::pid{command.pid});
            if (!installed)
                return failed("Install EPT hook", installed.error());
            output.message("Hook " + std::to_string(installed->id()) +
                           (command.pid ? " installed in the target process."
                                        : " installed in this process."));
            output.wait_for_enter();
            break;
        }
        default: {
            auto queried = session->query();
            if (!queried)
                return failed("Query driver", queried.error());
            dashboard view{ipc::abi_version,
                           queried->abi,
                           queried->hooks,
                           queried->window_hooks,
                           static_cast<std::uint32_t>(queried->backend_status),
                           queried->running,
                           queried->enabled,
                           queried->hidden};
            return operation_result{queried->running ? 0 : 2, view};
        }
    }
    return operation_result{};
}
}  // namespace blook::loader
