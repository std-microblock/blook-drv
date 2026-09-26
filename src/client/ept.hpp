#pragma once
#include <windows.h>

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <system_error>
#include <type_traits>
#include <utility>

#include "client/handle.hpp"
#include "ipc/protocol.hpp"
#include "policy/hook.hpp"

// User-mode side of the driver ABI.
//
// A session belongs to the process that opened the device, but a single
// session can hook *any* process it can name: `session::patch` installs an
// EPT hook that only takes effect in that process, without touching a single
// byte of its memory. Reads through the region still return the original
// code, so the target cannot discover the hook by comparing its own bytes.
// Any number of non-overlapping hooks can share one page; the driver merges
// them into a single shadow page per process.
namespace blook::client {

template <class T>
using result = std::expected<T, std::error_code>;

[[nodiscard]] inline std::error_code last_error() noexcept {
    return {static_cast<int>(GetLastError()), std::system_category()};
}

// Strong process id. The default-constructed value (0) asks the driver to
// target the calling process; `pid::current()` names it explicitly.
struct pid {
    uint32_t value{};
    [[nodiscard]] static pid current() noexcept {
        return pid{GetCurrentProcessId()};
    }
    friend bool operator==(pid, pid) = default;
};

enum class process_role : uint32_t {
    tool = ipc::hide_role_tool,
    target = ipc::hide_role_target,
};

enum class scrub : uint32_t {
    peb = ipc::scrub_peb,
    heap = ipc::scrub_heap,
    all = ipc::scrub_all,
};

// Any contiguous sequence of 1-byte trivially-copyable values: std::byte,
// std::uint8_t, char buffers, std::vector<std::uint8_t>, C arrays, ...
template <class Range>
concept byte_range =
    std::ranges::contiguous_range<Range> &&
    std::is_trivially_copyable_v<std::ranges::range_value_t<Range>> &&
    sizeof(std::ranges::range_value_t<Range>) == 1;

template <byte_range Range>
[[nodiscard]] std::span<const std::byte> bytes_of(Range&& range) noexcept {
    return std::as_bytes(std::span{std::data(range), std::size(range)});
}

namespace detail {
struct connection final {
    unique_handle handle;
    connection() = default;
    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;
    connection(connection&&) = delete;
    connection& operator=(connection&&) = delete;

    [[nodiscard]] result<void> call(DWORD code, const void* input,
                                    DWORD input_size, void* output,
                                    DWORD output_size) const noexcept {
        if (!handle)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        DWORD returned{};
        if (!DeviceIoControl(handle.get(), code, const_cast<void*>(input),
                             input_size, output, output_size, &returned,
                             nullptr))
            return std::unexpected(last_error());
        if (returned != output_size)
            return std::unexpected(
                std::error_code{ERROR_INVALID_DATA, std::system_category()});
        return {};
    }
};
}  // namespace detail

// An entry jump that can be handed to `session::patch`: `jmp qword ptr
// [rip+rel32]` through a literal that lives outside the patched page and
// stays mapped for the lifetime of the hook. The literal cannot be part of
// the patch itself: the page is executed through a shadow that is mapped
// execute-only, so a read of it is answered from the untouched page and
// would deliver the wrong bytes. An empty optional means the literal is out
// of the +-2 GiB the encoding can reach, in which case the caller must not
// install the hook.
[[nodiscard]] inline std::optional<
    std::array<std::byte, blook::jump_patch_length>>
entry_jump(const void* target, const void* literal) noexcept {
    std::array<std::byte, blook::jump_patch_length> result{};
    result[0] = std::byte{0xff};
    result[1] = std::byte{0x25};
    const auto displacement =
        static_cast<int64_t>(reinterpret_cast<uintptr_t>(literal)) -
        static_cast<int64_t>(reinterpret_cast<uintptr_t>(target) +
                             blook::jump_patch_length);
    if (displacement > 0x7fffffffll || displacement < -0x80000000ll)
        return std::nullopt;
    const auto rel = static_cast<int32_t>(displacement);
    std::memcpy(result.data() + 2, &rel, sizeof(rel));
    return result;
}

// A installed hook. Move-only; destroying the last handle removes the hook
// from the driver. A moved-from hook is inert.
class hook final {
    std::shared_ptr<detail::connection> connection_;
    uint64_t id_{};

   public:
    hook(std::shared_ptr<detail::connection> connection, uint64_t id) noexcept
        : connection_(std::move(connection)), id_(id) {}
    hook(const hook&) = delete;
    hook& operator=(const hook&) = delete;
    hook(hook&& other) noexcept
        : connection_(std::move(other.connection_)),
          id_(std::exchange(other.id_, 0)) {}
    hook& operator=(hook&& other) noexcept {
        if (this != &other) {
            (void)remove();
            connection_ = std::move(other.connection_);
            id_ = std::exchange(other.id_, 0);
        }
        return *this;
    }
    ~hook() { (void)remove(); }

    [[nodiscard]] uint64_t id() const noexcept { return id_; }
    [[nodiscard]] explicit operator bool() const noexcept { return id_ != 0; }

    [[nodiscard]] result<void> remove() noexcept {
        if (!id_)
            return {};
        if (!connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        auto request = ipc::request<ipc::HookRequest>();
        request.id = id_;
        auto status = connection_->call(ipc::IOCTL_BLOOK_REMOVE, &request,
                                        sizeof(request), nullptr, 0);
        if (status)
            id_ = 0;
        return status;
    }

    // Caller must quiesce execution while changing source code or refreshing
    // its snapshot.
    [[nodiscard]] result<void> refresh() const noexcept {
        if (!id_ || !connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        auto request = ipc::request<ipc::HookRequest>();
        request.id = id_;
        return connection_->call(ipc::IOCTL_BLOOK_REFRESH, &request,
                                 sizeof(request), nullptr, 0);
    }
};

// Decoded `session::query` response. Field-for-field the wire protocol, but
// with flags as bools so call sites do not reinterpret integers.
struct session_info {
    uint32_t abi{};
    uint32_t version{};
    bool running{};
    bool enabled{};
    uint32_t hooks{};
    bool hidden{};
    int32_t backend_status{};
    uint32_t window_hooks{};
};

enum class open_mode {
    read_write,  // open the device and enable the session
    read_only,   // open the device without enabling it
};

class session final {
    std::shared_ptr<detail::connection> connection_;
    explicit session(std::shared_ptr<detail::connection> connection) noexcept
        : connection_(std::move(connection)) {}

    [[nodiscard]] result<void> call(DWORD code, const void* input,
                                    DWORD input_size, void* output,
                                    DWORD output_size) const noexcept {
        if (!connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        return connection_->call(code, input, input_size, output, output_size);
    }

   public:
    session(const session&) = delete;
    session& operator=(const session&) = delete;
    session(session&&) noexcept = default;
    session& operator=(session&&) noexcept = default;
    ~session() = default;

    [[nodiscard]] static result<session> open(
        open_mode mode = open_mode::read_write) {
        auto connection = std::make_shared<detail::connection>();
        connection->handle.reset(
            CreateFileW(ipc::kUserModePath, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!connection->handle)
            return std::unexpected(last_error());
        if (mode == open_mode::read_write) {
            auto request = ipc::request<ipc::EnableRequest>();
            auto status = connection->call(ipc::IOCTL_BLOOK_ENABLE, &request,
                                           sizeof(request), nullptr, 0);
            if (!status)
                return std::unexpected(status.error());
        }
        return session{std::move(connection)};
    }

    [[nodiscard]] result<session_info> query() const noexcept {
        ipc::QueryResponse raw{};
        auto status =
            call(ipc::IOCTL_BLOOK_QUERY, nullptr, 0, &raw, sizeof(raw));
        if (!status)
            return std::unexpected(status.error());
        return session_info{.abi = raw.abi,
                            .version = raw.version,
                            .running = raw.running != 0,
                            .enabled = raw.enabled != 0,
                            .hooks = raw.hooks,
                            .hidden = raw.hidden != 0,
                            .backend_status = raw.backend_status,
                            .window_hooks = raw.window_hooks};
    }

    // Install `bytes` at `address` in the address space of `target`
    // (default: this process). The patch must lie within one 4 KiB page; the
    // driver extends it to whole instructions. Non-overlapping patches on the
    // same page coexist and are merged into one shadow page.
    template <byte_range Bytes>
    [[nodiscard]] result<hook> patch(void* address, Bytes&& bytes,
                                     pid target = pid::current()) const {
        const auto view = bytes_of(bytes);
        const auto at = reinterpret_cast<uint64_t>(address);
        if (!blook::valid_patch(at, view.size()) ||
            view.size() > sizeof(ipc::InstallRequest::bytes))
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        auto request = ipc::request<ipc::InstallRequest>();
        request.pid = target.value;
        request.target = at;
        request.length = static_cast<uint32_t>(view.size());
        std::memcpy(request.bytes, view.data(), view.size());
        ipc::InstallResponse response{};
        auto status = call(ipc::IOCTL_BLOOK_INSTALL, &request, sizeof(request),
                           &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return hook{connection_, response.id};
    }

    // Redirect an entry point to a replacement of the caller's own, e.g. a
    // handler inside a DLL that is mapped into the target process.
    [[nodiscard]] result<hook> redirect(void* target, void* replacement,
                                        pid owner = pid::current()) const {
        if (!connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        const auto destination = reinterpret_cast<uint64_t>(replacement);
        if (!blook::user_address(destination))
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        // Park the literal in a page of its own, on the far side of the
        // patched one. It is deliberately never freed: the patch can execute
        // for as long as the hook lives, so the literal has to stay readable
        // and at the same address.
        void* literal = nullptr;
        if (owner.value == 0 || owner == pid::current()) {
            literal = VirtualAlloc(nullptr, sizeof(uint64_t),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (literal)
                std::memcpy(literal, &destination, sizeof(destination));
        } else {
            HANDLE process = OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, owner.value);
            if (process) {
                literal =
                    VirtualAllocEx(process, nullptr, sizeof(uint64_t),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (literal)
                    WriteProcessMemory(process, literal, &destination,
                                       sizeof(destination), nullptr);
                CloseHandle(process);
            }
        }
        if (!literal)
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        auto bytes = entry_jump(target, literal);
        if (!bytes)  // literal out of reach
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        return patch(target, *bytes, owner);
    }

    [[nodiscard]] result<void> hide(bool enable) const noexcept {
        auto request = ipc::request<ipc::HideRequest>();
        request.enable_hide = enable ? 1u : 0u;
        return call(ipc::IOCTL_BLOOK_HIDE, &request, sizeof(request), nullptr,
                    0);
    }

    [[nodiscard]] result<void> hide_windows(bool enable) const noexcept {
        auto request = ipc::request<ipc::HideRequest>();
        request.enable_hide =
            enable ? ipc::hide_windows_on : ipc::hide_windows_off;
        return call(ipc::IOCTL_BLOOK_HIDE, &request, sizeof(request), nullptr,
                    0);
    }

    [[nodiscard]] result<void> pin(pid process,
                                   process_role role) const noexcept {
        auto request = ipc::request<ipc::HideRequest>();
        request.enable_hide = 2;
        request.pid = process.value;
        request.role = static_cast<uint32_t>(role);
        return call(ipc::IOCTL_BLOOK_HIDE, &request, sizeof(request), nullptr,
                    0);
    }

    [[nodiscard]] result<void> unpin(pid process) const noexcept {
        auto request = ipc::request<ipc::HideRequest>();
        request.enable_hide = 3;
        request.pid = process.value;
        return call(ipc::IOCTL_BLOOK_HIDE, &request, sizeof(request), nullptr,
                    0);
    }

    // Clear the debug artefacts a process can read out of its own structures.
    [[nodiscard]] result<void> scrub(pid process,
                                     scrub flags = scrub::all) const noexcept {
        auto request = ipc::request<ipc::ScrubRequest>();
        request.pid = process.value;
        request.flags = static_cast<uint32_t>(flags);
        return call(ipc::IOCTL_BLOOK_SCRUB, &request, sizeof(request), nullptr,
                    0);
    }
};
}  // namespace blook::client
