#pragma once
#include <windows.h>

#include <array>
#include <cstring>
#include <expected>
#include <memory>
#include <span>
#include <utility>

#include "ipc/protocol.hpp"
#include "policy/hook.hpp"

// User-mode side of the driver ABI.
//
// A session belongs to the process that opened the device, but a single
// session can hook *any* process it can name: `patch(pid, address, bytes)`
// installs an EPT hook that only takes effect in that process, without
// touching a single byte of its memory. Reads through the region still return
// the original code, so the target cannot discover the hook by comparing its
// own bytes.
namespace blook::client {
template <class T>
using result = std::expected<T, DWORD>;

namespace detail {
struct connection final {
    HANDLE handle{INVALID_HANDLE_VALUE};
    ~connection() {
        if (handle != INVALID_HANDLE_VALUE)
            CloseHandle(handle);
    }
    connection() = default;
    connection(const connection&) = delete;
    result<void> call(DWORD code, const void* input, DWORD input_size,
                      void* output, DWORD output_size) const {
        DWORD returned{};
        if (!DeviceIoControl(handle, code, const_cast<void*>(input), input_size,
                             output, output_size, &returned, nullptr))
            return std::unexpected(GetLastError());
        if (returned != output_size)
            return std::unexpected(ERROR_INVALID_DATA);
        return {};
    }
};
}  // namespace detail

// An entry jump that can be handed to `patch`: `jmp qword ptr [rip+rel32]`
// through a literal that lives outside the patched page and stays mapped for
// the lifetime of the hook. The literal cannot be part of the patch itself:
// the page is executed through a shadow that is mapped execute-only, so a read
// of it is answered from the untouched page and would deliver the wrong bytes.
// An empty result means the literal is out of the +-2 GiB the encoding can
// reach, in which case the caller must not install the hook.
[[nodiscard]] inline std::array<uint8_t, blook::jump_patch_length> entry_jump(
    const void* target, const void* literal) {
    std::array<uint8_t, blook::jump_patch_length> result{0xff, 0x25, 0, 0, 0, 0};
    const auto displacement = static_cast<int64_t>(
                                   reinterpret_cast<uintptr_t>(literal)) -
                               static_cast<int64_t>(
                                   reinterpret_cast<uintptr_t>(target) +
                                   blook::jump_patch_length);
    if (displacement > 0x7fffffffll || displacement < -0x80000000ll)
        return {};
    const auto rel = static_cast<int32_t>(displacement);
    std::memcpy(result.data() + 2, &rel, sizeof(rel));
    return result;
}

class hook final {
    std::shared_ptr<detail::connection> connection_;
    uint64_t id_{};

   public:
    hook(std::shared_ptr<detail::connection> connection, uint64_t id)
        : connection_(std::move(connection)), id_(id) {}
    hook(const hook&) = delete;
    hook& operator=(const hook&) = delete;
    hook(hook&& other) noexcept
        : connection_(std::move(other.connection_)),
          id_(std::exchange(other.id_, 0)) {}
    hook& operator=(hook&&) = delete;
    ~hook() { (void)remove(); }
    [[nodiscard]] uint64_t id() const noexcept { return id_; }
    [[nodiscard]] result<void> remove() {
        if (!id_)
            return {};
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
    [[nodiscard]] result<void> refresh() const {
        if (!id_)
            return std::unexpected(ERROR_INVALID_HANDLE);
        auto request = ipc::request<ipc::HookRequest>();
        request.id = id_;
        return connection_->call(ipc::IOCTL_BLOOK_REFRESH, &request,
                                 sizeof(request), nullptr, 0);
    }
};

class session final {
    std::shared_ptr<detail::connection> connection_;
    explicit session(std::shared_ptr<detail::connection> connection)
        : connection_(std::move(connection)) {}

   public:
    session(const session&) = delete;
    session& operator=(const session&) = delete;
    session(session&&) noexcept = default;
    session& operator=(session&&) noexcept = default;

    [[nodiscard]] static result<session> open(bool enable_hooks = true) {
        auto connection = std::make_shared<detail::connection>();
        connection->handle =
            CreateFileW(ipc::kUserModePath, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (connection->handle == INVALID_HANDLE_VALUE)
            return std::unexpected(GetLastError());
        if (enable_hooks) {
            auto request = ipc::request<ipc::EnableRequest>();
            auto status = connection->call(ipc::IOCTL_BLOOK_ENABLE, &request,
                                           sizeof(request), nullptr, 0);
            if (!status)
                return std::unexpected(status.error());
        }
        return session{std::move(connection)};
    }

    [[nodiscard]] result<ipc::QueryResponse> query() const {
        ipc::QueryResponse response{};
        auto status = connection_->call(ipc::IOCTL_BLOOK_QUERY, nullptr, 0,
                                        &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    // pid 0 hooks the calling process.
    [[nodiscard]] result<hook> patch(uint32_t pid, void* address,
                                     std::span<const uint8_t> bytes) const {
        if (bytes.empty() ||
            bytes.size() > sizeof(ipc::InstallRequest::bytes) ||
            (reinterpret_cast<uintptr_t>(address) & 4095) + bytes.size() > 4096)
            return std::unexpected(ERROR_INVALID_PARAMETER);
        auto request = ipc::request<ipc::InstallRequest>();
        request.pid = pid;
        request.target = reinterpret_cast<uint64_t>(address);
        request.length = static_cast<uint32_t>(bytes.size());
        std::memcpy(request.bytes, bytes.data(), bytes.size());
        ipc::InstallResponse response{};
        auto status =
            connection_->call(ipc::IOCTL_BLOOK_INSTALL, &request,
                              sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return hook{connection_, response.id};
    }

    [[nodiscard]] result<hook> patch(void* address,
                                     std::span<const uint8_t> bytes) const {
        return patch(0, address, bytes);
    }

    // Redirect an entry point to a replacement of the caller's own, e.g. a
    // handler inside a DLL that is mapped into the target process.
    [[nodiscard]] result<hook> redirect(uint32_t pid, void* target,
                                        const void* replacement) const {
        const auto destination = reinterpret_cast<uint64_t>(replacement);
        if (!destination || destination >= 0x0000800000000000ull)
            return std::unexpected(ERROR_INVALID_PARAMETER);
        // Park the literal in a page of its own, on the far side of the
        // patched one. It is deliberately never freed: the patch can execute
        // for as long as the hook lives, so the literal has to stay readable
        // and at the same address.
        void* literal = nullptr;
        if (!pid) {
            literal = VirtualAlloc(nullptr, sizeof(uint64_t),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (literal)
                std::memcpy(literal, &destination, sizeof(destination));
        } else {
            HANDLE process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                                         FALSE, pid);
            if (process) {
                literal = VirtualAllocEx(process, nullptr, sizeof(uint64_t),
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
                if (literal)
                    WriteProcessMemory(process, literal, &destination,
                                       sizeof(destination), nullptr);
                CloseHandle(process);
            }
        }
        if (!literal)
            return std::unexpected(ERROR_INVALID_PARAMETER);
        const auto bytes = entry_jump(target, literal);
        if (bytes[0] != 0xff)  // literal out of reach
            return std::unexpected(ERROR_INVALID_PARAMETER);
        return patch(pid, target, bytes);
    }

    [[nodiscard]] result<hook> redirect(void* target,
                                        const void* replacement) const {
        return redirect(0, target, replacement);
    }

    [[nodiscard]] result<void> hide(bool enable) const {
        auto request = ipc::request<ipc::HideRequest>();
        request.enable_hide = enable ? 1u : 0u;
        return connection_->call(ipc::IOCTL_BLOOK_HIDE, &request,
                                 sizeof(request), nullptr, 0);
    }

    [[nodiscard]] result<void> pin(uint32_t pid, uint32_t role) const {
        auto request = ipc::request<ipc::HideRequest>();
        request.enable_hide = 2;
        request.pid = pid;
        request.role = role;
        return connection_->call(ipc::IOCTL_BLOOK_HIDE, &request,
                                 sizeof(request), nullptr, 0);
    }

    [[nodiscard]] result<void> unpin(uint32_t pid) const {
        auto request = ipc::request<ipc::HideRequest>();
        request.enable_hide = 3;
        request.pid = pid;
        return connection_->call(ipc::IOCTL_BLOOK_HIDE, &request,
                                 sizeof(request), nullptr, 0);
    }

    // win32k window hides: the sample can no longer find the tools' windows.
    [[nodiscard]] result<void> hide_windows(bool enable) const {
        auto request = ipc::request<ipc::HideRequest>();
        request.enable_hide = enable ? ipc::hide_windows_on : ipc::hide_windows_off;
        return connection_->call(ipc::IOCTL_BLOOK_HIDE, &request, sizeof(request), nullptr, 0);
    }

    // Clear the debug artefacts a process can read out of its own structures.
    [[nodiscard]] result<void> scrub(uint32_t pid,
                                     uint32_t flags = ipc::scrub_all) const {
        auto request = ipc::request<ipc::ScrubRequest>();
        request.pid = pid;
        request.flags = flags;
        return connection_->call(ipc::IOCTL_BLOOK_SCRUB, &request,
                                 sizeof(request), nullptr, 0);
    }
};
}  // namespace blook::client
