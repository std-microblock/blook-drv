#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include "ipc/protocol.hpp"
#include "policy/hook.hpp"
#include "support.hpp"

// Only the device boundary is faked. No driver is opened and no IOCTL reaches
// the host; all handles owned by these tests are real, harmless event objects.
namespace fake {
inline bool fail_open{};
inline bool fail_call{};
inline bool short_response{};
inline unsigned calls{};
inline HANDLE last_handle{};
inline ipc::WatchRequest last_watch{};
// What the fake driver hands out as a finished dump.
inline std::array<std::uint8_t, 8> dump_bytes{0x30, 0x31, 0x32, 0x33,
                                              0x34, 0x35, 0x36, 0x37};
HANDLE WINAPI open(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                   HANDLE) {
    if (fail_open) {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    last_handle = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    return last_handle;
}
BOOL WINAPI control(HANDLE, DWORD code, LPVOID input, DWORD, LPVOID output,
                    DWORD size, LPDWORD returned, LPOVERLAPPED) {
    ++calls;
    if (fail_call) {
        SetLastError(ERROR_NOT_READY);
        return FALSE;
    }
    if (code == ipc::IOCTL_BLOOK_QUERY && size == sizeof(ipc::QueryResponse)) {
        const ipc::QueryResponse info{
            .version = 3, .running = 1, .abi = ipc::abi_version};
        std::memcpy(output, &info, sizeof(info));
    }
    if (code == ipc::IOCTL_BLOOK_INSTALL &&
        size == sizeof(ipc::InstallResponse)) {
        const ipc::InstallResponse made{.id = 0xabc};
        std::memcpy(output, &made, sizeof(made));
    }
    if (code == ipc::IOCTL_BLOOK_WATCH && input &&
        size == sizeof(ipc::WatchResponse)) {
        const auto* request = static_cast<const ipc::WatchRequest*>(input);
        if (request->action == ipc::watch_arm) {
            last_watch = *request;
            const ipc::WatchResponse made{.id = 0xdef};
            std::memcpy(output, &made, sizeof(made));
        }
    }
    if (code == ipc::IOCTL_BLOOK_DUMP && input &&
        size == sizeof(ipc::DumpResponse)) {
        const auto* request = static_cast<const ipc::DumpRequest*>(input);
        ipc::DumpResponse made{};
        made.state = blook::watch_hit;
        made.total = dump_bytes.size();
        made.hit_rip = 0x1234;
        made.hit_cr3 = 1;
        if (request->offset < dump_bytes.size()) {
            const auto available =
                dump_bytes.size() - request->offset;
            const auto take = request->length < available
                                  ? request->length
                                  : static_cast<uint32_t>(available);
            std::memcpy(made.data, dump_bytes.data() + request->offset, take);
            made.copied = take;
        }
        std::memcpy(output, &made, sizeof(made));
    }
    *returned = short_response && size ? size - 1 : size;
    return TRUE;
}
}  // namespace fake

#define CreateFileW fake::open
#define DeviceIoControl fake::control
#include "client/ept.hpp"
#undef DeviceIoControl
#undef CreateFileW

namespace {
bool valid(HANDLE handle) {
    DWORD flags{};
    return GetHandleInformation(handle, &flags) != FALSE;
}
template <class T>
bool denied(const std::expected<T, std::error_code>& status, DWORD code) {
    return !status && status.error() == std::error_code{static_cast<int>(code),
                                                        std::system_category()};
}
}  // namespace

int main() {
    using namespace blook::client;
    static_assert(!std::is_copy_constructible_v<unique_handle>);
    static_assert(!std::is_copy_assignable_v<unique_handle>);
    static_assert(std::is_nothrow_move_constructible_v<unique_handle>);
    static_assert(std::is_nothrow_move_assignable_v<unique_handle>);
    static_assert(!std::is_copy_assignable_v<detail::connection>);
    static_assert(!std::is_copy_constructible_v<detail::connection>);
    static_assert(!std::is_move_constructible_v<detail::connection>);
    static_assert(!std::is_copy_constructible_v<session>);
    static_assert(std::is_nothrow_move_constructible_v<session>);
    static_assert(!std::is_copy_constructible_v<hook>);
    static_assert(std::is_nothrow_move_constructible_v<hook>);
    static_assert(byte_range<std::uint8_t[4]>);
    static_assert(byte_range<std::array<std::byte, 4>>);
    static_assert(byte_range<std::vector<std::uint8_t>>);
    static_assert(byte_range<std::span<const std::byte>>);
    static_assert(!byte_range<std::uint16_t[4]>);
    static_assert(!byte_range<int>);

    unique_handle empty;
    unique_handle null{nullptr};
    test::check(!empty && !null, "both invalid sentinels are empty");
    unique_handle first{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    test::check(static_cast<bool>(first), "create event");
    const auto original = first.get();
    unique_handle second{std::move(first)};
    test::check(!first && second.get() == original, "move transfers ownership");
    second.reset(second.get());
    test::check(valid(original), "reset to same handle is harmless");
    const auto detached = second.release();
    test::check(!second && valid(detached), "release does not close");
    first.reset(detached);
    SetLastError(ERROR_ACCESS_DENIED);
    first.reset();
    test::check(GetLastError() == ERROR_ACCESS_DENIED,
                "cleanup preserves last error");
    test::check(!valid(original), "reset closes owned object");

    first.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    second.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    test::check(first && second, "create move-assignment events");
    const auto replaced = second.get();
    second = std::move(first);
    test::check(!first && second && !valid(replaced),
                "move assignment closes old owner");
    second = std::move(second);
    test::check(static_cast<bool>(second), "self move keeps owner");

    // The entry-jump helper: reachable literal encodes ff 25 rel32, an
    // out-of-range literal is an empty optional instead of a sentinel array.
    auto near_jump = entry_jump(reinterpret_cast<void*>(0x10000000),
                                reinterpret_cast<void*>(0x10001000));
    test::check(near_jump && (*near_jump)[0] == std::byte{0xff} &&
                    (*near_jump)[1] == std::byte{0x25},
                "entry jump encodes rip-relative indirect jmp");
    test::check(
        !entry_jump(reinterpret_cast<void*>(std::uintptr_t{0x10000000}),
                    reinterpret_cast<void*>(std::uintptr_t{0x90000007})),
        "out-of-reach literal rejected");
    test::check(!entry_jump(reinterpret_cast<void*>(std::uintptr_t{0x80000000}),
                            reinterpret_cast<void*>(std::uintptr_t{0x0})),
                "below-range literal rejected");

    fake::fail_open = true;
    auto denied_open = session::open(open_mode::read_only);
    test::check(!denied_open && denied_open.error().value() ==
                                    static_cast<int>(ERROR_ACCESS_DENIED),
                "open error propagated");
    fake::fail_open = false;
    fake::fail_call = true;
    auto failed = session::open();
    test::check(
        !failed && failed.error().value() == static_cast<int>(ERROR_NOT_READY),
        "enable failure propagated");
    test::check(!valid(fake::last_handle), "failed open closes connection");
    fake::fail_call = false;
    HANDLE connection_handle{};
    {
        const auto before = fake::calls;
        auto opened = session::open(open_mode::read_only);
        test::check(opened.has_value(), "open readonly connection");
        connection_handle = fake::last_handle;
        test::check(fake::calls == before,
                    "read_only open does not enable session");
        auto moved = std::move(*opened);
        const auto invalid = opened->query();
        test::check(!invalid && invalid.error().value() ==
                                    static_cast<int>(ERROR_INVALID_HANDLE),
                    "moved-from query is safe");
        const auto info = moved.query();
        test::check(info && info->abi == ipc::abi_version && info->running &&
                        !info->enabled && !info->hidden,
                    "query decodes response");
        fake::short_response = true;
        const auto truncated = moved.query();
        test::check(!truncated && truncated.error().value() ==
                                      static_cast<int>(ERROR_INVALID_DATA),
                    "reject short response");
        fake::short_response = false;
        fake::fail_call = true;
        const auto unavailable = moved.query();
        test::check(!unavailable && unavailable.error().value() ==
                                        static_cast<int>(ERROR_NOT_READY),
                    "query error propagated");
        fake::fail_call = false;

        // Patch validation is client-side and precedes any IOCTL: empty
        // ranges, page-crossing ranges and oversized patches are rejected
        // before the device is touched.
        fake::calls = 0;
        const std::array<std::uint8_t, 1> nop{0x90};
        const std::array<std::uint8_t, 2> pair{0x90, 0x90};
        test::check(
            denied(moved.patch(reinterpret_cast<void*>(0x1ffff), pair, pid{}),
                   ERROR_INVALID_PARAMETER),
            "page-crossing patch rejected");
        test::check(
            denied(moved.patch(nullptr, std::span<const std::byte>{}, pid{}),
                   ERROR_INVALID_PARAMETER),
            "empty byte range rejected");
        const std::vector<std::byte> wide(65, std::byte{0x90});
        test::check(
            denied(moved.patch(nullptr, wide, pid{}), ERROR_INVALID_PARAMETER),
            "oversized patch rejected");
        test::check(fake::calls == 0, "validation reaches no ioctl");
        const auto installed =
            moved.patch(reinterpret_cast<void*>(std::uintptr_t{0x10000}), nop,
                        pid::current());
        test::check(installed.has_value() && installed->id() == 0xabc &&
                        fake::calls == 1,
                    "valid patch issues one ioctl");
    }
    // The watch API: arm (absolute and module-relative), poll, chunked and
    // full dump, disarm on destruction.
    {
        auto opened = session::open(open_mode::read_only);
        test::check(opened.has_value(), "open session for watch tests");
        fake::calls = 0;
        auto armed = opened->watch_execute(
            reinterpret_cast<void*>(std::uintptr_t{0x700080}),
            reinterpret_cast<void*>(std::uintptr_t{0x710000}), 0x1020,
            pid{1234});
        test::check(armed && armed->id() == 0xdef && fake::calls == 1,
                    "absolute watch arm issues one ioctl");
        test::check(fake::last_watch.action == ipc::watch_arm &&
                        fake::last_watch.pid == 1234 &&
                        fake::last_watch.address == 0x700080 &&
                        fake::last_watch.base == 0 &&
                        fake::last_watch.dump_base == 0x710000 &&
                        fake::last_watch.dump_size == 0x1020,
                    "arm request carries absolute VAs");
        const auto via_module = opened->watch_execute_at(
            reinterpret_cast<void*>(std::uintptr_t{0x10000000}), 0x80, 0x1000,
            4096, pid{42});
        test::check(via_module && fake::last_watch.base == 0x10000000 &&
                        fake::last_watch.address == 0x80 &&
                        fake::last_watch.dump_base == 0x1000 &&
                        fake::last_watch.pid == 42,
                    "module-relative arm keeps base + offsets");
        test::check(
            denied(opened->watch_execute(nullptr,
                                         reinterpret_cast<void*>(
                                             std::uintptr_t{0x710000}),
                                         0x1020, pid{1}),
                   ERROR_INVALID_PARAMETER),
            "null address rejected client-side");
        test::check(
            denied(opened->watch_execute(
                       reinterpret_cast<void*>(std::uintptr_t{0x700080}),
                       reinterpret_cast<void*>(std::uintptr_t{0x710000}),
                       blook::max_dump + 1, pid{1}),
                   ERROR_INVALID_PARAMETER),
            "oversized dump rejected client-side");

        const auto hit = armed->poll();
        test::check(hit && hit->ready && hit->rip == 0x1234 &&
                        hit->cr3 == 1 && hit->total == fake::dump_bytes.size(),
                    "poll reports the hit");
        std::array<std::byte, 3> slice{};
        const auto piece = armed->read(2, slice);
        test::check(piece && *piece == 3 &&
                        slice[0] == std::byte{fake::dump_bytes[2]} &&
                        slice[2] == std::byte{fake::dump_bytes[4]},
                    "chunked read maps offsets");
        const auto full = armed->dump();
        test::check(full && full->size() == fake::dump_bytes.size() &&
                        std::memcmp(full->data(), fake::dump_bytes.data(),
                                    full->size()) == 0,
                    "full dump reassembles chunks");

        // The RAII tail: moved-from handles are inert, destruction disarms.
        auto moved_watch = std::move(*armed);
        test::check(armed->id() == 0 && !*armed &&
                        armed->disarm().has_value(),
                    "moved-from watch is inert");
        test::check(moved_watch.disarm().has_value() &&
                        moved_watch.id() == 0,
                    "disarm clears the handle");
    }

    test::check(!valid(connection_handle),
                "session destruction closes connection");
    detail::connection unopened;
    const auto invalid = unopened.call(0, nullptr, 0, nullptr, 0);
    test::check(!invalid && invalid.error().value() ==
                                static_cast<int>(ERROR_INVALID_HANDLE),
                "empty connection rejected");
    HANDLE shared_handle{};
    {
        auto connection = std::make_shared<detail::connection>();
        connection->handle.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        shared_handle = connection->handle.get();
        test::check(valid(shared_handle), "create shared connection event");
        hook owner{connection, 0};
        connection.reset();
        test::check(valid(shared_handle), "hook retains shared connection");
        hook moved_owner{std::move(owner)};
        test::check(owner.id() == 0 && !owner && owner.remove().has_value(),
                    "moved hook cleanup is inert");
    }
    test::check(!valid(shared_handle), "last shared owner closes connection");
    hook invalid_owner{nullptr, 1};
    const auto invalid_remove = invalid_owner.remove();
    const auto invalid_refresh = invalid_owner.refresh();
    test::check(denied(invalid_remove, ERROR_INVALID_HANDLE),
                "null hook connection rejected");
    test::check(denied(invalid_refresh, ERROR_INVALID_HANDLE),
                "null hook refresh rejected");
    return test::finish();
}
