#pragma once
#include <stddef.h>

#include "policy/integer.hpp"

// Fixed-width, pointer-free METHOD_BUFFERED ABI. READ|WRITE access is
// mandatory, and the device ACL restricts the device to SYSTEM and
// Administrators. Nothing in this ABI accepts a physical address, a page
// frame number or an arbitrary kernel pointer.
namespace ipc {
inline constexpr auto kDeviceName = L"\\Device\\BlookDrv";
inline constexpr auto kSymbolicLink = L"\\DosDevices\\BlookDrv";
inline constexpr auto kUserModePath = L"\\\\.\\BlookDrv";

constexpr uint32_t ioctl(uint32_t n) {
    return (0x22u << 16) | (3u << 14) | ((0x800u + n) << 2);
}
inline constexpr auto IOCTL_BLOOK_PING = ioctl(0);
inline constexpr auto IOCTL_BLOOK_GET_VERSION = ioctl(1);
inline constexpr auto IOCTL_BLOOK_ENABLE = ioctl(2);
inline constexpr auto IOCTL_BLOOK_INSTALL = ioctl(3);
inline constexpr auto IOCTL_BLOOK_REMOVE = ioctl(4);
inline constexpr auto IOCTL_BLOOK_REFRESH = ioctl(5);
inline constexpr auto IOCTL_BLOOK_QUERY = ioctl(6);
inline constexpr auto IOCTL_BLOOK_HIDE = ioctl(7);
inline constexpr auto IOCTL_BLOOK_SCRUB = ioctl(8);
inline constexpr auto IOCTL_BLOOK_STATS = ioctl(9);

inline constexpr uint32_t abi_version = 4;

struct Header {
    uint32_t version{abi_version};
    uint32_t size{};
};

struct PingRequest {
    Header header{};
    uint32_t magic{};
    static constexpr uint32_t kMagic = 0x424c4f4b;
};
struct PingResponse {
    uint32_t magic{}, status{};
    static constexpr uint32_t kMagic = 0x4b4f4c42, kStatusOk = 0;
};
struct VersionInfo {
    uint16_t major, minor, patch, reserved;
};
inline constexpr VersionInfo kDriverVersion{3, 0, 0, 0};

// Diagnostic counters for the user-mode hook path. Purely observational: the
// numbers say which branch a page access took, which is the only way to tell
// "the hook never fired" apart from "the page was never fetched".
struct StatsRequest {
    Header header{};
};
struct StatsResponse {
    Header header{};
    uint64_t execute_violations{};
    uint64_t data_violations{};
    uint64_t window_open{};
    uint64_t identity_ok{};
    uint64_t identity_mismatch{};
    uint64_t identity_failed{};
    uint64_t internal_entry{};
    uint64_t shadow_mapped{};
    uint64_t original_step{};
    uint64_t unowned_group{};
};
static_assert(sizeof(StatsResponse) <= 128);

struct EnableRequest {
    Header header{};
};
struct InstallRequest {
    Header header{};
    uint32_t pid{};
    uint32_t flags{};
    uint64_t target{};
    uint32_t length{};
    uint32_t reserved{};
    uint8_t bytes[64]{};
};
struct InstallResponse {
    uint64_t id{};
};
struct HookRequest {
    Header header{};
    uint64_t id{};
};
// enable_hide: 0 = deactivate, 1 = activate, 2 = pin the given pid to a role,
// 3 = unpin it. Roles are the same ones the image-name policy uses.
inline constexpr uint32_t hide_role_tool = 1;
inline constexpr uint32_t hide_role_target = 2;
// Window hides are a separate switch because they patch win32k: on a build
// where the win32kfull export table cannot be resolved they are simply left
// off instead of guessing.
inline constexpr uint32_t hide_windows_on = 4;
inline constexpr uint32_t hide_windows_off = 5;
struct HideRequest {
    Header header{};
    uint32_t enable_hide{};
    uint32_t pid{};
    uint32_t role{};
    uint32_t reserved{};
};
// scrub flags: bit 0 = PEB flags, bit 1 = heap flags. Hardware breakpoints are
// covered by the NtGetContextThread hook rather than by rewriting a context.
inline constexpr uint32_t scrub_peb = 1;
inline constexpr uint32_t scrub_heap = 2;
inline constexpr uint32_t scrub_all = scrub_peb | scrub_heap;
struct ScrubRequest {
    Header header{};
    uint32_t pid{};
    uint32_t flags{};
};
struct QueryResponse {
    uint32_t version{}, running{}, enabled{}, hooks{};
    uint32_t hidden{};
    uint32_t abi{};
    int32_t backend_status{};
    // Number of win32k window hooks that are actually installed, so a machine
    // where the win32kfull exports could not be resolved is visible instead of
    // silently hiding nothing.
    uint32_t window_hooks{};
};

// ABI v4 layout: fail compilation rather than silently changing the wire
// format.
static_assert(sizeof(Header) == 8 && alignof(Header) == 4);
static_assert(offsetof(Header, version) == 0);
static_assert(offsetof(Header, size) == 4);

static_assert(sizeof(PingRequest) == 12 && alignof(PingRequest) == 4);
static_assert(offsetof(PingRequest, header) == 0);
static_assert(offsetof(PingRequest, magic) == 8);

static_assert(sizeof(PingResponse) == 8 && alignof(PingResponse) == 4);
static_assert(offsetof(PingResponse, magic) == 0);
static_assert(offsetof(PingResponse, status) == 4);

static_assert(sizeof(VersionInfo) == 8 && alignof(VersionInfo) == 2);
static_assert(offsetof(VersionInfo, major) == 0);
static_assert(offsetof(VersionInfo, minor) == 2);
static_assert(offsetof(VersionInfo, patch) == 4);
static_assert(offsetof(VersionInfo, reserved) == 6);

static_assert(sizeof(EnableRequest) == 8 && alignof(EnableRequest) == 4);
static_assert(offsetof(EnableRequest, header) == 0);

static_assert(sizeof(InstallRequest) == 96 && alignof(InstallRequest) == 8);
static_assert(offsetof(InstallRequest, header) == 0);
static_assert(offsetof(InstallRequest, pid) == 8);
static_assert(offsetof(InstallRequest, flags) == 12);
static_assert(offsetof(InstallRequest, target) == 16);
static_assert(offsetof(InstallRequest, length) == 24);
static_assert(offsetof(InstallRequest, reserved) == 28);
static_assert(offsetof(InstallRequest, bytes) == 32);

static_assert(sizeof(InstallResponse) == 8 && alignof(InstallResponse) == 8);
static_assert(offsetof(InstallResponse, id) == 0);

static_assert(sizeof(HookRequest) == 16 && alignof(HookRequest) == 8);
static_assert(offsetof(HookRequest, header) == 0);
static_assert(offsetof(HookRequest, id) == 8);

static_assert(sizeof(HideRequest) == 24 && alignof(HideRequest) == 4);
static_assert(offsetof(HideRequest, header) == 0);
static_assert(offsetof(HideRequest, enable_hide) == 8);
static_assert(offsetof(HideRequest, pid) == 12);
static_assert(offsetof(HideRequest, role) == 16);
static_assert(offsetof(HideRequest, reserved) == 20);

static_assert(sizeof(ScrubRequest) == 16 && alignof(ScrubRequest) == 4);
static_assert(offsetof(ScrubRequest, header) == 0);
static_assert(offsetof(ScrubRequest, pid) == 8);
static_assert(offsetof(ScrubRequest, flags) == 12);

static_assert(sizeof(QueryResponse) == 32 && alignof(QueryResponse) == 4);
static_assert(offsetof(QueryResponse, version) == 0);
static_assert(offsetof(QueryResponse, running) == 4);
static_assert(offsetof(QueryResponse, enabled) == 8);
static_assert(offsetof(QueryResponse, hooks) == 12);
static_assert(offsetof(QueryResponse, hidden) == 16);
static_assert(offsetof(QueryResponse, abi) == 20);
static_assert(offsetof(QueryResponse, backend_status) == 24);
static_assert(offsetof(QueryResponse, window_hooks) == 28);

namespace detail {
template <class T, class U>
inline constexpr bool same_type = false;
template <class T>
inline constexpr bool same_type<T, T> = true;
}  // namespace detail

// Exact request types only: a look-alike header does not establish a wire ABI.
// Keep this constraint independent of STL headers for WDK /kernel builds.
template <class T>
concept WireRequest =
    detail::same_type<T, PingRequest> || detail::same_type<T, EnableRequest> ||
    detail::same_type<T, InstallRequest> || detail::same_type<T, HookRequest> ||
    detail::same_type<T, HideRequest> || detail::same_type<T, ScrubRequest>;

template <WireRequest T>
[[nodiscard]] constexpr T request() noexcept {
    T value{};
    value.header.version = abi_version;
    value.header.size = sizeof(T);
    return value;
}

template <WireRequest T>
[[nodiscard]] constexpr bool valid_header(const T& value) noexcept {
    return value.header.version == abi_version &&
           value.header.size == sizeof(T);
}
}  // namespace ipc
