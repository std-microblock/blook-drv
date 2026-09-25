#pragma once
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

inline constexpr uint32_t abi_version = 4;

struct Header {
    uint32_t version{abi_version};
    uint32_t size{};
};

template <class T>
[[nodiscard]] constexpr T request() noexcept {
    T value{};
    value.header.version = abi_version;
    value.header.size = sizeof(T);
    return value;
}

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

static_assert(sizeof(InstallRequest) == 96 && sizeof(InstallResponse) == 8);
static_assert(sizeof(HookRequest) == 16 && sizeof(QueryResponse) == 32);
static_assert(sizeof(HideRequest) == 24 && sizeof(ScrubRequest) == 16);

template <class T>
[[nodiscard]] constexpr bool valid_header(const T& value) noexcept {
    return value.header.version == abi_version &&
           value.header.size == sizeof(T);
}
}  // namespace ipc
