#include "ipc/protocol.hpp"

#include <gtest/gtest.h>

#include <array>
#include <concepts>
#include <cstddef>
#include <initializer_list>
#include <type_traits>

namespace {
template <class... Ts>
constexpr bool wire_value_types =
    ((std::is_standard_layout_v<Ts> && std::is_trivially_copyable_v<Ts>) &&
     ...);

static_assert(
    wire_value_types<ipc::Header, ipc::PingRequest, ipc::PingResponse,
                     ipc::VersionInfo, ipc::EnableRequest, ipc::InstallRequest,
                     ipc::InstallResponse, ipc::HookRequest, ipc::HideRequest,
                     ipc::ScrubRequest, ipc::QueryResponse, ipc::WatchRequest,
                     ipc::WatchResponse, ipc::DumpRequest, ipc::DumpResponse>);

template <class T>
concept HasFactory = requires {
    { ipc::request<T>() } noexcept -> std::same_as<T>;
};
template <class T>
concept HasHeaderValidator = requires(const T& value) {
    { ipc::valid_header<T>(value) } noexcept -> std::same_as<bool>;
};

struct HeaderLookalike {
    ipc::Header header{};
};
struct DerivedRequest : ipc::EnableRequest {};

template <class... Ts>
constexpr bool rejected_types =
    ((!HasFactory<Ts> && !HasHeaderValidator<Ts>) && ...);
static_assert(
    rejected_types<int, ipc::Header, ipc::PingResponse, ipc::VersionInfo,
                   ipc::InstallResponse, ipc::QueryResponse, ipc::WatchResponse,
                   ipc::DumpResponse, HeaderLookalike, DerivedRequest,
                   const ipc::PingRequest, volatile ipc::PingRequest,
                   ipc::PingRequest&>);

constexpr bool initialized_fields(const ipc::PingRequest& value) {
    return value.magic == 0;
}
constexpr bool initialized_fields(const ipc::EnableRequest&) {
    return true;  // No payload fields.
}
constexpr bool initialized_fields(const ipc::InstallRequest& value) {
    if (value.pid != 0 || value.flags != 0 || value.target != 0 ||
        value.length != 0 || value.reserved != 0)
        return false;
    for (const auto byte : value.bytes)
        if (byte != 0)
            return false;
    return true;
}
constexpr bool initialized_fields(const ipc::HookRequest& value) {
    return value.id == 0;
}
constexpr bool initialized_fields(const ipc::HideRequest& value) {
    return value.enable_hide == 0 && value.pid == 0 && value.role == 0 &&
           value.reserved == 0;
}
constexpr bool initialized_fields(const ipc::ScrubRequest& value) {
    return value.pid == 0 && value.flags == 0;
}
constexpr bool initialized_fields(const ipc::WatchRequest& value) {
    return value.address == 0 && value.base == 0 && value.dump_base == 0 &&
           value.dump_size == 0 && value.id == 0 && value.pid == 0 &&
           value.action == 0;
}
constexpr bool initialized_fields(const ipc::DumpRequest& value) {
    return value.id == 0 && value.offset == 0 && value.length == 0 &&
           value.reserved == 0;
}

template <ipc::WireRequest T>
constexpr bool factory_contract() {
    const auto value = ipc::request<T>();
    return HasFactory<T> && HasHeaderValidator<T> &&
           value.header.version == 5 && value.header.size == sizeof(T) &&
           ipc::valid_header(value) && initialized_fields(value);
}
static_assert(factory_contract<ipc::PingRequest>());
static_assert(factory_contract<ipc::EnableRequest>());
static_assert(factory_contract<ipc::InstallRequest>());
static_assert(factory_contract<ipc::HookRequest>());
static_assert(factory_contract<ipc::HideRequest>());
static_assert(factory_contract<ipc::ScrubRequest>());
static_assert(factory_contract<ipc::WatchRequest>());
static_assert(factory_contract<ipc::DumpRequest>());

static_assert(ipc::abi_version == 5);
static_assert(ipc::PingRequest::kMagic == 0x424c4f4b);
static_assert(ipc::PingResponse::kMagic == 0x4b4f4c42);
static_assert(ipc::PingResponse::kStatusOk == 0);
static_assert(ipc::kDriverVersion.major == 3 &&
              ipc::kDriverVersion.minor == 0 &&
              ipc::kDriverVersion.patch == 0 &&
              ipc::kDriverVersion.reserved == 0);
static_assert(ipc::hide_role_tool == 1 && ipc::hide_role_target == 2);
static_assert(ipc::hide_windows_on == 4 && ipc::hide_windows_off == 5);
static_assert(ipc::scrub_peb == 1 && ipc::scrub_heap == 2 &&
              ipc::scrub_all == 3);
static_assert(ipc::watch_arm == 1 && ipc::watch_disarm == 2);

constexpr std::array ioctls{
    ipc::IOCTL_BLOOK_PING,   ipc::IOCTL_BLOOK_GET_VERSION,
    ipc::IOCTL_BLOOK_ENABLE, ipc::IOCTL_BLOOK_INSTALL,
    ipc::IOCTL_BLOOK_REMOVE, ipc::IOCTL_BLOOK_REFRESH,
    ipc::IOCTL_BLOOK_QUERY,  ipc::IOCTL_BLOOK_HIDE,
    ipc::IOCTL_BLOOK_SCRUB,  ipc::IOCTL_BLOOK_STATS,
    ipc::IOCTL_BLOOK_PROBE,  ipc::IOCTL_BLOOK_WATCH,
    ipc::IOCTL_BLOOK_DUMP,
};
constexpr bool ioctl_contract() {
    for (std::size_t i = 0; i < ioctls.size(); ++i) {
        const auto code = ioctls[i];
        if (code != 0x0022e000u + 4u * i || (code & 3u) != 0 ||
            ((code >> 14) & 3u) != 3 || (code >> 16) != 0x22u ||
            ((code >> 2) & 0xfffu) != 0x800u + i)
            return false;
        for (std::size_t j = i + 1; j < ioctls.size(); ++j)
            if (code == ioctls[j])
                return false;
    }
    return true;
}
static_assert(ioctl_contract());

template <ipc::WireRequest T>
void test_request() {
    auto value = ipc::request<T>();
    ASSERT_TRUE((value.header.version == 5)) << "factory initializes ABI v5";
    ASSERT_TRUE((value.header.size == sizeof(T)))
        << "factory initializes exact wire size";
    ASSERT_TRUE((ipc::valid_header(value)))
        << "factory produces a valid header";
    // Inspect named fields only: padding bytes are not part of this contract.
    ASSERT_TRUE((initialized_fields(value)))
        << "factory initializes all payload fields";
    ASSERT_TRUE((!ipc::valid_header(T{}))) << "default request lacks wire size";

    for (const uint32_t version : {0u, 3u, 4u, 6u, 0xffffffffu}) {
        value = ipc::request<T>();
        value.header.version = version;
        ASSERT_TRUE((!ipc::valid_header(value)))
            << "reject unsupported version with valid size";
    }
    for (const uint32_t size :
         {0u, static_cast<uint32_t>(sizeof(T) - 1),
          static_cast<uint32_t>(sizeof(T) + 1), 0xffffffffu}) {
        value = ipc::request<T>();
        value.header.size = size;
        ASSERT_TRUE((!ipc::valid_header(value)))
            << "reject invalid size with valid version";
    }
    value.header.version = 0;
    ASSERT_TRUE((!ipc::valid_header(value)))
        << "reject invalid version and size together";
    value = ipc::request<T>();
    ASSERT_TRUE((ipc::valid_header(value))) << "restored header is valid";
}

TEST(ProtocolTest, ResponseValueInitialization) {
    const ipc::Header header{};
    ASSERT_TRUE((header.version == 5 && header.size == 0))
        << "header member defaults";
    const ipc::PingResponse ping{};
    ASSERT_TRUE((ping.magic == 0 && ping.status == 0))
        << "ping response member defaults";
    const ipc::VersionInfo version{};
    ASSERT_TRUE((version.major == 0 && version.minor == 0 &&
                 version.patch == 0 && version.reserved == 0))
        << "version value initialization";
    const ipc::InstallResponse install{};
    ASSERT_TRUE((install.id == 0)) << "install response member defaults";
    const ipc::QueryResponse query{};
    ASSERT_TRUE((query.version == 0 && query.running == 0 &&
                 query.enabled == 0 && query.hooks == 0 && query.hidden == 0 &&
                 query.abi == 0 && query.backend_status == 0 &&
                 query.window_hooks == 0))
        << "query response member defaults";
}

TEST(ProtocolTest, IoctlNumericAbiAndUniqueness) {
    for (std::size_t i = 0; i < ioctls.size(); ++i) {
        const auto code = ioctls[i];
        ASSERT_TRUE((code == 0x0022e000u + 4u * i))
            << "IOCTL numeric ABI unchanged";
        ASSERT_TRUE(((code & 3u) == 0)) << "IOCTL uses METHOD_BUFFERED";
        ASSERT_TRUE((((code >> 14) & 3u) == 3))
            << "IOCTL requires both READ and WRITE";
        ASSERT_TRUE(((code >> 16) == 0x22u))
            << "IOCTL uses FILE_DEVICE_UNKNOWN";
        ASSERT_TRUE((((code >> 2) & 0xfffu) == 0x800u + i))
            << "IOCTL function unchanged";
        for (std::size_t j = i + 1; j < ioctls.size(); ++j)
            ASSERT_TRUE((code != ioctls[j]))
                << "IOCTL values are pairwise unique";
    }
}

TEST(ProtocolTest, PingRequestFactoryAndHeaderValidation) {
    test_request<ipc::PingRequest>();
}

TEST(ProtocolTest, EnableRequestFactoryAndHeaderValidation) {
    test_request<ipc::EnableRequest>();
}

TEST(ProtocolTest, InstallRequestFactoryAndHeaderValidation) {
    test_request<ipc::InstallRequest>();
}

TEST(ProtocolTest, HookRequestFactoryAndHeaderValidation) {
    test_request<ipc::HookRequest>();
}

TEST(ProtocolTest, HideRequestFactoryAndHeaderValidation) {
    test_request<ipc::HideRequest>();
}

TEST(ProtocolTest, ScrubRequestFactoryAndHeaderValidation) {
    test_request<ipc::ScrubRequest>();
}

TEST(ProtocolTest, WatchRequestFactoryAndHeaderValidation) {
    test_request<ipc::WatchRequest>();
}

TEST(ProtocolTest, DumpRequestFactoryAndHeaderValidation) {
    test_request<ipc::DumpRequest>();
}
}  // namespace
