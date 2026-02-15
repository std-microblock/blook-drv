#pragma once

//
// IPC Protocol definitions shared between driver and user-mode
//

#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <windows.h>
#endif

namespace ipc {

//
// Device name and symbolic link
//
constexpr const wchar_t* kDeviceName = L"\\Device\\BlookDrv";
constexpr const wchar_t* kSymbolicLink = L"\\DosDevices\\BlookDrv";
constexpr const wchar_t* kUserModePath = L"\\\\.\\BlookDrv";

//
// IOCTL codes
//
constexpr unsigned long kIoctlBase = 0x800;

#define BLOOK_CTL_CODE(code) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, kIoctlBase + (code), METHOD_BUFFERED, FILE_ANY_ACCESS)

constexpr unsigned long IOCTL_BLOOK_PING = BLOOK_CTL_CODE(0);
constexpr unsigned long IOCTL_BLOOK_GET_VERSION = BLOOK_CTL_CODE(1);

//
// Ping request/response
//
struct PingRequest {
    unsigned long magic;
    static constexpr unsigned long kMagic = 0x424C4F4B;  // "BLOK"
};

struct PingResponse {
    unsigned long magic;
    unsigned long status;
    static constexpr unsigned long kMagic = 0x4B4F4C42;  // "KOLB"
    static constexpr unsigned long kStatusOk = 0;
};

//
// Version info
//
struct VersionInfo {
    unsigned short major;
    unsigned short minor;
    unsigned short patch;
    unsigned short reserved;
};

constexpr VersionInfo kDriverVersion = { 1, 0, 0, 0 };

}  // namespace ipc
