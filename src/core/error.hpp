#pragma once

// Core utilities for kernel mode driver
// No dynamic memory allocation - all stack/static based

namespace core {

// Error codes for expected<T, E> style error handling
enum class ErrorCode {
    Success = 0,

    // General errors
    InvalidArgument,
    NullPointer,
    NotInitialized,
    AlreadyInitialized,
    NotFound,
    OutOfRange,

    // SSDT specific errors
    KlhkNotLoaded,
    KlhkInitFailed,
    HvmInitFailed,
    SsdtNotBuilt,
    InvalidSsdtIndex,
    AlreadyHooked,
    NotHooked,
    HookFailed,
    UnhookFailed,

    // IPC errors
    IpcFailed,
    InvalidCommand,
    BufferTooSmall,

    // Service errors
    ServiceCreateFailed,
    ServiceStartFailed,
    ServiceStopFailed,
    ServiceDeleteFailed,
};

// Get error description
inline const char* error_to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::Success:
            return "Success";
        case ErrorCode::InvalidArgument:
            return "Invalid argument";
        case ErrorCode::NullPointer:
            return "Null pointer";
        case ErrorCode::NotInitialized:
            return "Not initialized";
        case ErrorCode::AlreadyInitialized:
            return "Already initialized";
        case ErrorCode::NotFound:
            return "Not found";
        case ErrorCode::OutOfRange:
            return "Out of range";
        case ErrorCode::KlhkNotLoaded:
            return "klhk.sys not loaded";
        case ErrorCode::KlhkInitFailed:
            return "klhk.sys initialization failed";
        case ErrorCode::HvmInitFailed:
            return "HVM initialization failed";
        case ErrorCode::SsdtNotBuilt:
            return "SSDT not built";
        case ErrorCode::InvalidSsdtIndex:
            return "Invalid SSDT index";
        case ErrorCode::AlreadyHooked:
            return "Already hooked";
        case ErrorCode::NotHooked:
            return "Not hooked";
        case ErrorCode::HookFailed:
            return "Hook failed";
        case ErrorCode::UnhookFailed:
            return "Unhook failed";
        case ErrorCode::IpcFailed:
            return "IPC failed";
        case ErrorCode::InvalidCommand:
            return "Invalid command";
        case ErrorCode::BufferTooSmall:
            return "Buffer too small";
        case ErrorCode::ServiceCreateFailed:
            return "Service creation failed";
        case ErrorCode::ServiceStartFailed:
            return "Service start failed";
        case ErrorCode::ServiceStopFailed:
            return "Service stop failed";
        case ErrorCode::ServiceDeleteFailed:
            return "Service deletion failed";
        default:
            return "Unknown error";
    }
}

}  // namespace core
