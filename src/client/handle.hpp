#pragma once

#include <windows.h>

#include <utility>

namespace blook::client {
// Owns only CloseHandle-compatible objects. Registry and SCM handles need
// their own deleters. A moved-from owner is empty and can be reused.
class unique_handle final {
    HANDLE value_{INVALID_HANDLE_VALUE};

   public:
    unique_handle() noexcept = default;
    explicit unique_handle(HANDLE value) noexcept : value_(value) {}
    unique_handle(const unique_handle&) = delete;
    unique_handle& operator=(const unique_handle&) = delete;
    unique_handle(unique_handle&& other) noexcept : value_(other.release()) {}
    unique_handle& operator=(unique_handle&& other) noexcept {
        if (this != &other)
            reset(other.release());
        return *this;
    }
    ~unique_handle() { reset(); }

    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }
    [[nodiscard]] HANDLE release() noexcept {
        return std::exchange(value_, INVALID_HANDLE_VALUE);
    }
    void reset(HANDLE value = INVALID_HANDLE_VALUE) noexcept {
        if (value_ == value)
            return;
        const auto previous = std::exchange(value_, value);
        if (previous != nullptr && previous != INVALID_HANDLE_VALUE) {
            // Destruction must not overwrite the error from the failed API that
            // caused stack unwinding / an early return.
            const auto error = GetLastError();
            CloseHandle(previous);
            SetLastError(error);
        }
    }
};
}  // namespace blook::client
