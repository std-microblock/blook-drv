#pragma once

#include "error.hpp"
namespace core {

template <typename E>
struct unexpected {
    E error;

    constexpr explicit unexpected(E e) : error(e) {}
};

template <typename T, typename E>
class expected {
   public:
    // Value constructors
    constexpr expected() : has_val_(false), error_(E{}) {}

    constexpr expected(const T& val) : has_val_(true), value_(val) {}
    constexpr expected(T&& val)
        : has_val_(true), value_(static_cast<T&&>(val)) {}

    // Error constructor
    constexpr expected(const unexpected<E>& err)
        : has_val_(false), error_(err.error) {}
    constexpr expected(unexpected<E>&& err)
        : has_val_(false), error_(static_cast<E&&>(err.error)) {}

    // Copy/move
    constexpr expected(const expected& other) : has_val_(other.has_val_) {
        if (has_val_) {
            ::new (&value_) T(other.value_);
        } else {
            error_ = other.error_;
        }
    }

    constexpr expected(expected&& other) : has_val_(other.has_val_) {
        if (has_val_) {
            ::new (&value_) T(static_cast<T&&>(other.value_));
        } else {
            error_ = static_cast<E&&>(other.error_);
        }
    }

    ~expected() {
        if (has_val_) {
            value_.~T();
        }
    }

    // Assignment
    constexpr expected& operator=(const expected& other) {
        if (this == &other)
            return *this;

        if (has_val_ && other.has_val_) {
            value_ = other.value_;
        } else if (has_val_ && !other.has_val_) {
            value_.~T();
            ::new (&error_) E(other.error_);
            has_val_ = false;
        } else if (!has_val_ && other.has_val_) {
            ::new (&value_) T(other.value_);
            has_val_ = true;
        } else {
            error_ = other.error_;
        }

        return *this;
    }

    constexpr expected& operator=(expected&& other) {
        if (this != &other) {
            if (has_val_) {
                value_.~T();
            }
            has_val_ = other.has_val_;
            if (has_val_) {
                ::new (&value_) T(static_cast<T&&>(other.value_));
            } else {
                error_ = static_cast<E&&>(other.error_);
            }
        }
        return *this;
    }

    // Accessors
    [[nodiscard]] constexpr bool has_value() const { return has_val_; }
    [[nodiscard]] constexpr explicit operator bool() const { return has_val_; }

    [[nodiscard]] constexpr T& value() & { return value_; }
    [[nodiscard]] constexpr const T& value() const& { return value_; }
    [[nodiscard]] constexpr T&& value() && { return static_cast<T&&>(value_); }

    [[nodiscard]] constexpr E& error() & { return error_; }
    [[nodiscard]] constexpr const E& error() const& { return error_; }
    [[nodiscard]] constexpr E&& error() && { return static_cast<E&&>(error_); }

    // Pointer-like access
    [[nodiscard]] constexpr T* operator->() { return &value_; }
    [[nodiscard]] constexpr const T* operator->() const { return &value_; }
    [[nodiscard]] constexpr T& operator*() & { return value_; }
    [[nodiscard]] constexpr const T& operator*() const& { return value_; }

    // Value or default
    template <typename U>
    [[nodiscard]] constexpr T value_or(U&& default_val) const& {
        return has_val_ ? value_
                        : static_cast<T>(static_cast<U&&>(default_val));
    }

   private:
    bool has_val_;
    union {
        T value_;
        E error_;
    };
};

// Specialization for void
template <typename E>
class expected<void, E> {
   public:
    constexpr expected() : has_val_(true), error_(E{}) {}

    constexpr expected(const unexpected<E>& err)
        : has_val_(false), error_(err.error) {}
    constexpr expected(unexpected<E>&& err)
        : has_val_(false), error_(static_cast<E&&>(err.error)) {}

    [[nodiscard]] constexpr bool has_value() const { return has_val_; }
    [[nodiscard]] constexpr explicit operator bool() const { return has_val_; }

    [[nodiscard]] constexpr E& error() & { return error_; }
    [[nodiscard]] constexpr const E& error() const& { return error_; }

   private:
    bool has_val_;
    E error_;
};

template <typename T, typename E>
class expected<T&, E> {
public:
    constexpr expected(T& val) : has_val_(true), val_ptr_(&val) {}
    
    constexpr expected(const unexpected<E>& err) 
        : has_val_(false), error_(err.error) {}
    constexpr expected(unexpected<E>&& err) 
        : has_val_(false), error_(static_cast<E&&>(err.error)) {}

    [[nodiscard]] constexpr bool has_value() const { return has_val_; }
    [[nodiscard]] constexpr explicit operator bool() const { return has_val_; }

    [[nodiscard]] constexpr T* operator->() const { return val_ptr_; }
    [[nodiscard]] constexpr T& operator*() const { return *val_ptr_; }
    [[nodiscard]] constexpr T& value() const { return *val_ptr_; }

    [[nodiscard]] constexpr const E& error() const { return error_; }

private:
    bool has_val_;
    union {
        T* val_ptr_;
        E error_;
    };
};

// Helper type aliases using ErrorCode
template <typename T>
using Result = expected<T, ErrorCode>;

using VoidResult = expected<void, ErrorCode>;

// Helper function to create success result
inline VoidResult ok() {
    return VoidResult{};
}

template <typename T>
Result<T> ok(T&& value) {
    return Result<T>{static_cast<T&&>(value)};
}

// Helper function to create error result
inline unexpected<ErrorCode> err(ErrorCode code) {
    return unexpected<ErrorCode>{code};
}

}  // namespace core
