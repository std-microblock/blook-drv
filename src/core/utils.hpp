#pragma once

#include <ntifs.h>
#include <windef.h>

#include "Veil.h"


namespace core {

// Pattern matching - uses hex string format
// Example: "4123FF66" or "41??FF66" (where ?? means wildcard)
uintptr_t find_pattern(uintptr_t base, size_t size, const char* hex_pattern);

// Find pattern in a specific PE section
uintptr_t find_pattern_section(uintptr_t base, const char* section_name,
                               const char* hex_pattern);

// Find pattern in a kernel module
uintptr_t find_pattern_km(const wchar_t* module_name, const char* section_name,
                          const char* hex_pattern);

// Get system routine by name
void* get_system_routine(const wchar_t* routine_name);

// Get ntoskrnl base address
uintptr_t get_ntos_base();

// Initialize core utilities
bool init();

// Get kernel module base address
uintptr_t get_kernel_module_base(const wchar_t* module_name);

// Global kernel pointers
inline PLIST_ENTRY PsLoadedModuleList = nullptr;
inline PERESOURCE PsLoadedModuleResource = nullptr;

// Type traits
// integral_constant
template <typename T, T v>
struct integral_constant {
    static constexpr T value = v;
    using value_type = T;
    using type = integral_constant;
    constexpr operator value_type() const noexcept { return value; }
    constexpr value_type operator()() const noexcept { return value; }
};

using true_type = integral_constant<bool, true>;
using false_type = integral_constant<bool, false>;

template <typename T>
struct remove_reference {
    using type = T;
};

template <typename T>
struct remove_reference<T&> {
    using type = T;
};

template <typename T>
struct remove_reference<T&&> {
    using type = T;
};

template <typename T>
using remove_reference_t = typename remove_reference<T>::type;

template <typename T>
struct is_lvalue_reference : false_type {};

template <typename T>
struct is_lvalue_reference<T&> : true_type {};

template <typename T>
inline constexpr bool is_lvalue_reference_v = is_lvalue_reference<T>::value;

template <typename T>
struct is_rvalue_reference : false_type {};

template <typename T>
struct is_rvalue_reference<T&&> : true_type {};

template <typename T>
inline constexpr bool is_rvalue_reference_v = is_rvalue_reference<T>::value;

template <typename T>
struct remove_pointer {
    using type = T;
};

template <typename T>
struct remove_pointer<T*> {
    using type = T;
};

template <typename T>
struct remove_pointer<T* const> {
    using type = T;
};

template <typename T>
struct remove_pointer<T* volatile> {
    using type = T;
};

template <typename T>
struct remove_pointer<T* const volatile> {
    using type = T;
};

template <typename T>
using remove_pointer_t = typename remove_pointer<T>::type;

template <typename T>
T&& forward(remove_reference_t<T>& arg) noexcept {
    return static_cast<T&&>(arg);
}

template <typename T>
T&& forward(remove_reference_t<T>&& arg) noexcept {
    static_assert(!is_lvalue_reference_v<T>,
                  "Cannot forward an rvalue as an lvalue");
    return static_cast<T&&>(arg);
}

template <typename T>
remove_reference_t<T>&& move(T&& arg) noexcept {
    return static_cast<remove_reference_t<T>&&>(arg);
}

}  // namespace core
