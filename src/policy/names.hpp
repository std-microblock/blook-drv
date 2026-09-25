#pragma once
#include <stddef.h>

#include "policy/integer.hpp"

// Name-based classification of the two sides of an analysis session.
//
//   target : the image under analysis. Every anti-anti-debug hook applies
//            when the *calling* thread belongs to one of these images, so the
//            sample keeps seeing a pristine environment.
//   tool   : the analyst debugger / scanner / monitor. These images are the
//            ones stripped out of enumeration queries and window lookups, and
//            they keep seeing the real system so the analyst can work.
//   watched: interesting but neither hidden nor protected; used for logging.
//
// The lists mirror the previous implementation process_manager tables so the
// migrated hooks keep behaving exactly as before. Matching is a
// case-insensitive substring test against the full image path.
namespace blook {
namespace names {

inline constexpr const wchar_t* target_images[] = {
    L"al-khaser_x64.exe",
    L"test_app.exe",
    L"ctf-target-",
};

inline constexpr const wchar_t* tool_images[] = {
    L"x64dbg.exe",   L"x32dbg.exe",         L"windbg.exe",
    L"cheatengine-", L"systeminformer.exe", L"processhacker.exe",
    L"frida.exe",    L"opencode.exe",       L"opencode-cli.exe",
};

inline constexpr const wchar_t* watched_images[] = {
    L"taskmgr.exe",
};

// Modules hidden from SystemModuleInformation so the sample cannot find the
// hypervisor driver that is doing the hiding.
inline constexpr const char* hidden_modules[] = {
    "blook-drv.sys",
};

}  // namespace names

[[nodiscard]] constexpr wchar_t ascii_lower(wchar_t value) noexcept {
    return value >= L'A' && value <= L'Z'
               ? static_cast<wchar_t>(value + (L'a' - L'A'))
               : value;
}

[[nodiscard]] constexpr char ascii_lower(char value) noexcept {
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A'))
                                        : value;
}

template <class Char>
[[nodiscard]] constexpr size_t text_length(const Char* text) noexcept {
    size_t length = 0;
    while (text && text[length])
        ++length;
    return length;
}

template <class Char>
[[nodiscard]] constexpr bool contains(const Char* haystack, size_t length,
                                      const Char* needle) noexcept {
    const auto needle_length = text_length(needle);
    if (!haystack || !needle_length || needle_length > length)
        return false;
    for (size_t start = 0; start + needle_length <= length; ++start) {
        size_t index = 0;
        while (index < needle_length && ascii_lower(haystack[start + index]) ==
                                            ascii_lower(needle[index]))
            ++index;
        if (index == needle_length)
            return true;
    }
    return false;
}

template <class Char, size_t Count>
[[nodiscard]] constexpr bool any_of(const Char* text, size_t length,
                                    const Char* const (&list)[Count]) noexcept {
    for (const auto* needle : list)
        if (contains(text, length, needle))
            return true;
    return false;
}

enum class role : uint8_t { other, target, tool, watched };

[[nodiscard]] constexpr role classify(const wchar_t* path,
                                      size_t length) noexcept {
    if (!path || !length)
        return role::other;
    if (any_of(path, length, names::target_images))
        return role::target;
    if (any_of(path, length, names::tool_images))
        return role::tool;
    if (any_of(path, length, names::watched_images))
        return role::watched;
    return role::other;
}

// The EPROCESS carries a 15 byte ANSI image name, so the same policy tables
// have to be matchable from both encodings.
template <size_t Count>
[[nodiscard]] constexpr bool any_of_ascii(
    const char* text, size_t length,
    const wchar_t* const (&list)[Count]) noexcept {
    for (const auto* needle : list) {
        const auto needle_length = text_length(needle);
        if (!needle_length || needle_length > length)
            continue;
        for (size_t start = 0; start + needle_length <= length; ++start) {
            size_t index = 0;
            while (index < needle_length &&
                   ascii_lower(text[start + index]) ==
                       ascii_lower(static_cast<char>(needle[index])))
                ++index;
            if (index == needle_length)
                return true;
        }
    }
    return false;
}

[[nodiscard]] constexpr role classify_ascii(const char* path,
                                            size_t length) noexcept {
    if (!path || !length)
        return role::other;
    if (any_of_ascii(path, length, names::target_images))
        return role::target;
    if (any_of_ascii(path, length, names::tool_images))
        return role::tool;
    if (any_of_ascii(path, length, names::watched_images))
        return role::watched;
    return role::other;
}

[[nodiscard]] constexpr bool hidden_module(const char* path,
                                           size_t length) noexcept {
    return any_of(path, length, names::hidden_modules);
}
}  // namespace blook
