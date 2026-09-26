#pragma once
#include <optional>

#include "cli.hpp"

namespace blook::loader::cli {
struct configuration {
    std::optional<bool> allow_users;
    std::optional<std::uint32_t> hook_mask, window_hook_mask;
    std::vector<std::wstring> tools, targets;
};
struct config_error {
    std::size_t line;
    std::string message;
};
[[nodiscard]] inline std::wstring_view trim(std::wstring_view text) {
    constexpr auto spaces = L" \t\r\n";
    const auto begin = text.find_first_not_of(spaces);
    return begin == text.npos
               ? std::wstring_view{}
               : text.substr(begin, text.find_last_not_of(spaces) - begin + 1);
}
[[nodiscard]] inline std::wstring lower(std::wstring_view text) {
    std::wstring result{text};
    for (auto& ch : result)
        if (ch >= L'A' && ch <= L'Z')
            ch += L'a' - L'A';
    return result;
}
// Preserve legacy unknown-key/section tolerance, but reject malformed known
// values before any registry/device operation. The platform layer only decodes
// UTF-8.
[[nodiscard]] inline std::expected<configuration, config_error> parse_config(
    std::wstring_view text) {
    configuration out;
    std::wstring section;
    std::size_t line_number{};
    while (!text.empty()) {
        ++line_number;
        const auto end = text.find(L'\n');
        auto line = trim(text.substr(0, end));
        text = end == text.npos ? std::wstring_view{} : text.substr(end + 1);
        const auto fail = [&](std::string message)
            -> std::expected<configuration, config_error> {
            return std::unexpected(
                config_error{line_number, std::move(message)});
        };
        if (line.find(L'\0') != line.npos)
            return fail("Embedded NUL characters are not allowed.");
        if (line.empty() || line.front() == L'#' || line.front() == L';')
            continue;
        if (line.front() == L'[') {
            if (line.back() != L']')
                return fail("Unclosed section header.");
            section = lower(trim(line.substr(1, line.size() - 2)));
            continue;
        }
        const auto equals = line.find(L'=');
        if (equals == line.npos)
            return fail("Expected key = value.");
        const auto key = lower(trim(line.substr(0, equals)));
        const auto value = trim(line.substr(equals + 1));
        if (section == L"device" && key == L"allow_users") {
            const auto mode = lower(value);
            if (mode == L"1" || mode == L"true" || mode == L"yes")
                out.allow_users = true;
            else if (mode == L"0" || mode == L"false" || mode == L"no")
                out.allow_users = false;
            else
                return fail("allow_users must be true/false, yes/no or 1/0.");
        } else if (section == L"hooks" &&
                   (key == L"hook_mask" || key == L"window_hook_mask")) {
            const auto base =
                value.starts_with(L"0x") || value.starts_with(L"0X") ? 16u
                : value.size() > 1 && value.front() == L'0'          ? 8u
                                                                     : 10u;
            auto mask = unsigned_number<std::uint32_t>(value, base);
            if (!mask)
                return fail(
                    "Mask must be an unsigned 32-bit decimal, octal or "
                    "hexadecimal integer.");
            (key == L"hook_mask" ? out.hook_mask : out.window_hook_mask) =
                *mask;
        } else if (section == L"roles" &&
                   (key == L"tool" || key == L"target")) {
            auto items = value;
            auto& wanted = key == L"tool" ? out.tools : out.targets;
            while (!items.empty()) {
                const auto delimiter = items.find_first_of(L",;");
                const auto item = trim(items.substr(0, delimiter));
                items = delimiter == items.npos ? std::wstring_view{}
                                                : items.substr(delimiter + 1);
                if (item.empty())
                    continue;
                if (((item.front() == L'+' || item.front() == L'-') &&
                     item.size() > 1 &&
                     item.substr(1).find_first_not_of(L"0123456789") ==
                         item.npos) ||
                    (item.find_first_not_of(L"0123456789") == item.npos &&
                     !parse_pid(item)))
                    return fail(
                        "Role PID must be a decimal integer from 1 to "
                        "4294967295.");
                wanted.emplace_back(item);
            }
        }
    }
    return out;
}
}  // namespace blook::loader::cli
