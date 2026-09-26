#pragma once

#include <concepts>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Portable, side-effect-free parsing. Arguments exclude the executable name.
namespace blook::loader::cli {
enum class kind {
    help,
    install,
    start,
    stop,
    uninstall,
    ping,
    version,
    status,
    hide,
    pin,
    unpin,
    apply,
    scrub,
    hook
};
enum class role { tool, target };
struct command {
    kind action{kind::help};
    std::wstring path;
    std::uint32_t pid{};
    role process_role{role::tool};
    bool windows{}, enable{};
    std::uintptr_t address{};
    std::vector<std::uint8_t> bytes;
};
struct parse_error {
    std::string message;
    std::string_view usage;
};

template <std::unsigned_integral T>
    requires(!std::same_as<T, bool>)
[[nodiscard]] inline std::expected<T, std::string> unsigned_number(
    std::wstring_view text, unsigned base = 10) {
    if (base != 8 && base != 10 && base != 16)
        return std::unexpected("Unsupported numeric base.");
    if (base == 16 && (text.starts_with(L"0x") || text.starts_with(L"0X")))
        text.remove_prefix(2);
    if (text.empty())
        return std::unexpected("A number is required.");
    T value{};
    for (const auto ch : text) {
        const auto digit = ch >= L'0' && ch <= L'9'   ? unsigned(ch - L'0')
                           : ch >= L'a' && ch <= L'f' ? unsigned(ch - L'a' + 10)
                           : ch >= L'A' && ch <= L'F' ? unsigned(ch - L'A' + 10)
                                                      : 16u;
        if (digit >= base)
            return std::unexpected("Invalid numeric character.");
        if (value > ((std::numeric_limits<T>::max)() - digit) / base)
            return std::unexpected("Number is out of range.");
        value = static_cast<T>(value * base + digit);
    }
    return value;
}

[[nodiscard]] inline std::expected<std::uint32_t, std::string> parse_pid(
    std::wstring_view text) {
    auto value = unsigned_number<std::uint32_t>(text);
    if (!value || *value == 0)
        return std::unexpected(
            "PID must be a decimal integer from 1 to 4294967295.");
    return *value;
}

[[nodiscard]] inline std::expected<std::vector<std::uint8_t>, std::string>
parse_bytes(std::wstring_view text) {
    if (text.empty() || text.size() % 2 || text.size() > 128)
        return std::unexpected(
            "Bytes must contain 1 to 64 hexadecimal pairs (no spaces or "
            "prefix).");
    std::vector<std::uint8_t> result;
    result.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        auto byte = unsigned_number<std::uint8_t>(text.substr(i, 2), 16);
        if (!byte)
            return std::unexpected(
                "Bytes must contain only hexadecimal pairs.");
        result.push_back(*byte);
    }
    return result;
}

[[nodiscard]] inline std::expected<command, parse_error> parse(
    std::span<const std::wstring_view> args) {
    command out;
    if (args.empty())
        return out;
    const auto name = args.front();
    std::string_view usage;
    if (name == L"help" || name == L"--help") {
        out.action = kind::help;
        usage = "help | --help";
    } else if (name == L"install") {
        out.action = kind::install;
        usage = "install <path-to-signed.sys>";
    } else if (name == L"start") {
        out.action = kind::start;
        usage = "start";
    } else if (name == L"stop") {
        out.action = kind::stop;
        usage = "stop";
    } else if (name == L"uninstall") {
        out.action = kind::uninstall;
        usage = "uninstall";
    } else if (name == L"ping") {
        out.action = kind::ping;
        usage = "ping";
    } else if (name == L"version") {
        out.action = kind::version;
        usage = "version";
    } else if (name == L"status") {
        out.action = kind::status;
        usage = "status";
    } else if (name == L"hide") {
        out.action = kind::hide;
        usage = "hide [windows] on|off";
    } else if (name == L"pin") {
        out.action = kind::pin;
        usage = "pin tool|target <pid>";
    } else if (name == L"unpin") {
        out.action = kind::unpin;
        usage = "unpin <pid>";
    } else if (name == L"apply") {
        out.action = kind::apply;
        usage = "apply [blook.ini]";
    } else if (name == L"scrub") {
        out.action = kind::scrub;
        usage = "scrub <pid>";
    } else if (name == L"hook") {
        out.action = kind::hook;
        usage = "hook <self|pid> <hex-address> <hex-bytes>";
    } else
        return std::unexpected(parse_error{
            "Unknown command. Run blook-loader --help for available commands.",
            "--help"});

    // Help is accepted only for a recognized command and cannot execute it.
    if (args.size() == 2 && args[1] == L"--help") {
        out.action = kind::help;
        return out;
    }
    const auto fail =
        [&](std::string message) -> std::expected<command, parse_error> {
        return std::unexpected(parse_error{std::move(message), usage});
    };
    const auto arity = [&](std::size_t size) { return args.size() == size; };
    switch (out.action) {
        case kind::install:
        case kind::apply:
            if (out.action == kind::apply && arity(1)) {
                out.path = L"blook.ini";
                break;
            }
            if (!arity(2))
                return fail("Expected exactly one file path.");
            if (args[1].empty() || args[1].starts_with(L"--") ||
                args[1].find(L'\0') != std::wstring_view::npos)
                return fail(
                    "A non-empty file path is required; quote paths containing "
                    "spaces.");
            out.path = args[1];
            break;
        case kind::hide:
            if (!arity(2) && !arity(3))
                return fail(
                    "Expected on or off, optionally preceded by windows.");
            out.windows = arity(3);
            if (out.windows && args[1] != L"windows")
                return fail("Expected the literal windows.");
            if (args.back() != L"on" && args.back() != L"off")
                return fail("Mode must be on or off.");
            out.enable = args.back() == L"on";
            break;
        case kind::pin:
        case kind::unpin:
        case kind::scrub: {
            if (!arity(out.action == kind::pin ? 3 : 2))
                return fail("Incorrect number of arguments.");
            if (out.action == kind::pin) {
                if (args[1] != L"tool" && args[1] != L"target")
                    return fail("Role must be tool or target.");
                out.process_role =
                    args[1] == L"tool" ? role::tool : role::target;
            }
            auto pid = parse_pid(args.back());
            if (!pid)
                return fail(pid.error());
            out.pid = *pid;
            break;
        }
        case kind::hook: {
            if (!arity(4))
                return fail(
                    "Expected owner, hexadecimal address and hexadecimal "
                    "bytes.");
            if (args[1] != L"self") {
                auto pid = parse_pid(args[1]);
                if (!pid)
                    return fail(pid.error());
                out.pid = *pid;
            }
            auto address = unsigned_number<std::uintptr_t>(args[2], 16);
            if (!address || !*address)
                return fail(
                    "Address must be a nonzero hexadecimal pointer-sized "
                    "integer.");
            auto bytes = parse_bytes(args[3]);
            if (!bytes)
                return fail(bytes.error());
            out.address = *address;
            out.bytes = std::move(*bytes);
            break;
        }
        default:
            if (!arity(1))
                return fail("This command does not accept arguments.");
            break;
    }
    return out;
}
}  // namespace blook::loader::cli
